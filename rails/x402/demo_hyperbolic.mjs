/**
 * Hyperbolic x402 Integration Demo
 *
 * Makes a real inference call to Hyperbolic via x402, captures the
 * payment proof, then calls OP's x402 verification endpoint to
 * issue an X402PaymentCredential.
 *
 * Usage:
 *   export MAINNET_PRIVATE_KEY=0x...
 *   node demo_hyperbolic.mjs
 *
 * Requires: x402-fetch, viem (install via: npm install x402-fetch viem)
 */

import { privateKeyToAccount } from 'viem/accounts';
import { randomUUID } from 'crypto';
import { createHash } from 'crypto';

const HYPERBOLIC_URL = 'https://hyperbolic-x402.vercel.app/v1/chat/completions';
const OP_API = process.env.OP_API_URL || 'https://api.observerprotocol.org';
const AGENT_ID = process.env.AGENT_ID || 'd13cdfceaa8f895afe56dc902179d279';
const AGENT_DID = process.env.AGENT_DID || 'did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279';

async function main() {
  const privateKey = process.env.MAINNET_PRIVATE_KEY;
  if (!privateKey) {
    console.error('Error: MAINNET_PRIVATE_KEY environment variable required');
    process.exit(1);
  }

  const account = privateKeyToAccount(privateKey);
  console.log('=== Hyperbolic x402 Integration Demo ===');
  console.log(`Wallet: ${account.address}`);
  console.log(`Agent: ${AGENT_ID}`);
  console.log('');

  // Step 1: Import x402-fetch
  let wrapFetchWithPayment, decodeXPaymentResponse;
  try {
    const x402 = await import('x402-fetch');
    wrapFetchWithPayment = x402.wrapFetchWithPayment;
    decodeXPaymentResponse = x402.decodeXPaymentResponse;
  } catch (e) {
    console.error('Error: x402-fetch not installed. Run: npm install x402-fetch viem');
    process.exit(1);
  }

  const fetchWithPayment = wrapFetchWithPayment(fetch, account);
  const requestId = randomUUID();

  // Step 2: Make inference call via x402
  console.log('Step 1: Making inference call to Hyperbolic via x402...');
  const requestBody = {
    model: 'meta-llama/Llama-3.2-3B-Instruct',
    messages: [
      { role: 'user', content: 'What is Observer Protocol? Answer in one sentence.' }
    ],
    max_tokens: 100,
    temperature: 0.1,
    stream: false,
  };

  let response;
  try {
    response = await fetchWithPayment(HYPERBOLIC_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Request-ID': requestId,
      },
      body: JSON.stringify(requestBody),
    });
  } catch (e) {
    console.error('x402 payment failed:', e.message);
    process.exit(1);
  }

  const body = await response.json();
  console.log('Inference response received.');
  if (body.choices && body.choices[0]) {
    console.log(`Model output: ${body.choices[0].message?.content?.slice(0, 200)}`);
  }
  console.log('');

  // Step 3: Extract payment proof from response headers
  const paymentHeader = response.headers.get('x-payment-response');
  if (!paymentHeader) {
    console.log('No payment header - request may have been free or cached.');
    process.exit(0);
  }

  const paymentResponse = decodeXPaymentResponse(paymentHeader);
  console.log('Step 2: Payment settled on-chain.');
  console.log(`  Transaction: ${paymentResponse.transaction}`);
  console.log(`  Network: ${paymentResponse.network}`);
  console.log(`  Payer: ${paymentResponse.payer}`);
  console.log('');

  // Step 4: Build payment payload for OP verification
  const paymentPayload = {
    transaction: paymentResponse.transaction,
    network: paymentResponse.network,
    payer: paymentResponse.payer,
    requestId,
    model: requestBody.model,
    timestamp: new Date().toISOString(),
  };

  // Determine network CAIP-2 identifier
  let networkCaip2 = 'eip155:8453'; // Base mainnet default
  if (paymentResponse.network === 'base-sepolia' || paymentResponse.network === '84532') {
    networkCaip2 = 'eip155:84532';
  }

  // Step 5: Call OP's x402 verification endpoint
  console.log('Step 3: Requesting X402PaymentCredential from Observer Protocol...');
  const verifyPayload = {
    agent_id: AGENT_ID,
    agent_did: AGENT_DID,
    counterparty: 'did:web:hyperbolic.xyz',
    payment_scheme: 'exact',
    network: networkCaip2,
    asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    asset_symbol: 'USDC',
    amount: paymentResponse.amount || '0',
    resource_uri: HYPERBOLIC_URL,
    facilitator_url: 'https://x402.coinbase.com',
    settlement_tx_hash: paymentResponse.transaction,
    payment_payload: paymentPayload,
  };

  try {
    const opResponse = await fetch(`${OP_API}/api/v1/x402/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyPayload),
    });

    if (opResponse.ok) {
      const result = await opResponse.json();
      console.log('X402PaymentCredential issued!');
      console.log(`  Credential ID: ${result.credential?.id}`);
      console.log(`  Facilitator verified: ${result.verification?.facilitator_verified}`);
      console.log(`  On-chain verified: ${result.verification?.onchain_verified}`);
      console.log(`  Discrepancy: ${result.verification?.discrepancy}`);
      console.log(`  Event ID: ${result.event_id}`);
      console.log('');
      console.log('Full credential:');
      console.log(JSON.stringify(result.credential, null, 2));
    } else {
      const err = await opResponse.text();
      console.error(`OP verification failed (${opResponse.status}): ${err}`);
    }
  } catch (e) {
    console.error('OP API call failed:', e.message);
    console.log('');
    console.log('Payment was successful but OP credential issuance failed.');
    console.log('Payment proof (for manual verification):');
    console.log(JSON.stringify(paymentPayload, null, 2));
  }

  console.log('');
  console.log('=== Demo complete ===');
}

main().catch(console.error);
