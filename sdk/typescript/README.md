# @observer-protocol/sdk

Agent identity, delegation, x402 verification, and chargeback prevention for the agentic economy.

Built on W3C DIDs and Verifiable Credentials. Browser and Node.js compatible. Zero dependencies.

## Install

```bash
npm install @observer-protocol/sdk
```

## Quick Start

```ts
import { ObserverClient } from '@observer-protocol/sdk';

const client = new ObserverClient();

// 1. Register an agent
const agent = await client.registerAgent({
  publicKey: 'ed25519_hex_64_chars',
  agentName: 'My Agent',
});
// agent.agentId, agent.agentDid, agent.didDocument

// 2. Verify key ownership (challenge-response)
const challenge = await client.requestChallenge(agent.agentId);
// Sign challenge.nonce with your Ed25519 private key
const signature = mySignFunction(challenge.nonce, privateKey);
await client.verifyAgent(agent.agentId, signature);
```

## Delegation (Chargeback Prevention)

```ts
// Issue a delegation credential
const delegation = await client.requestDelegation({
  agentId: 'd13cdfceaa8f895afe56dc902179d279',
  scope: ['payments'],
  rails: ['x402-usdc-base', 'lightning', 'tron:trc20'],
  spendingLimits: { perTransaction: '100', daily: '1000' },
  expiration: new Date(Date.now() + 30 * 86400000).toISOString(),
  attestationTier: 'enterprise', // or 'chain-anchored'
});

// List delegations
const delegations = await client.listDelegations();

// Revoke a delegation
await client.revokeDelegation(delegation.requestId, 'No longer needed');
```

## Magic Link (Human-in-the-Loop Authorization)

```ts
// Generate a magic link for human approval
const magicLink = await client.generateMagicLink({
  agentId: 'd13cdfceaa8f895afe56dc902179d279',
  counterpartyDid: 'did:web:neuralbridge.ai',
  counterpartyName: 'NeuralBridge',
  amount: '50.00',
  currency: 'USDT',
  rail: 'usdt-trc20',
  purchaseDescription: 'GPU inference credits',
});

// Agent forwards magicLink.url to its human via WhatsApp/Telegram/etc.
console.log(magicLink.url);   // https://api.observerprotocol.org/m/k7n2fxj4
console.log(magicLink.intro); // "I tried to purchase $50.00 in GPU inference credits..."

// Poll for the credential after human approves
const result = await client.getMagicLinkCredential(magicLink.jti);
if (result.status === 'authorized') {
  // Use result.credential to retry the purchase
}
```

## x402 Verification (USDC on Base)

```ts
// Verify an x402 payment and issue an X402PaymentCredential
const result = await client.verifyX402({
  agentId: 'd13cdfceaa8f895afe56dc902179d279',
  agentDid: 'did:web:observerprotocol.org:agents:d13cdf...',
  counterparty: 'did:web:hyperbolic.xyz',
  amount: '100000', // atomic units (0.10 USDC)
  resourceUri: 'https://hyperbolic-x402.vercel.app/v1/chat/completions',
  settlementTxHash: '0xd94a6d8bfa9c1634e19b59cac9503e732cb538772b96e02300702bc38fb39b94',
  paymentPayload: { transaction: '0x...', network: 'base', payer: '0x...' },
});

console.log(result.verification.onchainVerified);  // true
console.log(result.verification.discrepancy);       // false
console.log(result.credential.id);                  // urn:uuid:...
```

## Chain Verification

```ts
// Verify a Lightning payment
const lightning = await client.verifyLightning({
  receiptReference: 'urn:uuid:...',
  paymentHash: '442c94c8853df04ac239232614dbec05...',
  preimage: '69d5be20f040f926b184f6d166b0b717...',
});

// Verify a TRON transaction
const tron = await client.verifyTron({
  receiptReference: 'urn:uuid:...',
  tronTxHash: 'eb52108c9785a83d5ff381d6d5086dec...',
});
```

## Trust Score

```ts
const score = await client.getTrustScore('d13cdfceaa8f895afe56dc902179d279');
console.log(score.trustScore);           // 31.99
console.log(score.components.receiptScore);     // 76
console.log(score.components.counterpartyScore); // 75
console.log(score.receiptCount);         // 51
```

## ERC-8004 On-Chain Registry

```ts
// Get an agent's 8004 presence across Base + TRON
const summary = await client.get8004Summary('d13cdfceaa8f895afe56dc902179d279');
console.log(summary.has8004Presence); // true
console.log(summary.nfts);           // [{chain: 'base', tokenId: '42', ...}]

// Resolve DID to 8004 NFTs
const nfts = await client.resolve8004ByDid('did:web:observerprotocol.org:agents:d13cdf...');

// Pin a registration file for 8004 NFT minting
const pin = await client.pinRegistration({
  agentId: 'd13cdfceaa8f895afe56dc902179d279',
  agentDid: 'did:web:observerprotocol.org:agents:d13cdf...',
  agentName: 'Maxi',
});
// pin.servingUrl is the tokenURI for the 8004 NFT
```

## Configuration

```ts
const client = new ObserverClient({
  baseUrl: 'https://api.observerprotocol.org', // default
  apiKey: 'your-api-key',                       // for authenticated endpoints
  timeout: 30000,                               // request timeout in ms
});
```

## Supported Rails

| Rail | Method | Status |
|------|--------|--------|
| x402 / USDC on Base | `verifyX402()` | Live |
| Lightning / L402 | `verifyLightning()` | Live |
| TRON / TRC-20 USDT | `verifyTron()` | Live |
| Solana | `verifyChain({ chain: 'solana' })` | Live |

## Links

- [Documentation](https://observerprotocol.org)
- [GitHub](https://github.com/observer-protocol/observer-protocol-spec)
- [Chargeback Prevention Demo](https://observerprotocol.org/chargeback-prevention)
- [Delegation Schema v2](https://observerprotocol.org/schemas/delegation/v2.json)
- [X402 Payment Schema](https://observerprotocol.org/schemas/x402/v1.json)
- [Receipt Schema v1](https://observerprotocol.org/schemas/receipt/settlement-receipt-v1.json)

## License

MIT
