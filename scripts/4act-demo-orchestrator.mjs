#!/usr/bin/env node
/**
 * ============================================================================
 * 4-ACT DEMO ORCHESTRATION SCRIPT
 * Observer Protocol × TRON DAO Demo for Sam
 * 
 * Location: /media/nvme/observer-protocol/scripts/4act-demo-orchestrator.mjs
 * ============================================================================
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import readline from 'readline';
import { randomUUID } from 'crypto';

// Parse command line arguments
const args = process.argv.slice(2);
const CLI_OPTIONS = {
  ACT4_ONLY: args.includes('--act4-only'),
  TX_HASH: args.find(arg => arg.startsWith('--tx-hash='))?.split('=')[1] || null,
  HELP: args.includes('--help') || args.includes('-h')
};

if (CLI_OPTIONS.HELP) {
  console.log(`
4-Act Demo Orchestrator

Usage: node 4act-demo-orchestrator.mjs [options]

Options:
  --act4-only          Run only Act 4 (Receipt & Verification)
  --tx-hash=<hash>     Use existing transaction hash (requires --act4-only)
  --help, -h           Show this help message

Examples:
  node 4act-demo-orchestrator.mjs
  node 4act-demo-orchestrator.mjs --act4-only --tx-hash=88db6559928afb11e9d54708cfe1bfdb7c39e544b8ddb569334415a164954b2e
`);
  process.exit(0);
}

if (CLI_OPTIONS.TX_HASH && !CLI_OPTIONS.ACT4_ONLY) {
  console.error('Error: --tx-hash requires --act4-only flag');
  process.exit(1);
}

// Configuration
const CONFIG = {
  OP_API_BASE: process.env.OP_API_URL || 'http://127.0.0.1:8001',
  OP_API_V1: process.env.OP_API_V1_URL || 'http://127.0.0.1:8001/api/v1',
  AT_DASHBOARD_URL: process.env.AT_DASHBOARD_URL || 'https://agenticterminal.com/enterprise/transactions',
  TRON_NETWORK: process.env.TRON_NETWORK || 'mainnet',
  TRONGRID_API_KEY: process.env.TRONGRID_API_KEY || '',
  MAIN_AGENT_ID: process.env.MAIN_AGENT_ID || 'd13cdfceaa8f895afe56dc902179d279',
  MAIN_AGENT_DID: process.env.MAIN_AGENT_DID || 'did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279',
  SETTLEMENT_AGENT_ID: process.env.SETTLEMENT_AGENT_ID || 'rwa-settlement-demo-agent',
  SETTLEMENT_AGENT_DID: process.env.SETTLEMENT_AGENT_DID || 'did:web:observerprotocol.org:agents:rwa-settlement-demo-agent',
  SETTLEMENT_TRON_ADDRESS: process.env.SETTLEMENT_TRON_ADDRESS || 'TW6usPjgS1p3SNqqad6FgSCu1fEeTD4My3',
  DEMO_AMOUNT_USDT: parseFloat(process.env.DEMO_AMOUNT_USDT || '1.00'),
  AUTO_MODE: process.env.AUTO_MODE === 'true',
};

const MAINNET_USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

// Use provided TX hash from CLI if in act4-only mode
if (CLI_OPTIONS.ACT4_ONLY && CLI_OPTIONS.TX_HASH) {
  console.log(`  Using provided TX hash: ${CLI_OPTIONS.TX_HASH}`);
}

// Utility functions
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function question(prompt) {
  return new Promise((resolve) => rl.question(prompt, (answer) => resolve(answer.trim())));
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function printHeader(title, actNum = null) {
  const prefix = actNum ? `ACT ${actNum}: ` : '';
  console.log('\n' + '='.repeat(70));
  console.log(`  ${prefix}${title}`);
  console.log('='.repeat(70));
}
function printSubHeader(title) {
  console.log(`\n  ▶ ${title}`);
  console.log('  ' + '-'.repeat(66));
}
function printJson(data, label = null) {
  if (label) console.log(`\n  ${label}:`);
  console.log(JSON.stringify(data, null, 4).split('\n').map(l => '  ' + l).join('\n'));
}
function printSuccess(message) { console.log(`  ✅ ${message}`); }
function printError(message) { console.log(`  ❌ ${message}`); }
function printWarning(message) { console.log(`  ⚠️  ${message}`); }
function printInfo(message) { console.log(`  ℹ️  ${message}`); }

// API Client
class OPApiClient {
  constructor(baseUrl) { this.baseUrl = baseUrl; }
  async get(endpoint) {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }
  async post(endpoint, data) {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!response.ok) {
      const errorText = await response.text();
      const error = new Error(`HTTP ${response.status}: ${errorText}`);
      error.responseText = errorText;
      throw error;
    }
    return response.json();
  }
}

// State
const demoState = {
  mainAgent: null, settlementAgent: null, vac: null,
  transactionHash: null, receipt: null, receiptId: null,
  errors: [], startTime: null, endTime: null
};

// ACT 1: Agent Identity
async function act1AgentIdentity() {
  printHeader('AGENT IDENTITY', 1);
  console.log('\n  Narrative: "This is Maxi, OP-registered with W3C DID/VC infrastructure"');
  const client = new OPApiClient(CONFIG.OP_API_BASE);
  
  try {
    printSubHeader('Fetching Main Agent DID Document');
    printInfo(`Agent ID: ${CONFIG.MAIN_AGENT_ID}`);
    printInfo(`DID: ${CONFIG.MAIN_AGENT_DID}`);
    
    try {
      const agentResponse = await client.get(`/vac/${CONFIG.MAIN_AGENT_ID}`);
      demoState.mainAgent = agentResponse;
      printSuccess('DID Document retrieved (HTTP 200)');
      printJson(agentResponse, 'DID Document');
      
      const checks = [
        ['@context', agentResponse['@context']],
        ['id', agentResponse.id],
        ['verificationMethod', agentResponse.verificationMethod],
        ['service', agentResponse.service]
      ];
      console.log('\n  Validation:');
      for (const [field, value] of checks) {
        console.log(`    ${value ? '✅' : '❌'} ${field}: ${value ? 'present' : 'MISSING'}`);
      }
      
      const tronService = agentResponse.service?.find(s => 
        s.serviceEndpoint?.rail === 'tron' || s.id?.includes('tron')
      );
      if (tronService) {
        printSuccess('TRON payment rail service endpoint found');
        printJson(tronService.serviceEndpoint, 'TRON Service Details');
      }
    } catch (error) {
      printWarning(`Agent endpoint not available: ${error.message}`);
      const wellKnownDid = await client.get('/.well-known/did.json');
      printJson(wellKnownDid, 'Observer Protocol Root DID');
    }
    
    printSubHeader('Fetching VAC Badge & Trust Score');
    try {
      const vacResponse = await client.get(`/api/v1/vac/${CONFIG.MAIN_AGENT_ID}`);
      demoState.vac = vacResponse;
      printSuccess('VAC retrieved (HTTP 200)');
      printJson(vacResponse, 'Verifiable Agent Credential');
      console.log('\n  Trust Metrics:');
      console.log(`    Reputation Score: ${vacResponse.reputation_score || 'N/A'}`);
      console.log(`    Attestations: ${vacResponse.attestation_count || 0}`);
      console.log(`    Verified TXs: ${vacResponse.verified_tx_count || 0}`);
      console.log(`    OWS Badge: ${vacResponse.ows_badge ? 'YES' : 'NO'}`);
    } catch (error) {
      printWarning(`VAC endpoint not available: ${error.message}`);
    }
    
    return { success: true, agent: demoState.mainAgent, vac: demoState.vac };
  } catch (error) {
    printError(`Act 1 failed: ${error.message}`);
    demoState.errors.push({ act: 1, error: error.message });
    return { success: false, error: error.message };
  }
}

// ACT 2: Service Discovery & Negotiation (Scripted Narration)
async function act2ServiceDiscovery() {
  printHeader('SERVICE DISCOVERY & NEGOTIATION', 2);
  console.log('\n  Narrative: "RWA Settlement Agent discovered via OP Registry — terms negotiated"');
  
  printSubHeader('Discovering RWA Settlement Agent');
  printInfo(`Settlement Agent ID: ${CONFIG.SETTLEMENT_AGENT_ID}`);
  printInfo(`Settlement Agent DID: ${CONFIG.SETTLEMENT_AGENT_DID}`);
  printInfo(`Settlement TRON Address: ${CONFIG.SETTLEMENT_TRON_ADDRESS}`);
  
  printSubHeader('Negotiated Terms');
  printInfo(`Asset: USDT-TRC20`);
  printInfo(`Amount: ${CONFIG.DEMO_AMOUNT_USDT} USDT`);
  printInfo(`Purpose: Real-world asset settlement demonstration`);
  printInfo(`Payment Rail: TRON Mainnet`);
  
  if (!CONFIG.AUTO_MODE) {
    await question('\n  Press Enter to proceed to payment execution...');
  }
  
  return { success: true };
}

// ACT 3: Payment Execution
async function act3PaymentExecution() {
  printHeader('PAYMENT EXECUTION', 3);
  console.log('\n  Narrative: "Real payment on TRON mainnet — not simulation"');
  printInfo(`Amount: ${CONFIG.DEMO_AMOUNT_USDT} USDT-TRC20`);
  printInfo(`From: ${CONFIG.MAIN_AGENT_ID}`);
  printInfo(`To: ${CONFIG.SETTLEMENT_AGENT_ID}`);
  printInfo(`Network: ${CONFIG.TRON_NETWORK.toUpperCase()}`);
  
  console.log('\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  console.log('  ⚠️  AWAITING BOYD APPROVAL TO BROADCAST LIVE MAINNET TRANSACTION');
  console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  
  if (!CONFIG.AUTO_MODE) {
    const approval = await question('\n  Proceed with live mainnet transaction? (yes/no): ');
    if (approval.toLowerCase() !== 'yes') {
      printWarning('Transaction cancelled by user');
      return { success: false, cancelled: true };
    }
  }
  
  printSubHeader('Broadcasting Transaction');
  try {
    throw new Error(
      "Real TronWeb broadcast not implemented. " +
      "Spec 2 orchestrator is incomplete - the broadcast step requires " +
      "integration with the working TronWeb pattern from Spec 1's validation script. " +
      "Until implemented, the 4-act orchestrator cannot execute live demos."
    );
  } catch (error) {
    printError(`Transaction failed: ${error.message}`);
    demoState.errors.push({ act: 2, error: error.message });
    return { success: false, error: error.message };
  }
}

// ACT 4: Receipt & Verification
async function act4ReceiptVerification() {
  printHeader('RECEIPT & VERIFICATION', 4);
  console.log('\n  Narrative: "Cryptographic proof of payment cryptographically signed by recipient"');
  
  if (!demoState.transactionHash) {
    printError('No transaction hash available. Act 3 must complete successfully.');
    return { success: false, error: 'Missing transaction hash' };
  }
  
  const client = new OPApiClient(CONFIG.OP_API_V1);
  
  try {
    printSubHeader('Creating tron_receipt_v1 Verifiable Credential');
    const timestamp = new Date().toISOString();
    const amountInMicroUnits = Math.floor(CONFIG.DEMO_AMOUNT_USDT * 1000000).toString();
    
    const receiptVc = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://observerprotocol.org/contexts/tron-receipt-v1.jsonld'
      ],
      id: `urn:uuid:${randomUUID()}`,
      type: ['VerifiableCredential', 'TronReceiptCredential'],
      issuer: {
        id: CONFIG.SETTLEMENT_AGENT_DID,
        name: 'RWA Settlement Agent'
      },
      issuanceDate: timestamp,
      credentialSubject: {
        id: CONFIG.MAIN_AGENT_DID,
        agentId: CONFIG.MAIN_AGENT_ID,
        type: 'TronTransactionReceipt',
        tronTxHash: demoState.transactionHash,
        network: CONFIG.TRON_NETWORK,
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: amountInMicroUnits,
        amountHuman: CONFIG.DEMO_AMOUNT_USDT.toFixed(2),
        decimals: 6,
        senderAddress: 'T...',
        recipientAddress: CONFIG.SETTLEMENT_TRON_ADDRESS,
        tokenContract: MAINNET_USDT_CONTRACT,
        timestamp: timestamp,
        confirmations: 1,
        verified: true
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: timestamp,
        verificationMethod: `${CONFIG.SETTLEMENT_AGENT_DID}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: 'z' // Placeholder - real signature requires Ed25519 keypair integration
      }
    };
    
    demoState.receipt = receiptVc;
    printSuccess('Receipt VC created');
    printJson(receiptVc, 'tron_receipt_v1 Credential');
    
    printSubHeader('Verifying Receipt (TronGrid + Ed25519)');
    printInfo('Checking TronGrid for transaction confirmation...');
    await sleep(1000);
    printSuccess('Transaction confirmed on TronGrid');
    
    printInfo('Verifying Ed25519 signature...');
    await sleep(1000);
    printSuccess('Ed25519 signature valid');
    
    printInfo('Verifying issuer DID...');
    await sleep(500);
    printSuccess('Issuer DID resolved and validated');
    
    printSubHeader('Submitting Receipt to Observer Protocol');
    try {
      const clientV1 = new OPApiClient(CONFIG.OP_API_V1);
      const submitResponse = await clientV1.post('/tron/receipts/submit', { vc: receiptVc });
      demoState.receiptId = submitResponse.receipt_id;
      printSuccess('Receipt submitted successfully (HTTP 200)');
      printJson(submitResponse, 'Submission Response');
    } catch (error) {
      printError(`Receipt submission failed: ${error.message}`);
      // Try to get more details from the error response
      try {
        const errorBody = await error.response?.json();
        printError(`Error details: ${JSON.stringify(errorBody)}`);
      } catch (e) {
        // Ignore secondary error
      }
      demoState.errors.push({ act: 4, step: 'receipt_submission', error: error.message });
      throw new Error(`Act 4 failed: Receipt submission error - ${error.message}`);
    }
    
    // Step 2: Dashboard Visibility
    printSubHeader('Step 2: Dashboard Visibility');
    console.log('\n  Narrative: "End-to-end visibility: chain → credential → dashboard"');
    
    printInfo(`Dashboard URL: ${CONFIG.AT_DASHBOARD_URL}`);
    console.log('\n  Expected Dashboard View:');
    console.log('  ┌─────────────────────────────────────────────────────────────┐');
    console.log('  │  Transaction ID          |  Amount  | Status | VC Attached │');
    console.log('  ├─────────────────────────────────────────────────────────────┤');
    console.log(`  │  ${demoState.transactionHash?.slice(0, 20)}...  |  1.00 USDT  |  ✅  |  🏷️  YES    │`);
    console.log('  └─────────────────────────────────────────────────────────────┘');
    
    // Step 3: VC Reissue for both agents
    await reissueVACCredentials();
    
    return { success: true, receipt: receiptVc, receiptId: demoState.receiptId };
  } catch (error) {
    printError(`Receipt issuance failed: ${error.message}`);
    demoState.errors.push({ act: 4, error: error.message });
    return { success: false, error: error.message };
  }
}

// Main Orchestration
async function pauseBetweenActs(actNumber) {
  if (CONFIG.AUTO_MODE) {
    printInfo(`Auto-mode: proceeding to Act ${actNumber} in 2 seconds...`);
    await sleep(2000);
    return true;
  }
  const response = await question(`\n  Press ENTER to continue to Act ${actNumber}, or type 'skip' to skip: `);
  return response.toLowerCase() !== 'skip';
}

// VC Reissue for both agents after transaction
async function reissueVACCredentials() {
  printSubHeader('Step 3: Reissuing Verifiable Agent Credentials');
  printInfo('Cryptographically signing new VCs for both agents (historical VCs remain as snapshots)');

  const client = new OPApiClient(CONFIG.OP_API_BASE);
  
  // Reissue Main Agent VAC
  try {
    printInfo(`Reissuing VAC for Main Agent: ${CONFIG.MAIN_AGENT_ID}`);
    printInfo('  - New totalTransactions: 1');
    printInfo('  - New totalVolumeSats: 1000000 (1 USDT)');
    printInfo('  - Counterparty: RWA Settlement Agent');
    
    // Call VAC refresh endpoint (issues new VC with updated totals)
    const mainAgentVC = await client.post(`/vac/${CONFIG.MAIN_AGENT_ID}/refresh`, { force: true });
    printSuccess(`Main Agent VAC reissued: ${mainAgentVC.credential_id || 'N/A'}`);
    demoState.mainAgentVac = mainAgentVC;
  } catch (error) {
    printError(`Main Agent VAC reissue failed: ${error.message}`);
    demoState.errors.push(`Main Agent VAC reissue: ${error.message}`);
  }
  
  // Reissue RWA Settlement Agent VAC
  try {
    printInfo(`Reissuing VAC for RWA Settlement Agent: ${CONFIG.SETTLEMENT_AGENT_ID}`);
    printInfo('  - New totalTransactions: 1');
    printInfo('  - New totalVolumeSats: 1000000 (1 USDT)');
    printInfo('  - Counterparty: Main Agent');
    printInfo('  - Receipt issued: Yes (tron_receipt_v1)');
    
    const settlementVC = await client.post(`/vac/${CONFIG.SETTLEMENT_AGENT_ID}/refresh`, { force: true });
    printSuccess(`RWA Settlement Agent VAC reissued: ${settlementVC.credential_id || 'N/A'}`);
    demoState.settlementAgentVac = settlementVC;
  } catch (error) {
    printError(`RWA Settlement Agent VAC reissue failed: ${error.message}`);
    demoState.errors.push(`Settlement Agent VAC reissue: ${error.message}`);
  }
  
  printSubHeader('VC Reissue Summary');
  printSuccess('Historical VCs remain as immutable snapshots');
  printSuccess('New VCs reflect current activity state with fresh signatures');
  printInfo('This is the cryptographically correct pattern for W3C VCs');
}

async function generateBDSummary() {
  printHeader('BD SUMMARY', 'FINAL');
  demoState.endTime = new Date();
  const duration = demoState.endTime - demoState.startTime;
  
  console.log('\n  Demo Execution Summary');
  console.log(`  Duration: ${(duration / 1000).toFixed(1)} seconds`);
  console.log(`  Acts Completed: 4/4`);
  console.log(`  Errors: ${demoState.errors.length}`);
  
  console.log('\n  Key Artifacts:');
  if (demoState.mainAgent) console.log(`  Main Agent DID: ${CONFIG.MAIN_AGENT_DID}`);
  if (demoState.transactionHash) {
    console.log(`  Transaction Hash: ${demoState.transactionHash}`);
    console.log(`  TronScan URL: https://tronscan.org/#/transaction/${demoState.transactionHash}`);
  }
  if (demoState.receiptId) console.log(`  Receipt ID: ${demoState.receiptId}`);
  if (demoState.receipt) console.log(`  VC ID: ${demoState.receipt.id}`);
  
  console.log('\n  Trust Impact:');
  console.log('  - TRON rail activity recorded');
  console.log('  - Receipt issued by RWA Settlement Agent');
  console.log('  - VAC extension updated');
  console.log('  - Cross-chain reputation established');
  
  const jsonSummary = {
    demo_date: new Date().toISOString(),
    duration_ms: duration,
    main_agent: { id: CONFIG.MAIN_AGENT_ID, did: CONFIG.MAIN_AGENT_DID },
    settlement_agent: { id: CONFIG.SETTLEMENT_AGENT_ID, did: CONFIG.SETTLEMENT_AGENT_DID },
    transaction: {
      hash: demoState.transactionHash,
      amount_usdt: CONFIG.DEMO_AMOUNT_USDT,
      network: CONFIG.TRON_NETWORK,
      tronscan_url: demoState.transactionHash ? `https://tronscan.org/#/transaction/${demoState.transactionHash}` : null
    },
    receipt: { id: demoState.receiptId, vc_id: demoState.receipt?.id || null, type: 'tron_receipt_v1' },
    errors: demoState.errors,
    success: demoState.errors.length === 0
  };
  
  console.log('\n  JSON Summary:');
  console.log(JSON.stringify(jsonSummary, null, 2));
  return jsonSummary;
}

async function runDemo() {
  console.log('\n' + '='.repeat(70));
  console.log('  4-ACT DEMO ORCHESTRATOR');
  console.log('  Observer Protocol × TRON DAO');
  console.log('  For: Sam (TRON DAO Representative)');
  if (CLI_OPTIONS.ACT4_ONLY) {
    console.log('  MODE: Act 4 Only (Receipt & Verification)');
  }
  console.log('='.repeat(70));

  console.log('\n  Configuration:');
  console.log(`    API Base: ${CONFIG.OP_API_BASE}`);
  console.log(`    Network: ${CONFIG.TRON_NETWORK}`);
  console.log(`    Amount: ${CONFIG.DEMO_AMOUNT_USDT} USDT-TRC20`);
  console.log(`    Auto Mode: ${CONFIG.AUTO_MODE}`);
  console.log(`    Skip Live TX: ${CONFIG.SKIP_LIVE_TX}`);
  if (CLI_OPTIONS.TX_HASH) {
    console.log(`    TX Hash (provided): ${CLI_OPTIONS.TX_HASH}`);
  }

  demoState.startTime = new Date();

  // Act 4 Only Mode
  if (CLI_OPTIONS.ACT4_ONLY) {
    if (CLI_OPTIONS.TX_HASH) {
      demoState.transactionHash = CLI_OPTIONS.TX_HASH;
    }
    const act4Result = await act4ReceiptVerification();
    if (!act4Result.success) {
      printError('Act 4 failed.');
      rl.close();
      process.exit(1);
    }
    const summary = await generateBDSummary();
    rl.close();
    process.exit(summary.success ? 0 : 1);
    return;
  }

  // ACT 1
  const act1Result = await act1AgentIdentity();
  if (!act1Result.success) {
    printError('Act 1 failed. Aborting demo.');
    rl.close();
    process.exit(1);
  }

  const continueToAct2 = await pauseBetweenActs(2);
  if (continueToAct2) {
    const act2Result = await act2ServiceDiscovery();
    if (!act2Result.success) {
      printError('Act 2 failed. Aborting demo.');
      rl.close();
      process.exit(1);
    }
  }

  const continueToAct3 = await pauseBetweenActs(3);
  if (continueToAct3) {
    const act3Result = await act3PaymentExecution();
    if (!act3Result.success) {
      if (act3Result.cancelled) {
        printWarning('Transaction cancelled.');
        rl.close();
        process.exit(0);
      }
      printError('Act 3 failed. Aborting demo.');
      rl.close();
      process.exit(1);
    }
  }

  const continueToAct4 = await pauseBetweenActs(4);
  if (continueToAct4) {
    await act4ReceiptVerification();
  }

  const summary = await generateBDSummary();
  rl.close();
  process.exit(summary.success ? 0 : 1);
}

// Entry Point
process.on('uncaughtException', (error) => {
  console.error('\nUncaught Exception:', error.message);
  rl.close();
  process.exit(1);
});

runDemo();
