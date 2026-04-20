/**
 * TRON Transaction Receipt VC Schema
 * 
 * Defines the tron_receipt_v1 Verifiable Credential type for TRON rail transactions.
 * This enables counterparty-signed receipts for TRON and TRC-20 transfers.
 */

import { createHash, randomUUID } from 'crypto';
import base58 from 'base58';
import { 
  validateTronAddress, 
  tronAddressToHex, 
  hexToTronAddress,
  TRC20_CONTRACTS 
} from './tron-core.mjs';

// W3C contexts
const W3C_CREDENTIALS_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const TRON_RECEIPT_CONTEXT = 'https://observerprotocol.org/context/tron-receipt/v1';
const ED25519_2020_CONTEXT = 'https://w3id.org/security/suites/ed25519-2020/v1';

/**
 * TRON Receipt VC Schema Definition
 */
export const TronReceiptSchema = {
  id: 'tron_receipt_v1',
  version: '1.0.0',
  type: 'VerifiableCredential',
  
  // Required fields
  required: [
    'issuer_did',
    'subject_did', 
    'rail',
    'asset',
    'amount',
    'tron_tx_hash',
    'timestamp'
  ],
  
  // Field definitions
  fields: {
    issuer_did: {
      type: 'string',
      description: 'DID of the issuing agent',
      pattern: '^did:[a-z]+:.+$'
    },
    subject_did: {
      type: 'string',
      description: 'DID of the subject (counterparty) agent',
      pattern: '^did:[a-z]+:.+$'
    },
    rail: {
      type: 'string',
      enum: ['tron', 'tron:trc20', 'tron:native'],
      description: 'Payment rail used'
    },
    asset: {
      type: 'string',
      description: 'Asset identifier (e.g., TRX, USDT, USDC)'
    },
    amount: {
      type: 'string',
      description: 'Amount in smallest unit (sun for TRX, raw for TRC-20)'
    },
    tron_tx_hash: {
      type: 'string',
      pattern: '^[0-9a-fA-F]{64}$',
      description: 'TRON transaction hash'
    },
    timestamp: {
      type: 'string',
      format: 'date-time',
      description: 'ISO 8601 timestamp of transaction'
    },
    org_affiliation: {
      type: 'string',
      description: 'Organization affiliation of issuer (optional)',
      optional: true
    },
    sender_address: {
      type: 'string',
      description: 'TRON address of sender (T...)',
      optional: true
    },
    recipient_address: {
      type: 'string',
      description: 'TRON address of recipient (T...)',
      optional: true
    },
    token_contract: {
      type: 'string',
      description: 'TRC-20 contract address for TRC-20 transfers',
      optional: true
    },
    confirmations: {
      type: 'number',
      description: 'Number of block confirmations',
      optional: true,
      default: 0
    },
    network: {
      type: 'string',
      enum: ['mainnet', 'shasta', 'nile'],
      default: 'mainnet',
      optional: true
    }
  }
};

/**
 * Validate TRON receipt data
 */
export function validateTronReceiptData(data) {
  const errors = [];
  
  // Check required fields
  for (const field of TronReceiptSchema.required) {
    if (data[field] === undefined || data[field] === null) {
      errors.push(`Missing required field: ${field}`);
    }
  }
  
  // Validate rail type
  if (data.rail && !TronReceiptSchema.fields.rail.enum.includes(data.rail)) {
    errors.push(`Invalid rail: ${data.rail}`);
  }
  
  // Validate TRON transaction hash format
  if (data.tron_tx_hash && !/^[0-9a-fA-F]{64}$/.test(data.tron_tx_hash)) {
    errors.push(`Invalid tron_tx_hash format: must be 64 hex characters`);
  }
  
  // Validate addresses if provided
  if (data.sender_address && !validateTronAddress(data.sender_address)) {
    errors.push(`Invalid sender_address: ${data.sender_address}`);
  }
  
  if (data.recipient_address && !validateTronAddress(data.recipient_address)) {
    errors.push(`Invalid recipient_address: ${data.recipient_address}`);
  }
  
  // Validate timestamp format
  if (data.timestamp) {
    try {
      new Date(data.timestamp).toISOString();
    } catch {
      errors.push(`Invalid timestamp format: ${data.timestamp}`);
    }
  }
  
  // Validate amount is numeric string
  if (data.amount && !/^\d+$/.test(data.amount)) {
    errors.push(`Invalid amount: must be numeric string (no decimals)`);
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create a TRON receipt VC payload (before signing)
 */
export function createTronReceiptPayload(data) {
  const validation = validateTronReceiptData(data);
  if (!validation.valid) {
    throw new Error(`Invalid receipt data: ${validation.errors.join(', ')}`);
  }
  
  const credentialId = `urn:uuid:${randomUUID()}`;
  const now = new Date().toISOString();
  
  // Build credential subject
  const credentialSubject = {
    id: data.subject_did,
    rail: data.rail,
    asset: data.asset,
    amount: data.amount,
    tronTxHash: data.tron_tx_hash,
    timestamp: data.timestamp
  };
  
  // Add optional fields
  if (data.org_affiliation) {
    credentialSubject.orgAffiliation = data.org_affiliation;
  }
  if (data.sender_address) {
    credentialSubject.senderAddress = data.sender_address;
  }
  if (data.recipient_address) {
    credentialSubject.recipientAddress = data.recipient_address;
  }
  if (data.token_contract) {
    credentialSubject.tokenContract = data.token_contract;
  }
  if (data.confirmations !== undefined) {
    credentialSubject.confirmations = data.confirmations;
  }
  if (data.network) {
    credentialSubject.network = data.network;
  }
  
  // Build the credential
  const credential = {
    '@context': [
      W3C_CREDENTIALS_CONTEXT,
      TRON_RECEIPT_CONTEXT,
      ED25519_2020_CONTEXT
    ],
    'id': credentialId,
    'type': ['VerifiableCredential', 'TronTransactionReceipt'],
    'issuer': data.issuer_did,
    'issuanceDate': now,
    'credentialSubject': credentialSubject
  };
  
  // Add expiration (7 days from issuance)
  const expiration = new Date();
  expiration.setDate(expiration.getDate() + 7);
  credential.expirationDate = expiration.toISOString();
  
  return credential;
}

/**
 * Sign a TRON receipt VC with Ed25519Signature2020
 */
export async function signTronReceipt(credential, signingKey) {
  // Import Ed25519 from node:crypto
  const { privateKey } = await import('node:crypto');
  
  // Create canonical bytes for signing (proof excluded)
  const docToSign = { ...credential };
  delete docToSign.proof;
  
  const canonicalBytes = Buffer.from(
    JSON.stringify(docToSign, Object.keys(docToSign).sort(), 0)
      .replace(/\s/g, ''),
    'utf-8'
  );
  
  // Hash the canonical document
  const hash = createHash('sha256').update(canonicalBytes).digest();
  
  // Sign the hash
  const signature = await signingKey.sign(hash);
  const signatureBase58 = 'z' + base58.encode(signature);
  
  // Create the proof
  const proof = {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${credential.issuer}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: signatureBase58
  };
  
  return {
    ...credential,
    proof
  };
}

/**
 * Verify a TRON receipt VC signature
 */
export async function verifyTronReceipt(vc, issuerPublicKey) {
  try {
    // Extract proof
    const { proof, ...credentialWithoutProof } = vc;
    
    if (!proof) {
      return { verified: false, error: 'Missing proof' };
    }
    
    if (proof.type !== 'Ed25519Signature2020') {
      return { verified: false, error: `Unsupported proof type: ${proof.type}` };
    }
    
    // Reconstruct canonical bytes
    const canonicalBytes = Buffer.from(
      JSON.stringify(credentialWithoutProof, Object.keys(credentialWithoutProof).sort(), 0)
        .replace(/\s/g, ''),
      'utf-8'
    );
    
    const hash = createHash('sha256').update(canonicalBytes).digest();
    
    // Decode signature
    const signatureBase58 = proof.proofValue.startsWith('z') 
      ? proof.proofValue.slice(1) 
      : proof.proofValue;
    const signature = base58.decode(signatureBase58);
    
    // Verify
    const verified = issuerPublicKey.verify(hash, signature);
    
    return {
      verified,
      error: verified ? null : 'Signature verification failed'
    };
  } catch (error) {
    return {
      verified: false,
      error: error.message
    };
  }
}

/**
 * Hash a TRON receipt for storage/lookup
 */
export function hashTronReceipt(vc) {
  const canonical = JSON.stringify(vc.credentialSubject, Object.keys(vc.credentialSubject).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Extract receipt summary for VAC extension
 */
export function extractReceiptSummary(vc) {
  const cs = vc.credentialSubject;
  
  return {
    receiptId: vc.id,
    type: 'tron_receipt_v1',
    issuer: vc.issuer,
    subject: cs.id,
    rail: cs.rail,
    asset: cs.asset,
    amount: cs.amount,
    tronTxHash: cs.tronTxHash,
    timestamp: cs.timestamp,
    orgAffiliation: cs.orgAffiliation || null,
    verified: !!vc.proof,
    issuedAt: vc.issuanceDate
  };
}

/**
 * Generate a receipt ID from transaction hash
 */
export function generateReceiptId(tronTxHash, senderDid, timestamp) {
  const input = `${tronTxHash}:${senderDid}:${timestamp}`;
  return createHash('sha256').update(input).digest('hex');
}

export default {
  TronReceiptSchema,
  validateTronReceiptData,
  createTronReceiptPayload,
  signTronReceipt,
  verifyTronReceipt,
  hashTronReceipt,
  extractReceiptSummary,
  generateReceiptId
};
