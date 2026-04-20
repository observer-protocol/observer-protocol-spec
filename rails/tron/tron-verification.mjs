/**
 * TRON Verification and AIP Integration
 * 
 * Integrates TRON rail with Observer Protocol:
 * - Verify TRON receipts against TronGrid
 * - Store verified receipts in VAC
 * - AIP receipt endpoint handler
 * 
 * Updated for Mainnet Cutover: Uses TronConfig for network selection
 */

import { 
  TronGridClient, 
  validateTronAddress, 
  TRON_AIP_TYPES,
  getTronConfig
} from './tron-core.mjs';
import { 
  validateTronReceiptData, 
  verifyTronReceipt,
  hashTronReceipt,
  extractReceiptSummary 
} from './tron-receipt-vc.mjs';

/**
 * TRON Receipt Verifier
 * Handles verification of TRON transaction receipts
 */
export class TronReceiptVerifier {
  constructor(options = {}) {
    // Use provided config or load from environment
    this.config = options.config;
    
    if (this.config) {
      this.tronGrid = new TronGridClient({ config: this.config });
      this.minConfirmations = options.minConfirmations || this.config.getMinConfirmations();
    } else {
      // Fallback to options for backwards compatibility
      this.tronGrid = new TronGridClient(options);
      this.minConfirmations = options.minConfirmations || 19;
    }
    
    this.maxAgeHours = options.maxAgeHours || 24 * 7; // 7 days
  }

  /**
   * Verify a TRON receipt against TronGrid API
   */
  async verifyReceipt(receipt) {
    const result = {
      verified: false,
      tronGridVerified: false,
      signatureValid: false,
      error: null,
      details: {}
    };

    try {
      // 1. Validate receipt structure
      const validation = validateTronReceiptData(receipt.credentialSubject || receipt);
      if (!validation.valid) {
        result.error = `Invalid receipt structure: ${validation.errors.join(', ')}`;
        return result;
      }

      const cs = receipt.credentialSubject || receipt;
      result.details.credentialSubject = cs;

      // 2. Verify transaction on TronGrid
      const isTRC20 = cs.rail === 'tron:trc20';
      
      if (isTRC20) {
        // Validate contract network compatibility
        if (cs.tokenContract && this.config) {
          const contractValidation = this.config.validateContractNetwork(cs.tokenContract);
          if (!contractValidation.valid) {
            result.error = `Contract validation failed: ${contractValidation.error}`;
            return result;
          }
        }

        // Verify TRC-20 transfer
        const txInfo = await this.tronGrid.verifyTRC20Transfer(
          cs.tronTxHash,
          cs.senderAddress,
          cs.recipientAddress,
          cs.amount,
          cs.tokenContract
        );

        result.details.tronGrid = txInfo;

        if (!txInfo.verified) {
          result.error = `TronGrid verification failed: ${txInfo.error}`;
          return result;
        }

        result.tronGridVerified = true;
        result.details.confirmations = txInfo.confirmations;

        // Check minimum confirmations
        if (txInfo.confirmations < this.minConfirmations) {
          result.error = `Insufficient confirmations: ${txInfo.confirmations} < ${this.minConfirmations}`;
          return result;
        }
      } else {
        // Verify native TRX transfer
        const txInfo = await this.verifyNativeTransfer(cs);
        
        result.details.tronGrid = txInfo;

        if (!txInfo.verified) {
          result.error = `TronGrid verification failed: ${txInfo.error}`;
          return result;
        }

        result.tronGridVerified = true;
      }

      // 3. Check receipt age
      const receiptTime = new Date(cs.timestamp);
      const now = new Date();
      const ageHours = (now - receiptTime) / (1000 * 60 * 60);

      if (ageHours > this.maxAgeHours) {
        result.error = `Receipt too old: ${ageHours.toFixed(1)} hours > ${this.maxAgeHours} hours`;
        return result;
      }

      result.details.ageHours = ageHours;

      // 4. Verify signature if proof is present
      if (receipt.proof) {
        // Public key would be resolved from issuer DID
        // For now, mark as needing DID resolution
        result.details.signatureCheck = 'requires_did_resolution';
        result.signatureValid = null; // Unknown until DID resolved
      } else {
        result.signatureValid = null; // No signature to verify
      }

      result.verified = result.tronGridVerified;

    } catch (error) {
      result.error = `Verification error: ${error.message}`;
    }

    return result;
  }

  /**
   * Verify native TRX transfer
   */
  async verifyNativeTransfer(cs) {
    const result = {
      verified: false,
      txHash: cs.tronTxHash,
      from: null,
      to: null,
      amount: null,
      timestamp: null,
      blockNumber: null,
      confirmations: 0,
      error: null
    };

    try {
      const txInfo = await this.tronGrid.getTransaction(cs.tronTxHash);
      
      if (!txInfo.data || txInfo.data.length === 0) {
        result.error = 'Transaction not found';
        return result;
      }

      const tx = txInfo.data[0];
      
      result.blockNumber = tx.block_number;
      result.timestamp = tx.block_timestamp;

      // Check transaction type (native transfer = 1)
      if (tx.raw_data?.contract?.[0]?.type !== 'TransferContract') {
        result.error = 'Not a native TRX transfer';
        return result;
      }

      const contract = tx.raw_data.contract[0].parameter.value;
      result.from = hexToTronAddress(contract.owner_address);
      result.to = hexToTronAddress(contract.to_address);
      result.amount = contract.amount; // in sun (1 TRX = 1,000,000 sun)

      // Validate against expected values
      if (cs.senderAddress && result.from !== cs.senderAddress) {
        result.error = `Sender mismatch: expected ${cs.senderAddress}, got ${result.from}`;
        return result;
      }

      if (cs.recipientAddress && result.to !== cs.recipientAddress) {
        result.error = `Recipient mismatch: expected ${cs.recipientAddress}, got ${result.to}`;
        return result;
      }

      if (cs.amount && BigInt(result.amount) !== BigInt(cs.amount)) {
        result.error = `Amount mismatch: expected ${cs.amount}, got ${result.amount}`;
        return result;
      }

      // Get confirmations
      try {
        const nowBlock = await this.tronGrid.request('/v1/blocks/latest');
        if (nowBlock.data && nowBlock.data.length > 0) {
          result.confirmations = nowBlock.data[0].block_number - tx.block_number;
        }
      } catch (e) {
        // Don't fail if we can't get confirmations
      }

      result.verified = true;

    } catch (error) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Batch verify multiple receipts
   */
  async batchVerify(receipts) {
    const results = await Promise.allSettled(
      receipts.map(r => this.verifyReceipt(r))
    );

    return results.map((result, index) => ({
      index,
      receiptId: receipts[index].id || `receipt_${index}`,
      status: result.status,
      result: result.status === 'fulfilled' ? result.value : { error: result.reason?.message }
    }));
  }
}

/**
 * AIP Receipt Endpoint Handler
 * Handles receipt transmission between agents
 */
export class TronReceiptEndpoint {
  constructor(options = {}) {
    // Use provided config or load from environment
    this.config = options.config;
    
    if (this.config) {
      this.verifier = new TronReceiptVerifier({ config: this.config });
    } else {
      this.verifier = new TronReceiptVerifier(options);
    }
    
    this.dbUrl = options.dbUrl || process.env.DATABASE_URL;
    this.opDid = options.opDid || process.env.OP_DID;
  }

  /**
   * Handle incoming receipt from another agent
   */
  async handleReceiptSubmission(receipt, recipientAgentId) {
    const result = {
      accepted: false,
      receiptId: null,
      verificationResult: null,
      error: null
    };

    try {
      // 1. Verify receipt
      const verification = await this.verifier.verifyReceipt(receipt);
      result.verificationResult = verification;

      if (!verification.verified) {
        result.error = `Receipt verification failed: ${verification.error}`;
        return result;
      }

      // 2. Store receipt
      const stored = await this.storeReceipt(receipt, recipientAgentId);
      result.receiptId = stored.receiptId;
      result.accepted = true;

    } catch (error) {
      result.error = `Receipt submission error: ${error.message}`;
    }

    return result;
  }

  /**
   * Store verified receipt in database
   */
  async storeReceipt(receipt, recipientAgentId) {
    const receiptHash = hashTronReceipt(receipt);
    const receiptId = `tr_${receiptHash.slice(0, 32)}`;
    
    const summary = extractReceiptSummary(receipt);
    
    // This would connect to the database
    // For now, return the structure that would be stored
    return {
      receiptId,
      agentId: recipientAgentId,
      type: 'tron_receipt_v1',
      status: 'verified',
      summary,
      fullReceipt: receipt,
      verifiedAt: new Date().toISOString(),
      expiresAt: receipt.expirationDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    };
  }

  /**
   * Get receipts for an agent
   */
  async getAgentReceipts(agentId, options = {}) {
    // This would query the database
    // Placeholder for implementation
    return {
      agentId,
      receipts: [],
      total: 0,
      page: options.page || 1,
      limit: options.limit || 10
    };
  }

  /**
   * Send receipt to another agent's endpoint
   */
  async sendReceipt(receipt, recipientEndpoint, recipientDid) {
    const payload = {
      receipt,
      senderDid: receipt.issuer,
      recipientDid,
      timestamp: new Date().toISOString()
    };

    try {
      const response = await fetch(recipientEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Receipt-Type': 'tron_receipt_v1',
          'X-Sender-DID': receipt.issuer
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`HTTP ${response.status}: ${error}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Failed to send receipt: ${error.message}`);
    }
  }
}

/**
 * Convert TRON receipt to VAC extension format
 */
export function tronReceiptToVACExtension(receipt, verificationResult) {
  const cs = receipt.credentialSubject || receipt;
  
  return {
    type: 'tron_receipt_v1',
    receiptId: receipt.id,
    issuerDid: receipt.issuer,
    rail: cs.rail,
    asset: cs.asset,
    amount: cs.amount,
    tronTxHash: cs.tronTxHash,
    timestamp: cs.timestamp,
    orgAffiliation: cs.orgAffiliation || null,
    verified: verificationResult?.verified || false,
    tronGridVerified: verificationResult?.tronGridVerified || false,
    issuedAt: receipt.issuanceDate,
    expiresAt: receipt.expirationDate
  };
}

// Helper function for hex conversion
function hexToTronAddress(hex) {
  const { hexToTronAddress: convert } = require('./tron-core.mjs');
  return convert(hex);
}

export default {
  TronReceiptVerifier,
  TronReceiptEndpoint,
  tronReceiptToVACExtension
};
