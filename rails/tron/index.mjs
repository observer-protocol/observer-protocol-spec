/**
 * TRON Rail — Observer Protocol Integration
 * 
 * Main entry point for TRON rail functionality.
 * 
 * Usage:
 *   import { TronRail } from './rails/tron/index.mjs';
 *   
 *   // Configuration is loaded from environment:
 *   // export TRON_NETWORK=mainnet  # or shasta
 *   // export TRONGRID_API_KEY=your_key
 *   
 *   const tron = new TronRail();
 *   
 *   // Create and sign a receipt
 *   const receipt = await tron.createReceipt({
 *     issuer_did: 'did:op:...',
 *     subject_did: 'did:op:...',
 *     rail: 'tron:trc20',
 *     asset: 'USDT',
 *     amount: '1000000', // 1 USDT (6 decimals)
 *     tron_tx_hash: '...',
 *     timestamp: '2026-04-13T14:00:00Z',
 *     sender_address: 'T...',
 *     recipient_address: 'T...',
 *     token_contract: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
 *   });
 *   
 *   // Verify a receipt
 *   const result = await tron.verifyReceipt(receipt);
 *   console.log(result.verified); // true/false
 * 
 * Environment Variables:
 *   - TRON_NETWORK: Required. Set to 'mainnet' or 'shasta'
 *   - TRONGRID_API_KEY: API key for mainnet
 *   - TRONGRID_SHASTA_API_KEY: Optional separate API key for Shasta
 *   - OP_DID: Observer Protocol DID (optional)
 *   - OP_SIGNING_KEY: Signing key for receipts (optional)
 */

import { 
  TronGridClient, 
  publicKeyToTronAddress, 
  TRON_AIP_TYPES,
  TronConfig,
  getTronConfig,
  resetTronConfig,
  MAINNET_USDT_CONTRACT
} from './tron-core.mjs';
import { 
  createTronReceiptPayload, 
  signTronReceipt,
  verifyTronReceipt,
  validateTronReceiptData,
  extractReceiptSummary 
} from './tron-receipt-vc.mjs';
import { 
  TronReceiptVerifier, 
  TronReceiptEndpoint,
  tronReceiptToVACExtension 
} from './tron-verification.mjs';

/**
 * Main TRON Rail class
 * 
 * Configuration Priority:
 * 1. Constructor options
 * 2. Environment variables (TRON_NETWORK, TRONGRID_API_KEY)
 * 
 * @throws {Error} If TRON_NETWORK is not set
 * @throws {Error} If API key for the network is not found
 */
export class TronRail {
  constructor(options = {}) {
    // Initialize configuration
    try {
      this.config = options.config || getTronConfig(options);
    } catch (error) {
      // Enhance error message with helpful context
      if (error.message.includes('TRON_NETWORK')) {
        throw new Error(
          `${error.message}\n\n` +
          `To use the TRON rail, you must set the TRON_NETWORK environment variable:\n` +
          `  export TRON_NETWORK=mainnet   # For production/mainnet\n` +
          `  export TRON_NETWORK=shasta    # For testing on Shasta testnet\n\n` +
          `You also need a TronGrid API key:\n` +
          `  export TRONGRID_API_KEY=your_api_key_here\n\n` +
          `Get a free API key at: https://www.trongrid.io/`
        );
      }
      throw error;
    }
    
    this.network = this.config.getNetworkName();
    this.apiKey = this.config.getApiKey();
    this.opDid = options.opDid || process.env.OP_DID;
    this.signingKey = options.signingKey || null;
    
    // Initialize TronGrid client with config
    this.client = new TronGridClient({
      config: this.config,
      timeout: options.timeout
    });
    
    // Initialize verifier with config
    this.verifier = new TronReceiptVerifier({
      config: this.config,
      minConfirmations: options.minConfirmations || this.config.getMinConfirmations(),
      maxAgeHours: options.maxAgeHours
    });
    
    // Initialize endpoint with config
    this.endpoint = new TronReceiptEndpoint({
      config: this.config,
      opDid: this.opDid
    });
  }

  /**
   * Get the current configuration summary (safe for logging - API key masked)
   */
  getConfigSummary() {
    return this.config.getSummary();
  }

  /**
   * Check if running on mainnet
   */
  isMainnet() {
    return this.config.isMainnet();
  }

  /**
   * Check if running on testnet
   */
  isTestnet() {
    return this.config.isTestnet();
  }

  /**
   * Create a new TRON transaction receipt
   */
  async createReceipt(data, options = {}) {
    // Validate input
    const validation = validateTronReceiptData(data);
    if (!validation.valid) {
      throw new Error(`Invalid receipt data: ${validation.errors.join(', ')}`);
    }

    // Validate contract network compatibility if token_contract provided
    if (data.token_contract) {
      const contractValidation = this.config.validateContractNetwork(data.token_contract);
      if (!contractValidation.valid) {
        throw new Error(`Contract validation failed: ${contractValidation.error}`);
      }
      if (contractValidation.warning) {
        console.warn(`⚠️  ${contractValidation.warning}`);
      }
    }

    // Create credential payload
    const payload = createTronReceiptPayload({
      ...data,
      network: this.network
    });

    // Sign if signing key provided
    if (options.sign && this.signingKey) {
      return await signTronReceipt(payload, this.signingKey);
    }

    return payload;
  }

  /**
   * Sign an existing receipt
   */
  async signReceipt(receipt) {
    if (!this.signingKey) {
      throw new Error('No signing key configured');
    }
    return await signTronReceipt(receipt, this.signingKey);
  }

  /**
   * Verify a receipt (both signature and TronGrid)
   */
  async verifyReceipt(receipt, options = {}) {
    return await this.verifier.verifyReceipt(receipt);
  }

  /**
   * Submit receipt to recipient endpoint
   */
  async submitReceipt(receipt, recipientEndpoint, recipientDid) {
    return await this.endpoint.sendReceipt(receipt, recipientEndpoint, recipientDid);
  }

  /**
   * Handle incoming receipt
   */
  async handleIncomingReceipt(receipt, recipientAgentId) {
    return await this.endpoint.handleReceiptSubmission(receipt, recipientAgentId);
  }

  /**
   * Convert receipt to VAC extension
   */
  toVACExtension(receipt, verificationResult) {
    return tronReceiptToVACExtension(receipt, verificationResult);
  }

  /**
   * Derive TRON address from public key
   */
  deriveAddress(publicKey, isTestnet = null) {
    // If isTestnet not specified, use current network
    const useTestnet = isTestnet !== null ? isTestnet : this.isTestnet();
    return publicKeyToTronAddress(publicKey, useTestnet);
  }

  /**
   * Get AIP type identifier
   */
  getAIPType(isTRC20 = true) {
    return isTRC20 ? TRON_AIP_TYPES.TRC20 : TRON_AIP_TYPES.NATIVE;
  }

  /**
   * Get TRX balance for an address
   */
  async getTrxBalance(address) {
    return await this.client.getTrxBalance(address);
  }

  /**
   * Get TRC-20 token balance
   */
  async getTRC20Balance(address, contract = null) {
    const tokenContract = contract || this.config.getUsdtContract();
    return await this.client.getTRC20Balance(address, tokenContract);
  }

  /**
   * Check if address has sufficient gas (TRX)
   */
  async checkGasBalance(address, requiredEnergy = 65000) {
    return await this.client.checkGasBalance(address, requiredEnergy);
  }

  /**
   * Get USDT contract address
   */
  getUsdtContract() {
    return this.config.getUsdtContract();
  }

  /**
   * Get TronScan URL for a transaction
   */
  getTronscanUrl(txHash) {
    return this.config.getTronscanTxUrl(txHash);
  }

  /**
   * Get minimum required confirmations for this network
   */
  getMinConfirmations() {
    return this.config.getMinConfirmations();
  }

  /**
   * Get token information
   */
  async getTokenInfo(contract = null) {
    const tokenContract = contract || this.config.getUsdtContract();
    return await this.client.getTokenInfo(tokenContract);
  }

  /**
   * Validate a transaction exists and has required confirmations
   */
  async validateTransaction(txHash, options = {}) {
    const minConfirmations = options.minConfirmations || this.getMinConfirmations();
    
    try {
      const result = await this.client.verifyTRC20Transfer(
        txHash,
        options.expectedFrom || null,
        options.expectedTo || null,
        options.expectedAmount || null,
        options.tokenContract || null
      );

      if (!result.verified) {
        return {
          valid: false,
          error: result.error,
          txHash
        };
      }

      if (result.confirmations < minConfirmations) {
        return {
          valid: false,
          error: `Insufficient confirmations: ${result.confirmations} < ${minConfirmations}`,
          txHash,
          confirmations: result.confirmations,
          required: minConfirmations
        };
      }

      return {
        valid: true,
        txHash,
        from: result.from,
        to: result.to,
        amount: result.amount,
        token: result.token,
        confirmations: result.confirmations,
        blockNumber: result.blockNumber,
        timestamp: result.timestamp
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message,
        txHash
      };
    }
  }
}

// Re-exports from submodules (includes all named exports)
export * from './tron-core.mjs';
export * from './tron-receipt-vc.mjs';
export * from './tron-verification.mjs';
export * from './tron-config.mjs';

export default TronRail;
