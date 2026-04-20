/**
 * TRON Configuration Module
 * 
 * Environment-based network selection for TRON rail.
 * Supports mainnet and shasta testnet configurations.
 */

// Valid TRON networks
export const VALID_NETWORKS = ['mainnet', 'shasta', 'nile'];

// Default USDT contract on mainnet
export const MAINNET_USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

// Configuration by network
const NETWORK_CONFIG = {
  mainnet: {
    name: 'mainnet',
    apiEndpoint: 'https://api.trongrid.io',
    usdtContract: MAINNET_USDT_CONTRACT,
    minConfirmations: 19,
    tronscanUrl: 'https://tronscan.org/#/transaction',
    chainId: '0x2b6653dc',
    isTestnet: false
  },
  shasta: {
    name: 'shasta',
    apiEndpoint: 'https://api.shasta.trongrid.io',
    usdtContract: null, // No official USDT on Shasta - use test tokens
    minConfirmations: 1,
    tronscanUrl: 'https://shasta.tronscan.org/#/transaction',
    chainId: '0x94a9059e',
    isTestnet: true
  },
  nile: {
    name: 'nile',
    apiEndpoint: 'https://nile.trongrid.io',
    usdtContract: null,
    minConfirmations: 1,
    tronscanUrl: 'https://nile.tronscan.org/#/transaction',
    chainId: '0xcd8690dc',
    isTestnet: true
  }
};

/**
 * TRON Configuration class
 * Loads configuration once at initialization based on TRON_NETWORK env var
 */
export class TronConfig {
  constructor(options = {}) {
    this.network = options.network || process.env.TRON_NETWORK;
    this.apiKey = options.apiKey || this._getApiKeyForNetwork();
    this._config = null;
    
    // Validate network is set
    if (!this.network) {
      throw new Error(
        'TRON_NETWORK environment variable is not set. ' +
        'Please set TRON_NETWORK to "mainnet" or "shasta". ' +
        'Example: export TRON_NETWORK=mainnet'
      );
    }
    
    // Validate network is valid
    if (!VALID_NETWORKS.includes(this.network)) {
      throw new Error(
        `Invalid TRON_NETWORK: "${this.network}". ` +
        `Must be one of: ${VALID_NETWORKS.join(', ')}`
      );
    }
    
    // Load configuration
    this._loadConfig();
  }
  
  /**
   * Get API key for the configured network
   * Supports TRONGRID_API_KEY (mainnet) and TRONGRID_SHASTA_API_KEY (shasta)
   */
  _getApiKeyForNetwork() {
    if (this.network === 'mainnet') {
      return process.env.TRONGRID_API_KEY;
    } else if (this.network === 'shasta') {
      return process.env.TRONGRID_SHASTA_API_KEY || process.env.TRONGRID_API_KEY;
    } else {
      return process.env.TRONGRID_API_KEY;
    }
  }
  
  /**
   * Load configuration for the selected network
   */
  _loadConfig() {
    const baseConfig = NETWORK_CONFIG[this.network];
    
    if (!baseConfig) {
      throw new Error(`Configuration not found for network: ${this.network}`);
    }
    
    this._config = {
      ...baseConfig,
      apiKey: this.apiKey
    };
    
    // Validate API key is present
    if (!this.apiKey) {
      throw new Error(
        `TronGrid API key not found for ${this.network}. ` +
        `Please set ${this.network === 'mainnet' ? 'TRONGRID_API_KEY' : 'TRONGRID_SHASTA_API_KEY or TRONGRID_API_KEY'} ` +
        `environment variable.`
      );
    }
    
    // Validate USDT contract on mainnet
    if (this.network === 'mainnet' && !this._validateUsdtContract()) {
      throw new Error(
        `USDT contract validation failed for mainnet. ` +
        `Expected: ${MAINNET_USDT_CONTRACT}. ` +
        `Please verify contract address at https://tronscan.org`
      );
    }
  }
  
  /**
   * Validate USDT contract address format
   */
  _validateUsdtContract() {
    const contract = this._config.usdtContract;
    if (!contract || contract.length !== 34 || !contract.startsWith('T')) {
      return false;
    }
    // Additional validation could query TronGrid to verify contract exists
    return true;
  }
  
  /**
   * Get full configuration object
   */
  getConfig() {
    return { ...this._config };
  }
  
  /**
   * Get API endpoint URL
   */
  getApiEndpoint() {
    return this._config.apiEndpoint;
  }
  
  /**
   * Get USDT contract address
   */
  getUsdtContract() {
    return this._config.usdtContract;
  }
  
  /**
   * Get minimum required confirmations
   */
  getMinConfirmations() {
    return this._config.minConfirmations;
  }
  
  /**
   * Get TronScan URL for transaction
   */
  getTronscanTxUrl(txHash) {
    return `${this._config.tronscanUrl}/${txHash}`;
  }
  
  /**
   * Check if current network is mainnet
   */
  isMainnet() {
    return this.network === 'mainnet';
  }
  
  /**
   * Check if current network is a testnet
   */
  isTestnet() {
    return this._config.isTestnet;
  }
  
  /**
   * Get network name
   */
  getNetworkName() {
    return this.network;
  }
  
  /**
   * Get API key
   */
  getApiKey() {
    return this.apiKey;
  }
  
  /**
   * Validate that a contract address matches the declared network
   * Mainnet contract should not be used on testnet and vice versa
   */
  validateContractNetwork(contractAddress) {
    // Mainnet USDT contract should only be used on mainnet
    if (contractAddress === MAINNET_USDT_CONTRACT && this.network !== 'mainnet') {
      return {
        valid: false,
        error: `Mainnet USDT contract ${MAINNET_USDT_CONTRACT} cannot be used on ${this.network}. ` +
               `Please use a testnet USDT contract or switch to mainnet.`
      };
    }
    
    // If using a non-mainnet contract on mainnet, warn but allow
    // (could be a different TRC-20 token)
    if (this.network === 'mainnet' && contractAddress && contractAddress !== MAINNET_USDT_CONTRACT) {
      // This is a warning scenario - different tokens are allowed
      return {
        valid: true,
        warning: `Using non-standard contract ${contractAddress} on mainnet. ` +
                 `Ensure this is the correct contract address.`
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Get a summary of the current configuration (for logging/debugging)
   * Mask the API key for security
   */
  getSummary() {
    const maskedKey = this.apiKey 
      ? `${this.apiKey.slice(0, 8)}...${this.apiKey.slice(-4)}`
      : 'not set';
    
    return {
      network: this.network,
      apiEndpoint: this._config.apiEndpoint,
      apiKey: maskedKey,
      usdtContract: this._config.usdtContract,
      minConfirmations: this._config.minConfirmations,
      isTestnet: this._config.isTestnet
    };
  }
}

/**
 * Get singleton config instance
 * Ensures config is loaded only once
 */
let configInstance = null;

export function getTronConfig(options = {}) {
  if (!configInstance || options.forceReload) {
    configInstance = new TronConfig(options);
  }
  return configInstance;
}

/**
 * Reset config instance (useful for testing)
 */
export function resetTronConfig() {
  configInstance = null;
}

export default {
  TronConfig,
  getTronConfig,
  resetTronConfig,
  MAINNET_USDT_CONTRACT,
  VALID_NETWORKS
};
