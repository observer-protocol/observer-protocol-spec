/**
 * TRON Rail — Core Utilities
 * 
 * Provides TRON-specific functionality:
 * - Address derivation (secp256k1 + Base58Check with T prefix)
 * - TronGrid API integration for TRC-20 transaction verification
 * - TRON network utilities (mainnet/shasta testnet)
 * 
 * Updated for Mainnet Cutover: Environment-based network selection via TRON_NETWORK env var
 */

import { createHash } from 'crypto';
import { TronConfig, getTronConfig, resetTronConfig, MAINNET_USDT_CONTRACT, VALID_NETWORKS } from './tron-config.mjs';

// Re-export configuration
export { TronConfig, getTronConfig, resetTronConfig, MAINNET_USDT_CONTRACT, VALID_NETWORKS };

// TRON address version byte (mainnet)
const TRON_ADDRESS_VERSION = 0x41; // 'T' prefix when Base58Check encoded
const TRON_SHASTA_VERSION = 0xA0; // Shasta testnet

// Common TRC-20 token contracts (mainnet)
const TRC20_CONTRACTS = {
  USDT: MAINNET_USDT_CONTRACT,
  USDC: 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8',
  TUSD: 'TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4',
  USDD: 'TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn'
};

// TRC-20 Transfer event signature
const TRANSFER_EVENT_SIGNATURE = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

/**
 * Convert a public key to a TRON address
 * Uses secp256k1 public key → keccak256 → last 20 bytes → Base58Check with T prefix
 * 
 * @param {Buffer} publicKey - Uncompressed public key (64 bytes, without 0x04 prefix)
 * @param {boolean} isTestnet - Whether to use Shasta testnet
 * @returns {string} TRON address (e.g., "TJRabPrwbZyHFGZVFwP7KV...")
 */
export function publicKeyToTronAddress(publicKey, isTestnet = false) {
  // Remove 0x04 prefix if present
  const pubKeyBytes = publicKey.length === 65 && publicKey[0] === 0x04
    ? publicKey.slice(1)
    : publicKey;
  
  if (pubKeyBytes.length !== 64) {
    throw new Error(`Invalid public key length: ${pubKeyBytes.length} bytes (expected 64)`);
  }

  // Keccak256 hash of public key
  const hash = createHash('sha3-256').update(pubKeyBytes).digest();
  
  // Last 20 bytes become the address
  const addressBytes = hash.slice(-20);
  
  // Add version byte prefix
  const version = isTestnet ? TRON_SHASTA_VERSION : TRON_ADDRESS_VERSION;
  const versioned = Buffer.concat([Buffer.from([version]), addressBytes]);
  
  // Double SHA256 checksum
  const checksum = createHash('sha256').update(
    createHash('sha256').update(versioned).digest()
  ).digest().slice(0, 4);
  
  // Base58 encode
  const fullBytes = Buffer.concat([versioned, checksum]);
  return base58Encode(fullBytes);
}

/**
 * Base58 encode (TRON uses same alphabet as Bitcoin)
 */
function base58Encode(buffer) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  
  let num = BigInt('0x' + buffer.toString('hex'));
  let result = '';
  
  while (num > 0) {
    const remainder = Number(num % BigInt(58));
    result = ALPHABET[remainder] + result;
    num = num / BigInt(58);
  }
  
  // Add leading 1s for leading zero bytes
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 0) {
      result = '1' + result;
    } else {
      break;
    }
  }
  
  return result;
}

/**
 * Base58 decode
 */
function base58Decode(str) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const ALPHABET_MAP = new Map(ALPHABET.split('').map((c, i) => [c, BigInt(i)]));
  
  let num = BigInt(0);
  for (const char of str) {
    const val = ALPHABET_MAP.get(char);
    if (val === undefined) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }
    num = num * BigInt(58) + val;
  }
  
  // Convert to hex string
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  
  // Add leading zero bytes
  let leadingZeros = 0;
  for (const char of str) {
    if (char === '1') leadingZeros++;
    else break;
  }
  
  return Buffer.from('00'.repeat(leadingZeros) + hex, 'hex');
}

/**
 * Validate a TRON address format
 */
export function validateTronAddress(address) {
  if (typeof address !== 'string') return false;
  if (!address.startsWith('T') && !address.startsWith('27')) return false;
  if (address.length !== 34) return false;
  
  try {
    const decoded = base58Decode(address);
    if (decoded.length !== 25) return false;
    
    const version = decoded[0];
    const payload = decoded.slice(0, 21);
    const checksum = decoded.slice(21, 25);
    
    // Verify checksum
    const computedChecksum = createHash('sha256').update(
      createHash('sha256').update(payload).digest()
    ).digest().slice(0, 4);
    
    return checksum.equals(computedChecksum);
  } catch {
    return false;
  }
}

/**
 * Convert TRON address to hex format (for API calls)
 */
export function tronAddressToHex(address) {
  const decoded = base58Decode(address);
  return '41' + decoded.slice(1, 21).toString('hex');
}

/**
 * Convert hex address to Base58 TRON address
 */
export function hexToTronAddress(hex) {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const addressBytes = Buffer.from(cleanHex.slice(2), 'hex'); // Remove '41' prefix
  
  const versioned = Buffer.concat([Buffer.from([TRON_ADDRESS_VERSION]), addressBytes]);
  const checksum = createHash('sha256').update(
    createHash('sha256').update(versioned).digest()
  ).digest().slice(0, 4);
  
  return base58Encode(Buffer.concat([versioned, checksum]));
}

/**
 * TronGrid API Client
 * Updated for environment-based configuration
 */
export class TronGridClient {
  constructor(options = {}) {
    // Load configuration
    let config;
    try {
      config = options.config || getTronConfig(options);
    } catch (error) {
      // If config fails to load, use options or throw
      if (options.apiKey && options.network) {
        config = {
          getApiEndpoint: () => {
            const endpoints = {
              mainnet: 'https://api.trongrid.io',
              shasta: 'https://api.shasta.trongrid.io',
              nile: 'https://nile.trongrid.io'
            };
            return endpoints[options.network] || endpoints.mainnet;
          },
          getApiKey: () => options.apiKey,
          getMinConfirmations: () => options.minConfirmations || 19,
          getUsdtContract: () => MAINNET_USDT_CONTRACT,
          isMainnet: () => options.network === 'mainnet',
          isTestnet: () => options.network === 'shasta' || options.network === 'nile',
          getNetworkName: () => options.network || 'mainnet'
        };
      } else {
        throw error;
      }
    }
    
    this.config = config;
    this.apiKey = config.getApiKey();
    this.baseUrl = config.getApiEndpoint();
    this.network = config.getNetworkName();
    this.timeout = options.timeout || 30000;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    if (this.apiKey) {
      headers['TRON-PRO-API-KEY'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`TronGrid API error: ${response.status} - ${error}`);
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error('TronGrid API request timeout');
      }
      throw error;
    }
  }

  /**
   * Get account information
   */
  async getAccount(address) {
    const hexAddress = validateTronAddress(address) 
      ? tronAddressToHex(address) 
      : address;
    return this.request(`/v1/accounts/${hexAddress}`);
  }

  /**
   * Get transaction by ID
   */
  async getTransaction(txHash) {
    return this.request(`/v1/transactions/${txHash}`);
  }

  /**
   * Get TRC-20 transaction info by ID
   */
  async getTRC20Transaction(txHash) {
    return this.request(`/v1/contracts/${txHash}/transactions`);
  }

  /**
   * Get events for a specific contract
   */
  async getContractEvents(contract, options = {}) {
    const params = new URLSearchParams();
    if (options.eventName) params.append('event_name', options.eventName);
    if (options.blockNumber) params.append('block_number', options.blockNumber);
    if (options.minBlockTimestamp) params.append('min_block_timestamp', options.minBlockTimestamp);
    if (options.maxBlockTimestamp) params.append('max_block_timestamp', options.maxBlockTimestamp);
    if (options.limit) params.append('limit', options.limit.toString());
    
    return this.request(`/v1/contracts/${contract}/events?${params.toString()}`);
  }

  /**
   * Get TRX balance for an address
   */
  async getTrxBalance(address) {
    try {
      const account = await this.getAccount(address);
      if (account.data && account.data.length > 0) {
        return BigInt(account.data[0].balance || 0);
      }
      return BigInt(0);
    } catch (error) {
      if (error.message.includes('404')) {
        return BigInt(0); // Account not found = 0 balance
      }
      throw error;
    }
  }

  /**
   * Get TRC-20 token balance
   */
  async getTRC20Balance(address, contract) {
    const hexAddress = validateTronAddress(address)
      ? tronAddressToHex(address)
      : address;
    
    // Build the parameter for balanceOf(address)
    // address needs to be 32 bytes (64 hex chars) padded
    const paddedAddress = hexAddress.slice(2).padStart(64, '0'); // Remove '41' prefix and pad
    
    // Function selector for balanceOf(address) = 0x70a08231
    const data = {
      owner_address: hexAddress,
      contract_address: contract,
      function_selector: 'balanceOf(address)',
      parameter: paddedAddress
    };

    try {
      const result = await this.request('/wallet/triggerconstantcontract', {
        method: 'POST',
        body: JSON.stringify(data)
      });
      
      // Parse the constant result
      if (result.constant_result && result.constant_result.length > 0) {
        // Result is a hex string, convert to BigInt
        const hexResult = result.constant_result[0];
        return BigInt('0x' + hexResult);
      }
      return BigInt(0);
    } catch (error) {
      if (error.message.includes('404')) {
        return BigInt(0);
      }
      throw error;
    }
  }

  /**
   * Verify a TRC-20 transfer transaction
   */
  async verifyTRC20Transfer(txHash, expectedFrom, expectedTo, expectedAmount, tokenContract) {
    const result = {
      verified: false,
      txHash,
      from: null,
      to: null,
      amount: null,
      token: null,
      timestamp: null,
      blockNumber: null,
      confirmations: 0,
      error: null
    };

    try {
      // Get transaction info
      const txInfo = await this.getTransaction(txHash);
      
      if (!txInfo.data || txInfo.data.length === 0) {
        result.error = 'Transaction not found';
        return result;
      }

      const tx = txInfo.data[0];
      result.blockNumber = tx.block_number;
      result.timestamp = tx.block_timestamp;

      // Get contract for verification
      const contract = tokenContract || this.config.getUsdtContract();
      result.token = contract;
      
      if (!contract) {
        result.error = 'No token contract specified and no default for this network';
        return result;
      }

      // Validate contract network compatibility
      const config = this.config;
      if (config && config.validateContractNetwork) {
        const validation = config.validateContractNetwork(contract);
        if (!validation.valid) {
          result.error = validation.error;
          return result;
        }
      }

      // Get contract events for TRC-20 transfers
      const events = await this.getContractEvents(contract, {
        eventName: 'Transfer',
        minBlockTimestamp: tx.block_timestamp - 60000, // 1 min before
        maxBlockTimestamp: tx.block_timestamp + 60000, // 1 min after
        limit: 100
      });

      // Find matching transfer event
      const transferEvent = events.data?.find(event => {
        if (event.transaction_id !== txHash) return false;
        
        const from = hexToTronAddress(event.result.from || event.result._from);
        const to = hexToTronAddress(event.result.to || event.result._to);
        const amount = BigInt(event.result.value || event.result._value);
        
        const fromMatch = !expectedFrom || from === expectedFrom;
        const toMatch = !expectedTo || to === expectedTo;
        const amountMatch = !expectedAmount || amount === BigInt(expectedAmount);
        
        return fromMatch && toMatch && amountMatch;
      });

      if (!transferEvent) {
        result.error = 'No matching TRC-20 transfer found in transaction';
        return result;
      }

      result.from = hexToTronAddress(transferEvent.result.from || transferEvent.result._from);
      result.to = hexToTronAddress(transferEvent.result.to || transferEvent.result._to);
      result.amount = transferEvent.result.value || transferEvent.result._value;

      // Get current block for confirmations
      try {
        const nowBlock = await this.request('/v1/blocks/latest');
        if (nowBlock.data && nowBlock.data.length > 0) {
          result.confirmations = nowBlock.data[0].block_number - tx.block_number;
        }
      } catch (e) {
        // Don't fail if we can't get confirmations
        result.confirmations = 0;
      }

      // Verify all expected parameters
      if (expectedFrom && result.from !== expectedFrom) {
        result.error = `Sender mismatch: expected ${expectedFrom}, got ${result.from}`;
        return result;
      }

      if (expectedTo && result.to !== expectedTo) {
        result.error = `Recipient mismatch: expected ${expectedTo}, got ${result.to}`;
        return result;
      }

      if (expectedAmount && BigInt(result.amount) !== BigInt(expectedAmount)) {
        result.error = `Amount mismatch: expected ${expectedAmount}, got ${result.amount}`;
        return result;
      }

      result.verified = true;

    } catch (error) {
      result.error = error.message;
    }

    return result;
  }

  /**
   * Get token info for a TRC-20 contract
   */
  async getTokenInfo(contract) {
    return this.request(`/v1/contracts/${contract}`);
  }

  /**
   * Check if an account has sufficient TRX for gas
   * Returns { hasGas: boolean, balance: BigInt, estimatedFee: BigInt }
   */
  async checkGasBalance(address, requiredEnergy = 65000) {
    try {
      const balance = await this.getTrxBalance(address);
      
      // Estimate fee: ~0.5 TRX for basic TRC-20 transfer (conservative)
      // 1 TRX = 1,000,000 sun
      const estimatedFeeSun = BigInt(500000); // 0.5 TRX
      
      return {
        hasGas: balance >= estimatedFeeSun,
        balance,
        estimatedFee: estimatedFeeSun,
        balanceInTrx: Number(balance) / 1000000
      };
    } catch (error) {
      return {
        hasGas: false,
        balance: BigInt(0),
        estimatedFee: BigInt(500000),
        balanceInTrx: 0,
        error: error.message
      };
    }
  }
}

// AIP Type Registry constants
export const TRON_AIP_TYPES = {
  RAIL: 'tron',
  TRC20: 'tron:trc20',
  NATIVE: 'tron:native'
};

// Named exports
export { TRC20_CONTRACTS };

// Export default
export default {
  publicKeyToTronAddress,
  validateTronAddress,
  tronAddressToHex,
  hexToTronAddress,
  TronGridClient,
  TronConfig,
  getTronConfig,
  resetTronConfig,
  TRC20_CONTRACTS,
  TRON_AIP_TYPES,
  MAINNET_USDT_CONTRACT
};
