/**
 * Observer Protocol Client SDK
 * JavaScript/Node.js client for agent registration and payment attestation
 *
 * OWS (Open Wallet Standard) Support Added:
 * - Multi-chain key derivation
 * - OWS badge on registration
 * - Portable reputation across chains
 */

import { createHash, sign } from 'crypto';

/**
 * OWS Derivation Paths (BIP-44)
 * @readonly
 */
export const OWS_DERIVATION_PATHS = {
  /** Ethereum and EVM-compatible chains */
  EVM: "m/44'/60'/0'/0/0",
  /** Solana (Ed25519) */
  SOLANA: "m/44'/501'/0'/0'",
  /** Bitcoin (Native SegWit) */
  BITCOIN: "m/84'/0'/0'/0/0"
};

/**
 * OWS Chain Identifiers
 * @readonly
 */
export const OWS_CHAINS = {
  EVM: 'evm',
  SOLANA: 'solana',
  BITCOIN: 'bitcoin'
};

/**
 * Agent registration options
 * @typedef {Object} AgentRegistrationOptions
 * @property {string} [solanaAddress] - Solana wallet address
 * @property {string} [walletStandard] - Wallet standard: 'ows' or null
 * @property {string} [owsVaultName] - OWS vault identifier
 * @property {string[]} [chains] - Supported chains: ['evm', 'solana', 'bitcoin']
 * @property {string} [alias] - Human-readable agent name
 */

/**
 * Observer Protocol Client
 *
 * Usage:
 * const client = new ObserverClient({
 *   baseUrl: 'http://localhost:8000',
 *   agentId: 'my-agent',
 *   privateKey: 'base58-encoded-private-key'
 * });
 *
 * // Standard registration
 * await client.registerWithSolana({ solanaAddress: 'HN7cAB...' });
 *
 * // OWS registration
 * await client.register({
 *   solanaAddress: 'HN7cAB...',
 *   walletStandard: 'ows',
 *   owsVaultName: 'agent-treasury',
 *   chains: ['evm', 'solana', 'bitcoin'],
 *   alias: 'My OWS Agent'
 * });
 *
 * await client.attestSolanaPayment({ txSignature, senderAddress, recipientAddress, amountLamports });
 */
class ObserverClient {
  /**
   * @param {Object} config
   * @param {string} config.baseUrl - API base URL
   * @param {string} config.agentId - Unique agent identifier
   * @param {string} config.privateKey - Ed25519 private key (base58)
   * @param {string} config.publicKey - Ed25519 public key (base58)
   */
  constructor({ baseUrl, agentId, privateKey, publicKey }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.agentId = agentId;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Sign a message with the agent's Ed25519 private key
   * @param {string} message - Message to sign
   * @returns {string} base58-encoded signature
   */
  signMessage(message) {
    // This is a placeholder - implement with actual Ed25519 signing
    // Using tweetnacl or similar library
    throw new Error('signMessage not implemented. Use nacl.sign.detached with tweetnacl library.');
  }

  /**
   * Make authenticated API request
   * @private
   */
  async request(method, endpoint, body = null) {
    const url = `${this.baseUrl}${endpoint}`;
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(`API Error ${response.status}: ${error.detail || error.message}`);
    }

    return response.json();
  }

  /**
   * Register agent with Solana address (legacy method)
   * @param {Object} params
   * @param {string} params.solanaAddress - Solana wallet address
   * @returns {Promise<Object>} Agent registration info
   */
  async registerWithSolana({ solanaAddress }) {
    return this.request('POST', '/observer/register', {
      agent_id: this.agentId,
      public_key: this.publicKey,
      solana_address: solanaAddress
    });
  }

  /**
   * Register agent with full options (including OWS support)
   * @param {AgentRegistrationOptions} params - Registration options
   * @returns {Promise<Object>} Agent registration info with OWS badge
   */
  async register({
    solanaAddress,
    walletStandard,
    owsVaultName,
    chains,
    alias
  }) {
    const payload = {
      agent_id: this.agentId,
      public_key: this.publicKey,
      solana_address: solanaAddress
    };

    // Add OWS fields if provided
    if (walletStandard) {
      payload.wallet_standard = walletStandard;
    }
    if (owsVaultName) {
      payload.ows_vault_name = owsVaultName;
    }
    if (chains && Array.isArray(chains)) {
      payload.chains = chains;
    }
    if (alias) {
      payload.alias = alias;
    }

    return this.request('POST', '/observer/register', payload);
  }

  /**
   * Register as an OWS agent (convenience method)
   * @param {Object} params
   * @param {string} params.solanaAddress - Solana wallet address
   * @param {string} params.vaultName - OWS vault name
   * @param {string[]} [params.chains=['evm', 'solana', 'bitcoin']] - Supported chains
   * @param {string} [params.alias] - Human-readable name
   * @returns {Promise<Object>} Agent registration info with OWS badge
   *
   * @example
   * await client.registerOWS({
   *   solanaAddress: 'HN7cAB...',
   *   vaultName: 'agent-treasury',
   *   chains: ['evm', 'solana', 'bitcoin'],
   *   alias: 'My Agent'
   * });
   */
  async registerOWS({
    solanaAddress,
    vaultName,
    chains = ['evm', 'solana', 'bitcoin'],
    alias
  }) {
    return this.register({
      solanaAddress,
      walletStandard: 'ows',
      owsVaultName: vaultName,
      chains,
      alias: alias || this.agentId
    });
  }

  /**
   * Get Verifiable Agent Credential (VAC)
   * @returns {Promise<Object>} VAC with OWS badge and reputation
   */
  async getVAC() {
    return this.request('GET', `/vac/${this.agentId}`);
  }

  /**
   * Check if this agent has OWS badge
   * @returns {Promise<boolean>}
   */
  async hasOWSBadge() {
    const vac = await this.getVAC();
    return vac.ows_badge === true;
  }

  /**
   * Get supported chains for this agent
   * @returns {Promise<string[]>}
   */
  async getChains() {
    const vac = await this.getVAC();
    return vac.chains || [];
  }

  /**
   * Attest a Solana payment transaction
   * @param {Object} params
   * @param {string} params.txSignature - Transaction signature
   * @param {string} params.senderAddress - Sender wallet address
   * @param {string} params.recipientAddress - Recipient wallet address
   * @param {number} params.amountLamports - Amount in lamports (SOL) or token units
   * @param {string} params.mint - Token mint address or 'SOL' (default: 'SOL')
   * @returns {Promise<Object>} Attestation receipt
   */
  async attestSolanaPayment({
    txSignature,
    senderAddress,
    recipientAddress,
    amountLamports,
    mint = 'SOL'
  }) {
    // Create canonical payload
    const payload = `${txSignature}:${senderAddress}:${recipientAddress}:${amountLamports}:${mint}`;

    // Sign payload (requires actual Ed25519 implementation)
    // const signature = this.signMessage(payload);

    // For now, require signature to be provided
    throw new Error(
      'attestSolanaPayment requires Ed25519 signing. ' +
      'Sign the payload: `${txSignature}:${senderAddress}:${recipientAddress}:${amountLamports}:${mint}` ' +
      'and call with signature parameter.'
    );
  }

  /**
   * Attest a Solana payment with pre-computed signature
   * @param {Object} params
   * @param {string} params.txSignature - Transaction signature
   * @param {string} params.senderAddress - Sender wallet address
   * @param {string} params.recipientAddress - Recipient wallet address
   * @param {number} params.amountLamports - Amount in lamports (SOL) or token units
   * @param {string} params.mint - Token mint address or 'SOL' (default: 'SOL')
   * @param {string} params.signature - Ed25519 signature over canonical payload (base58)
   * @returns {Promise<Object>} Attestation receipt
   */
  async attestSolanaPaymentWithSignature({
    txSignature,
    senderAddress,
    recipientAddress,
    amountLamports,
    mint = 'SOL',
    signature
  }) {
    return this.request('POST', '/observer/solana-attest', {
      tx_signature: txSignature,
      sender_address: senderAddress,
      recipient_address: recipientAddress,
      amount_lamports: amountLamports,
      mint: mint,
      agent_id: this.agentId,
      signature: signature
    });
  }

  /**
   * Get agent information
   * @returns {Promise<Object>} Agent info including reputation score
   */
  async getAgentInfo() {
    return this.request('GET', `/observer/agent/${this.agentId}`);
  }

  /**
   * Get attestations for this agent
   * @param {number} limit - Maximum number of attestations to return
   * @returns {Promise<Object>} List of attestations
   */
  async getAttestations(limit = 100) {
    return this.request('GET', `/observer/attestations/${this.agentId}?limit=${limit}`);
  }

  /**
   * Get canonical payload for signing
   * @param {Object} params
   * @param {string} params.txSignature - Transaction signature
   * @param {string} params.senderAddress - Sender wallet address
   * @param {string} params.recipientAddress - Recipient wallet address
   * @param {number} params.amountLamports - Amount in lamports or token units
   * @param {string} params.mint - Token mint address or 'SOL'
   * @returns {string} Canonical payload string
   */
  static getCanonicalPayload({
    txSignature,
    senderAddress,
    recipientAddress,
    amountLamports,
    mint = 'SOL'
  }) {
    return `${txSignature}:${senderAddress}:${recipientAddress}:${amountLamports}:${mint}`;
  }

  /**
   * Derive key from OWS vault (placeholder - requires @openwallet/sdk)
   * @param {Object} params
   * @param {string} params.vaultName - OWS vault name
   * @param {string} params.path - Derivation path
   * @returns {Promise<Object>} Derived key
   * @static
   */
  static async deriveFromOWS({ vaultName, path }) {
    throw new Error(
      'deriveFromOWS requires @openwallet/sdk. ' +
      'Install: npm install @openwallet/sdk\n' +
      'Usage: const wallet = await OWSWallet.load(vaultName);\n' +
      '       const key = await wallet.derivePath(path);'
    );
  }
}

/**
 * Create canonical payload for Solana attestation
 * @param {Object} params
 * @param {string} params.txSignature - Transaction signature
 * @param {string} params.senderAddress - Sender wallet address
 * @param {string} params.recipientAddress - Recipient wallet address
 * @param {number} params.amountLamports - Amount in lamports (SOL) or token units
 * @param {string} params.mint - Token mint address or 'SOL'
 * @returns {string} Canonical payload string
 */
export function createCanonicalPayload({
  txSignature,
  senderAddress,
  recipientAddress,
  amountLamports,
  mint = 'SOL'
}) {
  return `${txSignature}:${senderAddress}:${recipientAddress}:${amountLamports}:${mint}`;
}

/**
 * Example OWS Usage:
 *
 * ```javascript
 * import nacl from 'tweetnacl';
 * import bs58 from 'bs58';
 * import ObserverClient, { OWS_DERIVATION_PATHS } from '@observerprotocol/sdk';
 *
 * // Load OWS wallet (requires @openwallet/sdk)
 * import { OWSWallet } from '@openwallet/sdk';
 * const wallet = await OWSWallet.load('agent-treasury');
 *
 * // Derive Solana key using OWS path
 * const solanaKey = await wallet.derivePath(OWS_DERIVATION_PATHS.SOLANA);
 *
 * // Create OP client with OWS-derived keys
 * const client = new ObserverClient({
 *   baseUrl: 'https://api.observerprotocol.org',
 *   agentId: 'my-ows-agent',
 *   publicKey: solanaKey.publicKey,
 *   privateKey: solanaKey.privateKey
 * });
 *
 * // Register as OWS agent
 * const agent = await client.registerOWS({
 *   solanaAddress: solanaKey.address,
 *   vaultName: 'agent-treasury',
 *   chains: ['evm', 'solana', 'bitcoin'],
 *   alias: 'My Multi-Chain Agent'
 * });
 *
 * console.log('OWS Badge:', agent.ows_badge); // true
 * console.log('VAC URL:', `/vac/${agent.agent_id}`);
 *
 * // Get VAC for verification
 * const vac = await client.getVAC();
 * console.log('Reputation:', vac.reputation_score);
 * console.log('Verified TXs:', vac.verified_tx_count);
 * ```
 */

export default ObserverClient;
