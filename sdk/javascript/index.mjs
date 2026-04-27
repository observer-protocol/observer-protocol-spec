/**
 * Observer Protocol JavaScript/Node.js SDK
 *
 * Register agents, verify transactions, and manage attestations
 * on Observer Protocol.
 *
 * Usage:
 *   import { ObserverClient } from '@observer-protocol/sdk';
 *
 *   const client = new ObserverClient();
 *   const agent = await client.registerAgent({ publicKey: 'ed25519_hex' });
 *   const challenge = await client.requestChallenge(agent.agentId);
 *   // sign challenge.nonce with your private key
 *   await client.verifyAgent(agent.agentId, signatureHex);
 *   const vac = await client.getVAC(agent.agentId);
 */

const DEFAULT_BASE_URL = 'https://api.observerprotocol.org';

export class ObserverError extends Error {
  constructor(statusCode, detail) {
    super(`OP API Error ${statusCode}: ${detail}`);
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

export class ObserverClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.baseUrl] - API base URL (default: https://api.observerprotocol.org)
   * @param {string} [options.apiKey] - Integrator API key for authenticated endpoints
   * @param {number} [options.timeout] - Request timeout in ms (default: 30000)
   */
  constructor({ baseUrl, apiKey, timeout } = {}) {
    this.baseUrl = (baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.apiKey = apiKey || null;
    this.timeout = timeout || 30000;
  }

  // ── HTTP helpers ──────────────────────────────────────────

  async _get(path, params) {
    let url = `${this.baseUrl}${path}`;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url += `?${qs}`;
    }
    return this._request('GET', url);
  }

  async _post(path, body, params) {
    let url = `${this.baseUrl}${path}`;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url += `?${qs}`;
    }
    return this._request('POST', url, body);
  }

  async _request(method, url, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    options.signal = controller.signal;

    try {
      const resp = await fetch(url, options);
      clearTimeout(timeoutId);

      if (!resp.ok) {
        let detail;
        try {
          const data = await resp.json();
          detail = data.detail || data.error || JSON.stringify(data);
          if (typeof detail === 'object') detail = detail.detail || detail.error || JSON.stringify(detail);
        } catch {
          detail = `HTTP ${resp.status}`;
        }
        throw new ObserverError(resp.status, detail);
      }

      if (resp.status === 204) return {};
      return resp.json();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof ObserverError) throw err;
      if (err.name === 'AbortError') throw new ObserverError(408, 'Request timed out');
      throw err;
    }
  }

  // ── Agent Registration ────────────────────────────────────

  /**
   * Register a new agent on Observer Protocol.
   * @param {Object} params
   * @param {string} params.publicKey - Ed25519 public key (hex, 64 chars)
   * @param {string} [params.agentName] - Human-readable name
   * @param {string} [params.alias] - Short alias
   * @param {string} [params.framework] - Agent framework identifier
   * @returns {Promise<{agentId: string, agentDid: string, didDocument: Object}>}
   */
  async registerAgent({ publicKey, agentName, alias, framework }) {
    const params = { public_key: publicKey };
    if (agentName) params.agent_name = agentName;
    if (alias) params.alias = alias;
    if (framework) params.framework = framework;

    const data = await this._post('/observer/register-agent', null, params);
    return {
      agentId: data.agent_id,
      agentDid: data.agent_did,
      agentName: data.agent_name,
      didDocument: data.did_document,
      verificationStatus: data.verification_status,
    };
  }

  /**
   * Request a cryptographic challenge for key ownership verification.
   * @param {string} agentId
   * @returns {Promise<{challengeId: string, nonce: string, expiresAt: string}>}
   */
  async requestChallenge(agentId) {
    const data = await this._post('/observer/challenge', null, { agent_id: agentId });
    return {
      challengeId: data.challenge_id,
      nonce: data.nonce,
      expiresAt: data.expires_at,
    };
  }

  /**
   * Submit a signed challenge to prove key ownership.
   * @param {string} agentId
   * @param {string} signedChallenge - Hex-encoded Ed25519 signature
   * @returns {Promise<{verified: boolean, verificationMethod: string}>}
   */
  async verifyAgent(agentId, signedChallenge) {
    return this._post('/observer/verify-agent', null, {
      agent_id: agentId,
      signed_challenge: signedChallenge,
    });
  }

  // ── Agent Profile ─────────────────────────────────────────

  /**
   * Get an agent's public profile.
   * @param {string} agentId
   * @returns {Promise<Object>}
   */
  async getAgent(agentId) {
    const data = await this._get(`/api/v1/agents/${agentId}/profile`);
    return {
      agentId: data.agent_id,
      agentName: data.agent_name,
      did: data.did,
      verified: data.verified,
      trustScore: data.trust_score,
      rails: data.rails,
      transactionCount: data.transaction_count,
      attestationCount: data.attestation_count,
    };
  }

  /**
   * Get an agent's W3C DID document.
   * @param {string} agentId
   * @returns {Promise<Object>}
   */
  async getDIDDocument(agentId) {
    return this._get(`/agents/${agentId}/did.json`);
  }

  // ── VAC ───────────────────────────────────────────────────

  /**
   * Get an agent's Verified Agent Credential (W3C Verifiable Presentation).
   * @param {string} agentId
   * @returns {Promise<Object>}
   */
  async getVAC(agentId) {
    return this._get(`/vac/${agentId}`);
  }

  // ── Trust Score ───────────────────────────────────────────

  /**
   * Get an agent's AT-ARS trust score with component breakdown.
   * @param {string} agentId
   * @returns {Promise<{agentId: string, trustScore: number, components: Object}>}
   */
  async getTrustScore(agentId) {
    const data = await this._get(`/api/v1/trust/tron/score/${agentId}`);
    return {
      agentId: data.agent_id,
      trustScore: data.trust_score,
      receiptCount: data.receipt_count,
      uniqueCounterparties: data.unique_counterparties,
      totalStablecoinVolume: data.total_stablecoin_volume,
      lastActivity: data.last_activity,
      components: data.components,
    };
  }

  // ── Attestations ──────────────────────────────────────────

  /**
   * Get all attestations for an agent.
   * @param {string} agentId
   * @param {string} [partnerType] - Filter: corpo, verifier, counterparty, infrastructure
   * @returns {Promise<Array>}
   */
  async getAttestations(agentId, partnerType) {
    const params = {};
    if (partnerType) params.partner_type = partnerType;
    const data = await this._get(`/vac/${agentId}/attestations`, params);
    return data.attestations || [];
  }

  // ── Chain Verification ────────────────────────────────────

  /**
   * Verify a transaction on any supported chain. Requires API key.
   * @param {Object} params
   * @param {string} params.receiptReference - Unique ID (idempotency key)
   * @param {string} params.chain - "lightning", "tron", or "stacks"
   * @param {Object} params.chainSpecific - Chain-specific verification params
   * @param {Object} [params.transaction] - Optional transaction details
   * @returns {Promise<{verified: boolean, chain: string, transactionReference: string, explorerUrl: string, chainSpecific: Object}>}
   */
  async verifyChain({ receiptReference, chain, chainSpecific, transaction }) {
    const body = {
      receipt_reference: receiptReference,
      chain,
      chain_specific: chainSpecific,
    };
    if (transaction) body.transaction = transaction;

    const data = await this._post('/v1/chain/verify', body);
    return {
      verified: data.verified,
      chain: data.chain,
      receiptReference: data.receipt_reference,
      transactionReference: data.transaction_reference,
      explorerUrl: data.explorer_url,
      confirmedAt: data.confirmed_at,
      chainSpecific: data.chain_specific,
      idempotentReplay: data.idempotent_replay,
    };
  }

  /**
   * Verify a Lightning payment. Convenience wrapper. Requires API key.
   * @param {Object} params
   * @param {string} params.receiptReference - Unique ID
   * @param {string} params.paymentHash - Lightning payment hash (hex)
   * @param {string} params.preimage - Lightning preimage (hex)
   * @param {string} [params.presenterRole='payee'] - "payer" or "payee"
   * @param {Object} [params.payeeAttestation] - Signed LightningPaymentReceipt VC (for Tier 1)
   * @returns {Promise<Object>}
   */
  async verifyLightningPayment({ receiptReference, paymentHash, preimage, presenterRole = 'payee', payeeAttestation }) {
    const chainSpecific = {
      payment_hash: paymentHash,
      preimage,
      presenter_role: presenterRole,
    };
    if (payeeAttestation) chainSpecific.payee_attestation = payeeAttestation;

    return this.verifyChain({ receiptReference, chain: 'lightning', chainSpecific });
  }

  /**
   * Verify a TRON TRC-20 transaction. Convenience wrapper. Requires API key.
   * @param {Object} params
   * @param {string} params.receiptReference - Unique ID
   * @param {string} params.tronTxHash - TRON transaction hash (hex)
   * @param {string} [params.network='mainnet'] - "mainnet" or "shasta"
   * @returns {Promise<Object>}
   */
  async verifyTronTransaction({ receiptReference, tronTxHash, network = 'mainnet' }) {
    return this.verifyChain({
      receiptReference,
      chain: 'tron',
      chainSpecific: { tron_tx_hash: tronTxHash, network },
    });
  }

  // ── Audit Trail ───────────────────────────────────────────

  /**
   * Get an agent's verified activity history.
   * @param {string} agentDid - The agent's DID
   * @param {Object} [options]
   * @param {number} [options.limit=50]
   * @param {string} [options.since] - ISO timestamp filter
   * @returns {Promise<Array>}
   */
  async getActivities(agentDid, { limit = 50, since } = {}) {
    const params = { limit };
    if (since) params.since = since;
    const data = await this._get(`/audit/agent/${encodeURIComponent(agentDid)}/activities`, params);
    return data.activities || [];
  }

  /**
   * Write a verified event to the audit trail. Requires API key.
   * @param {Object} params
   * @param {string} params.receiptReference - Receipt UUID (idempotency key)
   * @param {string} params.agentId
   * @param {string} params.amount
   * @param {string} params.currency
   * @param {string} params.category
   * @param {Object} [params.options] - Optional: agentDid, rail, settlementTxHash
   * @returns {Promise<{eventId: string, dashboardUrl: string}>}
   */
  async writeAuditEvent({ receiptReference, agentId, amount, currency, category, agentDid, rail, settlementTxHash }) {
    const body = {
      receipt_reference: receiptReference,
      agent: { agent_id: agentId },
      transaction: {
        amount: { value: amount, currency },
        category,
      },
    };
    if (agentDid) body.agent.did = agentDid;
    if (rail) body.transaction.rail = rail;
    if (settlementTxHash) body.settlement_reference = { transaction_hash: settlementTxHash, rail };

    const data = await this._post('/v1/audit/verified-event', body);
    return {
      eventId: data.event_id,
      receiptReference: data.receipt_reference,
      dashboardUrl: data.dashboard_url,
      idempotentReplay: data.idempotent_replay,
    };
  }

  // ── VAC Extensions ────────────────────────────────────────

  /**
   * Register a VAC extension schema. Requires API key.
   * @param {Object} params
   * @param {string} params.extensionId - e.g. "myplatform_reputation_v1"
   * @param {string} params.displayName
   * @param {string} params.issuerDid - Your DID
   * @param {Object} params.schema - JSON Schema
   * @param {Object} [params.options] - Optional: issuerDisplayName, issuerDomain, summaryFields
   * @returns {Promise<{extensionId: string, namespace: string, schemaUrl: string}>}
   */
  async registerExtension({ extensionId, displayName, issuerDid, schema, issuerDisplayName, issuerDomain, summaryFields }) {
    const body = {
      extension_id: extensionId,
      display_name: displayName,
      issuer: { did: issuerDid },
      schema,
    };
    if (issuerDisplayName) body.issuer.display_name = issuerDisplayName;
    if (issuerDomain) body.issuer.domain = issuerDomain;
    if (summaryFields) body.summary_fields = summaryFields;

    return this._post('/v1/vac/extensions/register', body);
  }

  /**
   * Submit a pre-signed extension attestation credential. Requires API key.
   * @param {Object} params
   * @param {string} params.extensionId
   * @param {Object} params.credential - Pre-signed W3C VC
   * @param {string[]} [params.summaryFields]
   * @returns {Promise<Object>}
   */
  async submitExtensionAttestation({ extensionId, credential, summaryFields }) {
    const body = {
      extension_id: extensionId,
      credential,
    };
    if (summaryFields) body.summary_fields = summaryFields;

    return this._post('/v1/vac/extensions/attest', body);
  }

  // ── Counterparties ────────────────────────────────────────

  /**
   * Get an agent's counterparty summary.
   * @param {string} agentId
   * @param {number} [limit=50]
   * @returns {Promise<Object>}
   */
  async getCounterparties(agentId, limit = 50) {
    return this._get(`/api/v1/agents/${agentId}/counterparties`, { limit });
  }
}

export default ObserverClient;
