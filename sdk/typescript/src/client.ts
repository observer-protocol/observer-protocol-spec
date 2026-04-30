/**
 * Observer Protocol SDK - Client
 *
 * Agent identity, delegation, x402 verification, and chargeback
 * prevention for the agentic economy.
 *
 * MIT Licensed. Browser and Node.js compatible (uses native fetch).
 *
 * @example
 * ```ts
 * import { ObserverClient } from '@observer-protocol/sdk';
 *
 * const client = new ObserverClient();
 * const agent = await client.registerAgent({ publicKey: 'ed25519_hex' });
 * const challenge = await client.requestChallenge(agent.agentId);
 * // sign challenge.nonce with your private key
 * await client.verifyAgent(agent.agentId, signatureHex);
 * ```
 */

import {
  ObserverClientOptions,
  ObserverError,
  RegisterAgentParams,
  RegisterAgentResult,
  Challenge,
  Agent,
  TrustScore,
  Attestation,
  DelegationRequest,
  DelegationRequestResult,
  Delegation,
  MagicLinkParams,
  MagicLinkResult,
  X402VerifyParams,
  X402VerifyResult,
  ChainVerifyParams,
  ChainVerifyResult,
  AuditEvent,
  AuditEventResult,
  ERC8004AgentSummary,
  RegistrationPinParams,
  RegistrationPinResult,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.observerprotocol.org';
const DEFAULT_TIMEOUT = 30000;

export class ObserverClient {
  private baseUrl: string;
  private apiKey: string | null;
  private timeout: number;

  constructor(options: ObserverClientOptions = {}) {
    this.baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.apiKey = options.apiKey || null;
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
  }

  // ── HTTP helpers ──────────────────────────────────────────

  private async request<T>(method: string, path: string, body?: unknown, params?: Record<string, string>): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!resp.ok) {
        let detail: string;
        try {
          const data = await resp.json();
          detail = typeof data.detail === 'string' ? data.detail :
                   Array.isArray(data.detail) ? data.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join(', ') :
                   JSON.stringify(data);
        } catch {
          detail = `HTTP ${resp.status}`;
        }
        throw new ObserverError(resp.status, detail);
      }

      if (resp.status === 204) return {} as T;
      return resp.json() as Promise<T>;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof ObserverError) throw err;
      if ((err as Error).name === 'AbortError') throw new ObserverError(408, 'Request timed out');
      throw err;
    }
  }

  private get<T>(path: string, params?: Record<string, string>): Promise<T> {
    return this.request('GET', path, undefined, params);
  }

  private post<T>(path: string, body?: unknown, params?: Record<string, string>): Promise<T> {
    return this.request('POST', path, body, params);
  }

  // ══════════════════════════════════════════════════════════
  // AGENT IDENTITY
  // ══════════════════════════════════════════════════════════

  /** Register a new agent with an Ed25519 public key. */
  async registerAgent(params: RegisterAgentParams): Promise<RegisterAgentResult> {
    const qp: Record<string, string> = { public_key: params.publicKey };
    if (params.agentName) qp.agent_name = params.agentName;
    if (params.alias) qp.alias = params.alias;
    if (params.framework) qp.framework = params.framework;

    const data = await this.post<Record<string, unknown>>('/observer/register-agent', null, qp);
    return {
      agentId: data.agent_id as string,
      agentDid: data.agent_did as string,
      agentName: data.agent_name as string,
      didDocument: data.did_document as Record<string, unknown>,
      verificationStatus: data.verification_status as string,
    };
  }

  /** Request a cryptographic challenge for key ownership verification. */
  async requestChallenge(agentId: string): Promise<Challenge> {
    const data = await this.post<Record<string, unknown>>('/observer/challenge', null, { agent_id: agentId });
    return {
      challengeId: data.challenge_id as string,
      nonce: data.nonce as string,
      expiresAt: data.expires_at as string,
    };
  }

  /** Submit a signed challenge to prove key ownership. */
  async verifyAgent(agentId: string, signedChallenge: string): Promise<{ verified: boolean }> {
    return this.post('/observer/verify-agent', null, {
      agent_id: agentId,
      signed_challenge: signedChallenge,
    });
  }

  /** Get an agent's public profile. */
  async getAgent(agentId: string): Promise<Agent> {
    const data = await this.get<Record<string, unknown>>(`/api/v1/agents/${agentId}/profile`);
    return {
      agentId: data.agent_id as string,
      agentDid: data.did as string,
      agentName: (data.agent_name || data.alias || null) as string | null,
      verified: data.verified as boolean,
      trustScore: (data.trust_score || null) as number | null,
      rails: (data.rails || null) as string[] | null,
      transactionCount: (data.transaction_count || 0) as number,
      attestationCount: (data.attestation_count || 0) as number,
    };
  }

  /** Get an agent's W3C DID document. */
  async getDIDDocument(agentId: string): Promise<Record<string, unknown>> {
    return this.get(`/agents/${agentId}/did.json`);
  }

  // ══════════════════════════════════════════════════════════
  // TRUST SCORE
  // ══════════════════════════════════════════════════════════

  /** Get an agent's AT-ARS trust score with component breakdown. */
  async getTrustScore(agentId: string): Promise<TrustScore> {
    const data = await this.get<Record<string, unknown>>(`/api/v1/trust/tron/score/${agentId}`);
    const c = data.components as Record<string, number> || {};
    return {
      agentId: data.agent_id as string,
      trustScore: data.trust_score as number,
      receiptCount: data.receipt_count as number,
      uniqueCounterparties: data.unique_counterparties as number,
      totalStablecoinVolume: data.total_stablecoin_volume as string,
      lastActivity: (data.last_activity || null) as string | null,
      components: {
        receiptScore: c.receipt_score || 0,
        counterpartyScore: c.counterparty_score || 0,
        orgScore: c.org_score || 0,
        recencyScore: c.recency_score || 0,
        volumeScore: c.volume_score || 0,
      },
    };
  }

  // ══════════════════════════════════════════════════════════
  // DELEGATION
  // ══════════════════════════════════════════════════════════

  /** Request a new delegation credential for an agent. */
  async requestDelegation(params: DelegationRequest): Promise<DelegationRequestResult> {
    const body: Record<string, unknown> = {
      agent_id: params.agentId,
      org_did: params.orgDid || 'did:web:observerprotocol.org',
      requested_by: params.requestedBy || 'sdk',
    };
    if (params.scope) body.scope = params.scope;
    if (params.rails) body.rails = params.rails;
    if (params.spendingLimits) {
      body.spending_limits = {
        per_transaction: params.spendingLimits.perTransaction,
        daily: params.spendingLimits.daily,
        currency: params.spendingLimits.currency || 'USD',
      };
    }
    if (params.expiration) body.expiration = params.expiration;
    if (params.attestationTier) body.attestation_tier = params.attestationTier;

    const data = await this.post<Record<string, unknown>>('/observer/request-delegation', body);
    return {
      requestId: data.request_id as string,
      status: data.status as string,
      agentDid: data.agent_did as string,
      orgDid: data.org_did as string,
    };
  }

  /** List delegation requests. */
  async listDelegations(): Promise<Delegation[]> {
    const data = await this.get<{ requests: Record<string, unknown>[] }>('/observer/delegation-requests');
    return (data.requests || []).map(r => ({
      requestId: r.request_id as string,
      agentId: r.agent_id as string,
      agentName: (r.agent_name || r.alias || null) as string | null,
      orgDid: r.org_did as string,
      requestedBy: r.requested_by as string,
      status: r.status as string,
      createdAt: r.created_at as string,
      expiry: (r.expiry || null) as string | null,
      spendingLimits: (r.spending_limits || null) as Record<string, string> | null,
      permissions: (r.permissions || null) as string[] | null,
      attestationTier: (r.attestation_tier || 'enterprise') as string,
    }));
  }

  /** Revoke a delegation. */
  async revokeDelegation(requestId: string, reason?: string): Promise<{ revoked: boolean }> {
    return this.post('/observer/revoke-delegation', {
      request_id: requestId,
      reason: reason || 'Revoked via SDK',
    });
  }

  // ══════════════════════════════════════════════════════════
  // MAGIC LINK (Chargeback Prevention Flow)
  // ══════════════════════════════════════════════════════════

  /** Generate a magic link for human-in-the-loop authorization. */
  async generateMagicLink(params: MagicLinkParams): Promise<MagicLinkResult> {
    const data = await this.post<Record<string, unknown>>('/api/v1/remediation/magic-link', {
      agent_id: params.agentId,
      counterparty_did: params.counterpartyDid,
      counterparty_name: params.counterpartyName,
      amount: params.amount,
      currency: params.currency,
      rail: params.rail,
      purchase_description: params.purchaseDescription,
      intro: params.intro,
      ttl_minutes: params.ttlMinutes,
    });
    return {
      token: data.token as string,
      url: data.url as string,
      slug: data.slug as string,
      intro: data.intro as string,
      transactionContext: data.transaction_context as MagicLinkResult['transactionContext'],
      expiresAt: data.expires_at as string,
      jti: data.jti as string,
    };
  }

  /** Check the status of a magic link credential retrieval. */
  async getMagicLinkCredential(jti: string): Promise<{ status: string; credential?: Record<string, unknown> }> {
    return this.get(`/api/v1/remediation/${jti}/credential`);
  }

  // ══════════════════════════════════════════════════════════
  // x402 VERIFICATION
  // ══════════════════════════════════════════════════════════

  /** Verify an x402 payment and issue an X402PaymentCredential. */
  async verifyX402(params: X402VerifyParams): Promise<X402VerifyResult> {
    const data = await this.post<Record<string, unknown>>('/api/v1/x402/verify', {
      agent_id: params.agentId,
      agent_did: params.agentDid,
      counterparty: params.counterparty,
      payment_scheme: params.paymentScheme || 'exact',
      network: params.network || 'eip155:8453',
      asset_address: params.assetAddress || '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      asset_symbol: params.assetSymbol || 'USDC',
      amount: params.amount,
      resource_uri: params.resourceUri,
      facilitator_url: params.facilitatorUrl || 'https://x402.coinbase.com',
      settlement_tx_hash: params.settlementTxHash,
      payment_payload: params.paymentPayload,
    });
    const v = data.verification as Record<string, unknown> || {};
    return {
      credential: data.credential as Record<string, unknown>,
      verification: {
        facilitatorVerified: v.facilitator_verified as boolean,
        onchainVerified: v.onchain_verified as boolean,
        discrepancy: v.discrepancy as boolean,
        onchainConfirmations: (v.onchain_confirmations || 0) as number,
      },
      eventId: data.event_id as string,
    };
  }

  /** List X402PaymentCredentials for an agent. */
  async getX402Credentials(agentId: string): Promise<{ credentials: Record<string, unknown>[]; count: number }> {
    return this.get(`/api/v1/x402/credentials/${agentId}`);
  }

  // ══════════════════════════════════════════════════════════
  // CHAIN VERIFICATION
  // ══════════════════════════════════════════════════════════

  /** Verify a transaction on any supported chain. Requires API key. */
  async verifyChain(params: ChainVerifyParams): Promise<ChainVerifyResult> {
    const data = await this.post<Record<string, unknown>>('/v1/chain/verify', {
      receipt_reference: params.receiptReference,
      chain: params.chain,
      chain_specific: params.chainSpecific,
      transaction: params.transaction,
    });
    return {
      verified: data.verified as boolean,
      chain: data.chain as string,
      receiptReference: data.receipt_reference as string,
      transactionReference: data.transaction_reference as string,
      explorerUrl: (data.explorer_url || null) as string | null,
      confirmedAt: data.confirmed_at as string,
      chainSpecific: data.chain_specific as Record<string, unknown>,
    };
  }

  /** Verify a Lightning payment. Convenience wrapper. */
  async verifyLightning(params: {
    receiptReference: string;
    paymentHash: string;
    preimage: string;
    presenterRole?: 'payer' | 'payee';
  }): Promise<ChainVerifyResult> {
    return this.verifyChain({
      receiptReference: params.receiptReference,
      chain: 'lightning',
      chainSpecific: {
        payment_hash: params.paymentHash,
        preimage: params.preimage,
        presenter_role: params.presenterRole || 'payee',
      },
    });
  }

  /** Verify a TRON TRC-20 transaction. Convenience wrapper. */
  async verifyTron(params: {
    receiptReference: string;
    tronTxHash: string;
    network?: 'mainnet' | 'shasta';
  }): Promise<ChainVerifyResult> {
    return this.verifyChain({
      receiptReference: params.receiptReference,
      chain: 'tron',
      chainSpecific: {
        tron_tx_hash: params.tronTxHash,
        network: params.network || 'mainnet',
      },
    });
  }

  // ══════════════════════════════════════════════════════════
  // ATTESTATIONS & VAC
  // ══════════════════════════════════════════════════════════

  /** Get an agent's Verified Agent Credential. */
  async getVAC(agentId: string): Promise<Record<string, unknown>> {
    return this.get(`/vac/${agentId}`);
  }

  /** Get attestations for an agent. */
  async getAttestations(agentId: string): Promise<Attestation[]> {
    const data = await this.get<{ attestations: Record<string, unknown>[] }>(`/vac/${agentId}/attestations`);
    return (data.attestations || []).map(a => ({
      attestationId: a.attestation_id as string,
      credentialId: (a.credential_id || null) as string | null,
      partnerId: a.partner_id as string,
      partnerName: a.partner_name as string,
      partnerType: a.partner_type as string,
      claims: a.claims as Record<string, unknown>,
      issuedAt: a.issued_at as string,
      attestationHash: a.attestation_hash as string,
    }));
  }

  // ══════════════════════════════════════════════════════════
  // AUDIT TRAIL
  // ══════════════════════════════════════════════════════════

  /** Write a verified event to the audit trail. Requires API key. */
  async writeAuditEvent(params: AuditEvent): Promise<AuditEventResult> {
    const body: Record<string, unknown> = {
      receipt_reference: params.receiptReference,
      agent: { agent_id: params.agentId, did: params.agentDid },
      transaction: {
        amount: { value: params.amount, currency: params.currency },
        category: params.category,
        rail: params.rail,
      },
    };
    if (params.settlementTxHash) {
      body.settlement_reference = { transaction_hash: params.settlementTxHash, rail: params.rail };
    }
    const data = await this.post<Record<string, unknown>>('/v1/audit/verified-event', body);
    return {
      eventId: data.event_id as string,
      receiptReference: data.receipt_reference as string,
      dashboardUrl: data.dashboard_url as string,
    };
  }

  /** Get an agent's activity history. */
  async getActivities(agentDid: string, options?: { limit?: number }): Promise<Record<string, unknown>[]> {
    const params: Record<string, string> = { limit: String(options?.limit || 50) };
    const data = await this.get<{ activities: Record<string, unknown>[] }>(
      `/audit/agent/${encodeURIComponent(agentDid)}/activities`, params
    );
    return data.activities || [];
  }

  // ══════════════════════════════════════════════════════════
  // ERC-8004 / TRC-8004 ON-CHAIN REGISTRY
  // ══════════════════════════════════════════════════════════

  /** Get an agent's 8004 on-chain presence summary. */
  async get8004Summary(agentId: string): Promise<ERC8004AgentSummary> {
    return this.get(`/api/v1/erc8004/agent/${agentId}/summary`);
  }

  /** Resolve an OP DID to any associated 8004 NFTs. */
  async resolve8004ByDid(did: string): Promise<{ did: string; nfts: Record<string, unknown>[]; count: number }> {
    return this.get(`/api/v1/erc8004/resolve/did/${encodeURIComponent(did)}`);
  }

  /** Resolve an 8004 NFT to its OP DID. */
  async resolve8004ByNft(chain: string, tokenId: string): Promise<Record<string, unknown>> {
    return this.get(`/api/v1/erc8004/resolve/nft/${chain}/${tokenId}`);
  }

  /** Pin an 8004 registration file for an agent. */
  async pinRegistration(params: RegistrationPinParams): Promise<RegistrationPinResult> {
    const data = await this.post<Record<string, unknown>>('/api/v1/erc8004/registration/pin', {
      agent_id: params.agentId,
      agent_did: params.agentDid,
      agent_name: params.agentName,
      description: params.description,
      image_url: params.imageUrl,
      a2a_endpoint: params.a2aEndpoint,
      mcp_endpoint: params.mcpEndpoint,
      web_endpoint: params.webEndpoint,
    });
    return {
      registrationFile: data.registration_file as Record<string, unknown>,
      contentHash: data.content_hash as string,
      servingUrl: data.serving_url as string,
      x402Credentials: data.x402_credentials as number,
    };
  }

  /** Get 8004 indexer status. */
  async get8004IndexerStatus(): Promise<Record<string, unknown>> {
    return this.get('/api/v1/erc8004/indexer/status');
  }
}
