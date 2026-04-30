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
import { ObserverError, } from './types.js';
const DEFAULT_BASE_URL = 'https://api.observerprotocol.org';
const DEFAULT_TIMEOUT = 30000;
export class ObserverClient {
    baseUrl;
    apiKey;
    timeout;
    constructor(options = {}) {
        this.baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
        this.apiKey = options.apiKey || null;
        this.timeout = options.timeout || DEFAULT_TIMEOUT;
    }
    // ── HTTP helpers ──────────────────────────────────────────
    async request(method, path, body, params) {
        let url = `${this.baseUrl}${path}`;
        if (params) {
            const qs = new URLSearchParams(params).toString();
            if (qs)
                url += `?${qs}`;
        }
        const headers = { 'Content-Type': 'application/json' };
        if (this.apiKey)
            headers['Authorization'] = `Bearer ${this.apiKey}`;
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
                let detail;
                try {
                    const data = await resp.json();
                    detail = typeof data.detail === 'string' ? data.detail :
                        Array.isArray(data.detail) ? data.detail.map((d) => d.msg || JSON.stringify(d)).join(', ') :
                            JSON.stringify(data);
                }
                catch {
                    detail = `HTTP ${resp.status}`;
                }
                throw new ObserverError(resp.status, detail);
            }
            if (resp.status === 204)
                return {};
            return resp.json();
        }
        catch (err) {
            clearTimeout(timeoutId);
            if (err instanceof ObserverError)
                throw err;
            if (err.name === 'AbortError')
                throw new ObserverError(408, 'Request timed out');
            throw err;
        }
    }
    get(path, params) {
        return this.request('GET', path, undefined, params);
    }
    post(path, body, params) {
        return this.request('POST', path, body, params);
    }
    // ══════════════════════════════════════════════════════════
    // AGENT IDENTITY
    // ══════════════════════════════════════════════════════════
    /** Register a new agent with an Ed25519 public key. */
    async registerAgent(params) {
        const qp = { public_key: params.publicKey };
        if (params.agentName)
            qp.agent_name = params.agentName;
        if (params.alias)
            qp.alias = params.alias;
        if (params.framework)
            qp.framework = params.framework;
        const data = await this.post('/observer/register-agent', null, qp);
        return {
            agentId: data.agent_id,
            agentDid: data.agent_did,
            agentName: data.agent_name,
            didDocument: data.did_document,
            verificationStatus: data.verification_status,
        };
    }
    /** Request a cryptographic challenge for key ownership verification. */
    async requestChallenge(agentId) {
        const data = await this.post('/observer/challenge', null, { agent_id: agentId });
        return {
            challengeId: data.challenge_id,
            nonce: data.nonce,
            expiresAt: data.expires_at,
        };
    }
    /** Submit a signed challenge to prove key ownership. */
    async verifyAgent(agentId, signedChallenge) {
        return this.post('/observer/verify-agent', null, {
            agent_id: agentId,
            signed_challenge: signedChallenge,
        });
    }
    /** Get an agent's public profile. */
    async getAgent(agentId) {
        const data = await this.get(`/api/v1/agents/${agentId}/profile`);
        return {
            agentId: data.agent_id,
            agentDid: data.did,
            agentName: (data.agent_name || data.alias || null),
            verified: data.verified,
            trustScore: (data.trust_score || null),
            rails: (data.rails || null),
            transactionCount: (data.transaction_count || 0),
            attestationCount: (data.attestation_count || 0),
        };
    }
    /** Get an agent's W3C DID document. */
    async getDIDDocument(agentId) {
        return this.get(`/agents/${agentId}/did.json`);
    }
    // ══════════════════════════════════════════════════════════
    // TRUST SCORE
    // ══════════════════════════════════════════════════════════
    /** Get an agent's AT-ARS trust score with component breakdown. */
    async getTrustScore(agentId) {
        const data = await this.get(`/api/v1/trust/tron/score/${agentId}`);
        const c = data.components || {};
        return {
            agentId: data.agent_id,
            trustScore: data.trust_score,
            receiptCount: data.receipt_count,
            uniqueCounterparties: data.unique_counterparties,
            totalStablecoinVolume: data.total_stablecoin_volume,
            lastActivity: (data.last_activity || null),
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
    async requestDelegation(params) {
        const body = {
            agent_id: params.agentId,
            org_did: params.orgDid || 'did:web:observerprotocol.org',
            requested_by: params.requestedBy || 'sdk',
        };
        if (params.scope)
            body.scope = params.scope;
        if (params.rails)
            body.rails = params.rails;
        if (params.spendingLimits) {
            body.spending_limits = {
                per_transaction: params.spendingLimits.perTransaction,
                daily: params.spendingLimits.daily,
                currency: params.spendingLimits.currency || 'USD',
            };
        }
        if (params.expiration)
            body.expiration = params.expiration;
        if (params.attestationTier)
            body.attestation_tier = params.attestationTier;
        const data = await this.post('/observer/request-delegation', body);
        return {
            requestId: data.request_id,
            status: data.status,
            agentDid: data.agent_did,
            orgDid: data.org_did,
        };
    }
    /** List delegation requests. */
    async listDelegations() {
        const data = await this.get('/observer/delegation-requests');
        return (data.requests || []).map(r => ({
            requestId: r.request_id,
            agentId: r.agent_id,
            agentName: (r.agent_name || r.alias || null),
            orgDid: r.org_did,
            requestedBy: r.requested_by,
            status: r.status,
            createdAt: r.created_at,
            expiry: (r.expiry || null),
            spendingLimits: (r.spending_limits || null),
            permissions: (r.permissions || null),
            attestationTier: (r.attestation_tier || 'enterprise'),
        }));
    }
    /** Revoke a delegation. */
    async revokeDelegation(requestId, reason) {
        return this.post('/observer/revoke-delegation', {
            request_id: requestId,
            reason: reason || 'Revoked via SDK',
        });
    }
    // ══════════════════════════════════════════════════════════
    // MAGIC LINK (Chargeback Prevention Flow)
    // ══════════════════════════════════════════════════════════
    /** Generate a magic link for human-in-the-loop authorization. */
    async generateMagicLink(params) {
        const data = await this.post('/api/v1/remediation/magic-link', {
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
            token: data.token,
            url: data.url,
            slug: data.slug,
            intro: data.intro,
            transactionContext: data.transaction_context,
            expiresAt: data.expires_at,
            jti: data.jti,
        };
    }
    /** Check the status of a magic link credential retrieval. */
    async getMagicLinkCredential(jti) {
        return this.get(`/api/v1/remediation/${jti}/credential`);
    }
    // ══════════════════════════════════════════════════════════
    // x402 VERIFICATION
    // ══════════════════════════════════════════════════════════
    /** Verify an x402 payment and issue an X402PaymentCredential. */
    async verifyX402(params) {
        const data = await this.post('/api/v1/x402/verify', {
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
        const v = data.verification || {};
        return {
            credential: data.credential,
            verification: {
                facilitatorVerified: v.facilitator_verified,
                onchainVerified: v.onchain_verified,
                discrepancy: v.discrepancy,
                onchainConfirmations: (v.onchain_confirmations || 0),
            },
            eventId: data.event_id,
        };
    }
    /** List X402PaymentCredentials for an agent. */
    async getX402Credentials(agentId) {
        return this.get(`/api/v1/x402/credentials/${agentId}`);
    }
    // ══════════════════════════════════════════════════════════
    // CHAIN VERIFICATION
    // ══════════════════════════════════════════════════════════
    /** Verify a transaction on any supported chain. Requires API key. */
    async verifyChain(params) {
        const data = await this.post('/v1/chain/verify', {
            receipt_reference: params.receiptReference,
            chain: params.chain,
            chain_specific: params.chainSpecific,
            transaction: params.transaction,
        });
        return {
            verified: data.verified,
            chain: data.chain,
            receiptReference: data.receipt_reference,
            transactionReference: data.transaction_reference,
            explorerUrl: (data.explorer_url || null),
            confirmedAt: data.confirmed_at,
            chainSpecific: data.chain_specific,
        };
    }
    /** Verify a Lightning payment. Convenience wrapper. */
    async verifyLightning(params) {
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
    async verifyTron(params) {
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
    async getVAC(agentId) {
        return this.get(`/vac/${agentId}`);
    }
    /** Get attestations for an agent. */
    async getAttestations(agentId) {
        const data = await this.get(`/vac/${agentId}/attestations`);
        return (data.attestations || []).map(a => ({
            attestationId: a.attestation_id,
            credentialId: (a.credential_id || null),
            partnerId: a.partner_id,
            partnerName: a.partner_name,
            partnerType: a.partner_type,
            claims: a.claims,
            issuedAt: a.issued_at,
            attestationHash: a.attestation_hash,
        }));
    }
    // ══════════════════════════════════════════════════════════
    // AUDIT TRAIL
    // ══════════════════════════════════════════════════════════
    /** Write a verified event to the audit trail. Requires API key. */
    async writeAuditEvent(params) {
        const body = {
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
        const data = await this.post('/v1/audit/verified-event', body);
        return {
            eventId: data.event_id,
            receiptReference: data.receipt_reference,
            dashboardUrl: data.dashboard_url,
        };
    }
    /** Get an agent's activity history. */
    async getActivities(agentDid, options) {
        const params = { limit: String(options?.limit || 50) };
        const data = await this.get(`/audit/agent/${encodeURIComponent(agentDid)}/activities`, params);
        return data.activities || [];
    }
    // ══════════════════════════════════════════════════════════
    // ERC-8004 / TRC-8004 ON-CHAIN REGISTRY
    // ══════════════════════════════════════════════════════════
    /** Get an agent's 8004 on-chain presence summary. */
    async get8004Summary(agentId) {
        return this.get(`/api/v1/erc8004/agent/${agentId}/summary`);
    }
    /** Resolve an OP DID to any associated 8004 NFTs. */
    async resolve8004ByDid(did) {
        return this.get(`/api/v1/erc8004/resolve/did/${encodeURIComponent(did)}`);
    }
    /** Resolve an 8004 NFT to its OP DID. */
    async resolve8004ByNft(chain, tokenId) {
        return this.get(`/api/v1/erc8004/resolve/nft/${chain}/${tokenId}`);
    }
    /** Pin an 8004 registration file for an agent. */
    async pinRegistration(params) {
        const data = await this.post('/api/v1/erc8004/registration/pin', {
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
            registrationFile: data.registration_file,
            contentHash: data.content_hash,
            servingUrl: data.serving_url,
            x402Credentials: data.x402_credentials,
        };
    }
    /** Get 8004 indexer status. */
    async get8004IndexerStatus() {
        return this.get('/api/v1/erc8004/indexer/status');
    }
}
//# sourceMappingURL=client.js.map