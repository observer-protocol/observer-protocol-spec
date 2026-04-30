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
import { ObserverClientOptions, RegisterAgentParams, RegisterAgentResult, Challenge, Agent, TrustScore, Attestation, DelegationRequest, DelegationRequestResult, Delegation, MagicLinkParams, MagicLinkResult, X402VerifyParams, X402VerifyResult, ChainVerifyParams, ChainVerifyResult, AuditEvent, AuditEventResult, ERC8004AgentSummary, RegistrationPinParams, RegistrationPinResult } from './types.js';
export declare class ObserverClient {
    private baseUrl;
    private apiKey;
    private timeout;
    constructor(options?: ObserverClientOptions);
    private request;
    private get;
    private post;
    /** Register a new agent with an Ed25519 public key. */
    registerAgent(params: RegisterAgentParams): Promise<RegisterAgentResult>;
    /** Request a cryptographic challenge for key ownership verification. */
    requestChallenge(agentId: string): Promise<Challenge>;
    /** Submit a signed challenge to prove key ownership. */
    verifyAgent(agentId: string, signedChallenge: string): Promise<{
        verified: boolean;
    }>;
    /** Get an agent's public profile. */
    getAgent(agentId: string): Promise<Agent>;
    /** Get an agent's W3C DID document. */
    getDIDDocument(agentId: string): Promise<Record<string, unknown>>;
    /** Get an agent's AT-ARS trust score with component breakdown. */
    getTrustScore(agentId: string): Promise<TrustScore>;
    /** Request a new delegation credential for an agent. */
    requestDelegation(params: DelegationRequest): Promise<DelegationRequestResult>;
    /** List delegation requests. */
    listDelegations(): Promise<Delegation[]>;
    /** Revoke a delegation. */
    revokeDelegation(requestId: string, reason?: string): Promise<{
        revoked: boolean;
    }>;
    /** Generate a magic link for human-in-the-loop authorization. */
    generateMagicLink(params: MagicLinkParams): Promise<MagicLinkResult>;
    /** Check the status of a magic link credential retrieval. */
    getMagicLinkCredential(jti: string): Promise<{
        status: string;
        credential?: Record<string, unknown>;
    }>;
    /** Verify an x402 payment and issue an X402PaymentCredential. */
    verifyX402(params: X402VerifyParams): Promise<X402VerifyResult>;
    /** List X402PaymentCredentials for an agent. */
    getX402Credentials(agentId: string): Promise<{
        credentials: Record<string, unknown>[];
        count: number;
    }>;
    /** Verify a transaction on any supported chain. Requires API key. */
    verifyChain(params: ChainVerifyParams): Promise<ChainVerifyResult>;
    /** Verify a Lightning payment. Convenience wrapper. */
    verifyLightning(params: {
        receiptReference: string;
        paymentHash: string;
        preimage: string;
        presenterRole?: 'payer' | 'payee';
    }): Promise<ChainVerifyResult>;
    /** Verify a TRON TRC-20 transaction. Convenience wrapper. */
    verifyTron(params: {
        receiptReference: string;
        tronTxHash: string;
        network?: 'mainnet' | 'shasta';
    }): Promise<ChainVerifyResult>;
    /** Get an agent's Verified Agent Credential. */
    getVAC(agentId: string): Promise<Record<string, unknown>>;
    /** Get attestations for an agent. */
    getAttestations(agentId: string): Promise<Attestation[]>;
    /** Write a verified event to the audit trail. Requires API key. */
    writeAuditEvent(params: AuditEvent): Promise<AuditEventResult>;
    /** Get an agent's activity history. */
    getActivities(agentDid: string, options?: {
        limit?: number;
    }): Promise<Record<string, unknown>[]>;
    /** Get an agent's 8004 on-chain presence summary. */
    get8004Summary(agentId: string): Promise<ERC8004AgentSummary>;
    /** Resolve an OP DID to any associated 8004 NFTs. */
    resolve8004ByDid(did: string): Promise<{
        did: string;
        nfts: Record<string, unknown>[];
        count: number;
    }>;
    /** Resolve an 8004 NFT to its OP DID. */
    resolve8004ByNft(chain: string, tokenId: string): Promise<Record<string, unknown>>;
    /** Pin an 8004 registration file for an agent. */
    pinRegistration(params: RegistrationPinParams): Promise<RegistrationPinResult>;
    /** Get 8004 indexer status. */
    get8004IndexerStatus(): Promise<Record<string, unknown>>;
}
//# sourceMappingURL=client.d.ts.map