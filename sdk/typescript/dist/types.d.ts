/**
 * Observer Protocol SDK - Type Definitions
 */
export interface ObserverClientOptions {
    /** API base URL (default: https://api.observerprotocol.org) */
    baseUrl?: string;
    /** API key for authenticated endpoints */
    apiKey?: string;
    /** Request timeout in ms (default: 30000) */
    timeout?: number;
}
export interface Agent {
    agentId: string;
    agentDid: string;
    agentName: string | null;
    verified: boolean;
    trustScore: number | null;
    rails: string[] | null;
    transactionCount: number;
    attestationCount: number;
}
export interface RegisterAgentParams {
    publicKey: string;
    agentName?: string;
    alias?: string;
    framework?: string;
}
export interface RegisterAgentResult {
    agentId: string;
    agentDid: string;
    agentName: string;
    didDocument: Record<string, unknown>;
    verificationStatus: string;
}
export interface Challenge {
    challengeId: string;
    nonce: string;
    expiresAt: string;
}
export interface TrustScoreComponents {
    receiptScore: number;
    counterpartyScore: number;
    orgScore: number;
    recencyScore: number;
    volumeScore: number;
}
export interface TrustScore {
    agentId: string;
    trustScore: number;
    receiptCount: number;
    uniqueCounterparties: number;
    totalStablecoinVolume: string;
    lastActivity: string | null;
    components: TrustScoreComponents;
}
export type AuthorizationLevel = 'one-time' | 'recurring' | 'policy';
export type AttestationTier = 'self-attested' | 'enterprise' | 'chain-anchored';
export interface DelegationRequest {
    agentId: string;
    orgDid?: string;
    requestedBy?: string;
    scope?: string[];
    rails?: string[];
    spendingLimits?: {
        perTransaction: string;
        daily: string;
        currency?: string;
    };
    expiration?: string;
    attestationTier?: AttestationTier;
}
export interface DelegationRequestResult {
    requestId: string;
    status: string;
    agentDid: string;
    orgDid: string;
}
export interface Delegation {
    requestId: string;
    agentId: string;
    agentName: string | null;
    orgDid: string;
    requestedBy: string;
    status: string;
    createdAt: string;
    expiry: string | null;
    spendingLimits: Record<string, string> | null;
    permissions: string[] | null;
    attestationTier: string;
}
export interface MagicLinkParams {
    agentId: string;
    counterpartyDid: string;
    counterpartyName: string;
    amount: string;
    currency: string;
    rail: string;
    purchaseDescription: string;
    intro?: string;
    ttlMinutes?: number;
}
export interface MagicLinkResult {
    token: string;
    url: string;
    slug: string;
    intro: string;
    transactionContext: {
        counterparty: string;
        counterpartyDid: string;
        amount: string;
        currency: string;
        rail: string;
        purchaseDescription: string;
    };
    expiresAt: string;
    jti: string;
}
export interface X402VerifyParams {
    agentId: string;
    agentDid: string;
    counterparty: string;
    paymentScheme?: string;
    network?: string;
    assetAddress?: string;
    assetSymbol?: string;
    amount: string;
    resourceUri: string;
    facilitatorUrl?: string;
    settlementTxHash: string;
    paymentPayload: Record<string, unknown>;
}
export interface X402VerifyResult {
    credential: Record<string, unknown>;
    verification: {
        facilitatorVerified: boolean;
        onchainVerified: boolean;
        discrepancy: boolean;
        onchainConfirmations: number;
    };
    eventId: string;
}
export interface ReceiptVerifyParams {
    receiptJson: Record<string, unknown>;
    issuerPublicKey?: string;
}
export interface ReceiptVerifyResult {
    valid: boolean;
    issuer: string;
    authorizationLevel: string;
    principalDid: string;
    transaction: Record<string, unknown>;
}
export interface ChainVerifyParams {
    receiptReference: string;
    chain: 'lightning' | 'tron' | 'x402' | 'solana';
    chainSpecific: Record<string, unknown>;
    transaction?: Record<string, unknown>;
}
export interface ChainVerifyResult {
    verified: boolean;
    chain: string;
    receiptReference: string;
    transactionReference: string;
    explorerUrl: string | null;
    confirmedAt: string;
    chainSpecific: Record<string, unknown>;
}
export interface ERC8004AgentSummary {
    agentId: string;
    has8004Presence: boolean;
    nfts: Array<{
        chain: string;
        chainId: string;
        tokenId: string;
        ownerAddress: string;
        active: boolean;
        hasX402Support: boolean;
    }>;
    feedback: {
        feedbackCount: number;
        opBackedCount: number;
    };
    validations: {
        validationCount: number;
        opValidationCount: number;
    };
}
export interface RegistrationPinParams {
    agentId: string;
    agentDid: string;
    agentName: string;
    description?: string;
    imageUrl?: string;
    a2aEndpoint?: string;
    mcpEndpoint?: string;
    webEndpoint?: string;
}
export interface RegistrationPinResult {
    registrationFile: Record<string, unknown>;
    contentHash: string;
    servingUrl: string;
    x402Credentials: number;
}
export interface Attestation {
    attestationId: string;
    credentialId: string | null;
    partnerId: string;
    partnerName: string;
    partnerType: string;
    claims: Record<string, unknown>;
    issuedAt: string;
    attestationHash: string;
}
export interface AuditEvent {
    receiptReference: string;
    agentId: string;
    amount: string;
    currency: string;
    category: string;
    agentDid?: string;
    rail?: string;
    settlementTxHash?: string;
}
export interface AuditEventResult {
    eventId: string;
    receiptReference: string;
    dashboardUrl: string;
}
export declare class ObserverError extends Error {
    statusCode: number;
    detail: string;
    constructor(statusCode: number, detail: string);
}
//# sourceMappingURL=types.d.ts.map