/**
 * @observer-protocol/sdk
 *
 * Agent identity, delegation, x402 verification, and chargeback
 * prevention for the agentic economy.
 *
 * MIT Licensed. Browser and Node.js compatible.
 *
 * @example
 * ```ts
 * import { ObserverClient } from '@observer-protocol/sdk';
 *
 * const client = new ObserverClient();
 *
 * // Register an agent
 * const agent = await client.registerAgent({ publicKey: 'ed25519_hex_64_chars' });
 *
 * // Verify key ownership
 * const challenge = await client.requestChallenge(agent.agentId);
 * // sign challenge.nonce with your Ed25519 private key
 * await client.verifyAgent(agent.agentId, signatureHex);
 *
 * // Issue a delegation
 * const delegation = await client.requestDelegation({
 *   agentId: agent.agentId,
 *   scope: ['payments'],
 *   rails: ['x402-usdc-base', 'lightning'],
 *   spendingLimits: { perTransaction: '100', daily: '1000' },
 * });
 *
 * // Verify an x402 payment
 * const result = await client.verifyX402({
 *   agentId: agent.agentId,
 *   agentDid: agent.agentDid,
 *   counterparty: 'did:web:hyperbolic.xyz',
 *   amount: '100000',
 *   resourceUri: 'https://api.hyperbolic.xyz/v1/chat/completions',
 *   settlementTxHash: '0x...',
 *   paymentPayload: { ... },
 * });
 *
 * // Generate a magic link for human authorization
 * const magicLink = await client.generateMagicLink({
 *   agentId: agent.agentId,
 *   counterpartyDid: 'did:web:neuralbridge.ai',
 *   counterpartyName: 'NeuralBridge',
 *   amount: '50.00',
 *   currency: 'USDT',
 *   rail: 'usdt-trc20',
 *   purchaseDescription: 'GPU inference credits',
 * });
 * // Agent forwards magicLink.url to its human via WhatsApp/Telegram/etc.
 * ```
 *
 * @see https://observerprotocol.org
 * @see https://github.com/observer-protocol/observer-protocol-spec
 */
export { ObserverClient } from './client.js';
export { ObserverError, } from './types.js';
//# sourceMappingURL=index.js.map