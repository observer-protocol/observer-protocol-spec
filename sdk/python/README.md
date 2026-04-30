# observer-protocol

Python SDK for Observer Protocol - agent identity, delegation, x402 verification, and chargeback prevention for the agentic economy.

Built on W3C DIDs and Verifiable Credentials. Type-hinted throughout.

## Install

```bash
pip install observer-protocol
```

## Quick Start

```python
from observer_protocol import ObserverClient

client = ObserverClient()

# 1. Register an agent
pub, priv = ObserverClient.generate_keypair()
agent = client.register_agent(public_key=pub, agent_name="My Agent")

# 2. Verify key ownership
challenge = client.request_challenge(agent.agent_id)
sig = ObserverClient.sign_challenge(priv, challenge.nonce)
client.verify_agent(agent.agent_id, sig)
```

## Delegation (Chargeback Prevention)

```python
delegation = client.request_delegation(
    agent_id="d13cdfceaa8f895afe56dc902179d279",
    scope=["payments"],
    rails=["x402-usdc-base", "lightning", "tron:trc20"],
    spending_limits={"per_transaction": "100", "daily": "1000"},
    attestation_tier="enterprise",
)

delegations = client.list_delegations()
client.revoke_delegation(delegation.request_id)
```

## Magic Link (Human-in-the-Loop)

```python
magic_link = client.generate_magic_link(
    agent_id="d13cdfceaa8f895afe56dc902179d279",
    counterparty_did="did:web:neuralbridge.ai",
    counterparty_name="NeuralBridge",
    amount="50.00", currency="USDT", rail="usdt-trc20",
    purchase_description="GPU inference credits",
)
# Agent forwards magic_link.url to its human
result = client.get_magic_link_credential(magic_link.jti)
```

## x402 Verification (USDC on Base)

```python
result = client.verify_x402(
    agent_id="d13cdf...", agent_did="did:web:...",
    counterparty="did:web:hyperbolic.xyz",
    amount="100000", resource_uri="https://...",
    settlement_tx_hash="0x...", payment_payload={...},
)
print(result.verification.onchain_verified)  # True
```

## Chain Verification

```python
client.verify_lightning(receipt_reference="...", payment_hash="...", preimage="...")
client.verify_tron(receipt_reference="...", tron_tx_hash="...")
```

## Trust Score

```python
score = client.get_trust_score("d13cdf...")
print(score.trust_score, score.components.receipt_score)
```

## ERC-8004 On-Chain Registry

```python
summary = client.get_8004_summary("d13cdf...")
client.pin_registration(agent_id="...", agent_did="...", agent_name="Maxi")
```

## Links

- [Documentation](https://observerprotocol.org)
- [GitHub](https://github.com/observer-protocol/observer-protocol-spec)
- [TypeScript SDK](https://github.com/observer-protocol/observer-protocol-spec/tree/master/sdk/typescript)

## License

MIT
