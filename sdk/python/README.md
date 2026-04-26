# Observer Protocol Python SDK

Register agents, verify transactions, and manage attestations on [Observer Protocol](https://observerprotocol.org).

## Install

```bash
pip install observer-protocol
```

## Quick start

```python
from observer_protocol import ObserverClient

client = ObserverClient()

# Generate a keypair (or use your existing Ed25519 key)
public_key, private_key = ObserverClient.generate_keypair()

# Register your agent
agent = client.register_agent(public_key=public_key, agent_name="My Agent")
print(f"Agent DID: {agent.agent_did}")

# Prove key ownership
challenge = client.request_challenge(agent.agent_id)
signature = ObserverClient.sign_challenge(private_key, challenge.nonce)
client.verify_agent(agent.agent_id, signature)

# Retrieve your VAC (Verified Agent Credential)
vac = client.get_vac(agent.agent_id)

# Check your trust score
score = client.get_trust_score(agent.agent_id)
print(f"Trust score: {score.trust_score}/100")
```

## Verify a Lightning payment

```python
import hashlib

client = ObserverClient(api_key="your_api_key")

preimage = "your_preimage_hex"
payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

result = client.verify_lightning_payment(
    receipt_reference="urn:uuid:unique-tx-id",
    payment_hash=payment_hash,
    preimage=preimage,
    presenter_role="payee",  # "payee" or "payer"
)

print(f"Verified: {result.verified}")
print(f"Tier: {result.chain_specific.get('verification_tier')}")
```

## Verify a TRON transaction

```python
result = client.verify_tron_transaction(
    receipt_reference="urn:uuid:unique-tx-id",
    tron_tx_hash="abc123...",
)

print(f"Verified: {result.verified}")
print(f"TRONScan: {result.explorer_url}")
```

## Register a VAC extension

```python
# Register your platform's reputation system as a VAC extension
client.register_extension(
    extension_id="myplatform_reputation_v1",
    display_name="My Reputation Score",
    issuer_did="did:web:myplatform.com:op-identity",
    schema={
        "type": "object",
        "properties": {
            "score": {"type": "integer", "minimum": 0, "maximum": 1000},
            "last_evaluated": {"type": "string", "format": "date-time"},
        },
    },
)

# Issue an attestation for an agent
client.submit_extension_attestation(
    extension_id="myplatform_reputation_v1",
    credential={...},  # Pre-signed W3C VC
    summary_fields=["score"],
)
```

## Get agent data

```python
# Public profile
agent = client.get_agent("agent_id")
print(f"{agent.agent_name}: {agent.trust_score}/100, {agent.transaction_count} txns")

# Attestations
attestations = client.get_attestations("agent_id")
for att in attestations:
    print(f"  {att.partner_name} ({att.partner_type}): {att.claims}")

# Trust score breakdown
score = client.get_trust_score("agent_id")
if score.components:
    print(f"  Transactions: {score.components.receipt_score}")
    print(f"  Counterparties: {score.components.counterparty_score}")
    print(f"  Recency: {score.components.recency_score}")

# Activity history
activities = client.get_activities("did:web:observerprotocol.org:agents:agent_id")
for act in activities:
    print(f"  {act.activity_type} on {act.transaction_rail}: {act.transaction_amount}")

# DID document
did_doc = client.get_did_document("agent_id")
```

## Authentication

Most endpoints are public. Chain verification, audit writes, and extension registration require an API key:

```python
# Public (no key needed)
client = ObserverClient()
agent = client.get_agent("agent_id")

# Authenticated (key required)
client = ObserverClient(api_key="your_api_key")
result = client.verify_lightning_payment(...)
```

To get an API key, email [dev@observerprotocol.org](mailto:dev@observerprotocol.org).

## Supported chains

| Chain | Method | Status |
|-------|--------|--------|
| Lightning | `verify_lightning_payment()` | Live |
| TRON | `verify_tron_transaction()` | Live |
| Stacks | `verify_chain("stacks", ...)` | Stub |

## Documentation

- [Developer Guide](https://github.com/observer-protocol/observer-protocol-spec/tree/master/docs/developer-guide)
- [API Reference](https://github.com/observer-protocol/observer-protocol-spec/blob/master/docs/developer-guide/api-reference.md)
- [AIP v0.5 Spec](https://github.com/observer-protocol/observer-protocol-spec/blob/master/docs/AIP_v0.5.md)

## License

MIT
