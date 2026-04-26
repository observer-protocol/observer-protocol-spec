# Observer Protocol

Open identity and verification protocol for autonomous agents. W3C DID/VC standards. Chain-agnostic. Rail-agnostic.

**Live at:** [api.observerprotocol.org](https://api.observerprotocol.org)

---

## What Observer Protocol does

Agents need portable, verifiable identity. Observer Protocol provides it:

- **Identity** — Every agent and organization gets a W3C Decentralized Identifier (`did:web`), publicly resolvable, cryptographically verifiable.
- **Delegation** — A human or organization cryptographically authorizes an agent to act within a defined scope (spending limits, counterparty restrictions, time windows, rail restrictions).
- **Attestation** — Third parties issue signed credentials about agents (KYB status, compliance facts, reputation scores). Issuer-direct signing — no intermediary.
- **Verification** — A single API call checks: is this agent authorized for this transaction? Returns a signed W3C Verifiable Credential receipt, independently verifiable by any party.
- **Chain verification** — Verify that a payment actually occurred on Lightning, TRON, or Stacks, with chain-specific evidence models.

The protocol is defined in [AIP v0.5](docs/AIP_v0.5.md) (Agentic Identity Protocol). The architecture is documented in [Build Principles](docs/OP-AT-BUILD-PRINCIPLES.md).

---

## Protocol stack

```
┌─────────────────────────────────────────┐
│         Policy Engine                   │  Fail-closed pre-commit checks
├─────────────────────────────────────────┤
│      AIP — Agentic Identity Protocol    │  Delegation, attestation, audit,
│                                         │  revocation, policy consultation
├─────────────────────────────────────────┤
│    OP — Observer Protocol               │  DIDs, VAC, schemas, status lists
├─────────────────────────────────────────┤
│        Settlement Rails                 │  Lightning, TRON, Stacks, x402
└─────────────────────────────────────────┘
```

---

## Chain support

| Rail | Status | Verification model |
|------|--------|--------------------|
| **Lightning** | Live | Three-tier: payee attestation, LND node query, preimage. Payer/payee asymmetry handled. |
| **TRON** | Live | TronGrid verification. TRC-20 USDT mainnet. |
| **Stacks** | Stub | Interface defined. Ready for integration. |
| **Solana** | Live | SOL + SPL token transfers. Ed25519 verification. |

Adding a chain means implementing one `ChainAdapter` — no protocol changes required.

---

## Quick start

```bash
# Clone
git clone https://github.com/observer-protocol/observer-protocol-spec.git
cd observer-protocol-spec

# Install dependencies
pip install -r api/requirements.txt

# Set environment
export DATABASE_URL="postgresql://user:pass@localhost/agentic_terminal_db"
export OP_SIGNING_KEY="<64-hex-char-ed25519-private-key>"
export OP_PUBLIC_KEY="<64-hex-char-ed25519-public-key>"
export OP_DID="did:web:observerprotocol.org"

# Run migrations
cd migrations
python3 001_add_ows_support.py
# ... through 015

# Start API
cd ../api
python3 -m uvicorn api-server-v2:app --host 0.0.0.0 --port 8000
```

The API serves interactive documentation at `/docs` (Swagger UI).

---

## Core API endpoints

### Identity

```bash
# Resolve an agent's DID document
curl https://api.observerprotocol.org/agents/agent_001/did.json

# Register an agent
curl -X POST https://api.observerprotocol.org/observer/register-agent \
  -H "Content-Type: application/json" \
  -d '{"public_key": "<ed25519-hex>", "agent_name": "My Agent"}'

# Cryptographic verification (challenge-response)
curl -X POST https://api.observerprotocol.org/observer/challenge \
  -d '{"agent_id": "agent_001"}'
# → sign the nonce with your private key, then:
curl -X POST https://api.observerprotocol.org/observer/verify-agent \
  -d '{"agent_id": "agent_001", "signed_challenge": "<signature>"}'
```

### Chain verification

```bash
# Verify a Lightning payment
curl -X POST https://api.observerprotocol.org/v1/chain/verify \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "receipt_reference": "urn:uuid:...",
    "chain": "lightning",
    "chain_specific": {
      "payment_hash": "<hex>",
      "preimage": "<hex>",
      "presenter_role": "payee"
    }
  }'
```

### VAC extensions (third-party attestations)

```bash
# Register a custom extension (e.g., reputation scores)
curl -X POST https://api.observerprotocol.org/v1/vac/extensions/register \
  -H "Authorization: Bearer <api_key>" \
  -d '{
    "extension_id": "myorg_reputation_v1",
    "display_name": "My Reputation Score",
    "issuer": {"did": "did:web:myorg.com:op-identity"},
    "schema": {"type": "object", "properties": {"score": {"type": "integer"}}}
  }'

# Issue an extension attestation for an agent
curl -X POST https://api.observerprotocol.org/v1/vac/extensions/attest \
  -H "Authorization: Bearer <api_key>" \
  -d '{
    "extension_id": "myorg_reputation_v1",
    "credential": { ... pre-signed W3C VC ... }
  }'
```

### Credentials and attestations

```bash
# Get an agent's VAC (Verified Agent Credential)
curl https://api.observerprotocol.org/vac/agent_001/full

# Verify a Verifiable Presentation
curl -X POST https://api.observerprotocol.org/vp/verify \
  -d '{"vp": { ... }}'

# List attestations for an agent
curl https://api.observerprotocol.org/vac/agent_001/attestations
```

---

## Cryptographic standards

| Standard | Usage |
|----------|-------|
| W3C DID | `did:web` for all identities |
| W3C VC Data Model 2.0 | All credentials (`validFrom`/`validUntil`) |
| Ed25519Signature2020 | All credential proofs |
| Bitstring Status List v1.0 | Credential revocation and suspension |
| Ed25519 | Agent and organization signing keys |

All credentials are independently verifiable: resolve the issuer's DID document, extract the public key, verify the Ed25519 signature. No runtime dependency on Observer Protocol.

---

## Repository structure

```
observer-protocol/
├── api/                          # FastAPI server (production)
│   ├── api-server-v2.py          # Main application
│   ├── chain_adapter.py          # Chain-agnostic verification interface
│   ├── lightning_adapter.py      # Lightning three-tier verification
│   ├── stacks_adapter.py         # Stacks adapter (stub)
│   ├── vac_extensions.py         # VAC extension registry + attestation
│   ├── verify_endpoints.py       # /v1/chain/verify, /v1/audit/verified-event
│   ├── delegation_routes.py      # Delegation credential management
│   ├── audit_routes.py           # Audit trail (Spec 3.4)
│   ├── policy_routes.py          # Policy consultation (Spec 3.5)
│   ├── counterparty_routes.py    # Counterparty management (Spec 3.6)
│   ├── sso_routes.py             # SSO/human identity (Spec 3.8)
│   ├── status_list_routes.py     # Revocation/suspension (Spec 3.3)
│   └── schemas/                  # Pydantic models
├── docs/                         # Protocol specifications
│   ├── AIP_v0.5.md               # Agentic Identity Protocol (current)
│   ├── Spec-3.1-*.md             # Third-party attestations
│   ├── Spec-3.2-*.md             # Delegation credentials
│   ├── Spec-3.3-*.md             # Revocation and lifecycle
│   └── OP-AT-BUILD-PRINCIPLES.md # Architecture decisions
├── schemas/                      # W3C JSON Schema definitions
│   ├── delegation/v1.json
│   ├── audit/v0.1/               # Audit credential schemas
│   ├── kyb-attestation/v2.json
│   └── ...
├── rails/                        # Settlement rail implementations
│   ├── tron/                     # TRON mainnet (TRC-20 USDT)
│   └── solana/                   # Solana (SOL + SPL tokens)
├── migrations/                   # Database migrations (001–015)
├── DEPLOYMENT-LOG.md             # Production deployment history
└── WHITEPAPER.md                 # Protocol vision (v1.0)
```

See [REPO_MAP.md](REPO_MAP.md) for detailed navigation.

---

## Protocol capabilities (AIP v0.5)

Eight capabilities deployed April 2026:

| # | Capability | Spec | What it does |
|---|-----------|------|-------------|
| 3.1 | Third-party attestations | [Spec 3.1](docs/Spec-3.1-Third-Party-Attestations-v0.2.md) | Issuer-direct signed attestation credentials |
| 3.2 | Delegation credentials | [Spec 3.2](docs/Spec-3.2-Delegation-Credentials-v0.1.md) | Recursive DID-to-DID authorization with scope attenuation |
| 3.3 | Revocation & lifecycle | [Spec 3.3](docs/Spec-3.3-Revocation-and-Lifecycle-v0.1.md) | Bitstring Status List v1.0. Revocation + suspension. ACL-on-chain authority. |
| 3.4 | Audit trail | Migration 010 | Dual-source evidence: agent activity + counterparty receipts |
| 3.5 | Policy consultation | Migration 013 | Pre-commit policy checks. Fail-closed. Signed decisions. |
| 3.6 | Counterparty management | Migration 014 | Auto-discovery, org-level acceptance, policy context |
| 3.7 | Agent profile | — | Agent configuration and metadata |
| 3.8 | SSO & human identity | Migrations 011–012 | SAML SSO, human principals as DIDs, custodial + Web3 signing |

Full protocol specification: [AIP v0.5](docs/AIP_v0.5.md)

---

## For integrators

### Extend the VAC with your own data

If you run a reputation system, compliance engine, or any service that produces agent-relevant data, you can register it as a VAC extension. Your attestation credentials get attached to agent VACs and are verifiable by any party that trusts your DID.

1. Register your extension schema → `POST /v1/vac/extensions/register`
2. Issue attestation credentials → `POST /v1/vac/extensions/attest`
3. Verifiers see your extension in the agent's VAC → `GET /vac/{agent_id}/full`

See the [VAC Extension Protocol](docs/AIP_v0.5.md#4-vac--verified-agent-credential) for details.

### Verify transactions on any chain

The `/v1/chain/verify` endpoint dispatches to chain-specific adapters. Lightning verification uses a three-tier model with explicit payer/payee asymmetry. Adding a new chain means implementing one `ChainAdapter` interface.

### Developer sandbox

A sandbox environment for integration testing is available with fixture data, deterministic policy outcomes, and reseedable state. Contact us for a sandbox API key.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [AIP v0.5](docs/AIP_v0.5.md) | Protocol specification (current) |
| [Whitepaper](WHITEPAPER.md) | Protocol vision and economics |
| [Build Principles](docs/OP-AT-BUILD-PRINCIPLES.md) | Architecture decisions |
| [Spec 3.1](docs/Spec-3.1-Third-Party-Attestations-v0.2.md) | Attestation credential spec |
| [Spec 3.2](docs/Spec-3.2-Delegation-Credentials-v0.1.md) | Delegation credential spec |
| [Spec 3.3](docs/Spec-3.3-Revocation-and-Lifecycle-v0.1.md) | Revocation and lifecycle spec |
| [REPO_MAP](REPO_MAP.md) | Repository navigation guide |
| [DEPLOYMENT-LOG](DEPLOYMENT-LOG.md) | Production deployment history |

---

## License

MIT

---

*Observer Protocol, Inc. · [observerprotocol.org](https://observerprotocol.org)*
