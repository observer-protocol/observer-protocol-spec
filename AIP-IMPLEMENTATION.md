# AIP v0.3.1 Implementation Documentation

**Agentic Identity Protocol (AIP) Implementation for Observer Protocol**
**Version:** 0.3.1 — Leo Bebchuk Architectural Sign-off
**Date:** April 6, 2026

---

## Overview

This document describes the implementation of AIP v0.3.1 for Observer Protocol, including all architectural decisions signed off by Leo Bebchuk.

### Implemented Components

1. **W3C DID Integration** (Section 2) — `did:web` ONLY, no fallback
2. **KYB Verifiable Credentials** (Section 3.1) — AT-anchored and provider-issued
3. **Delegation Credentials** (Section 3.2) — with Type Registry validation
4. **Revocation** (Section 4) — append-only with cascade support
5. **Remediation Response** (Section 5, 9.1) — MINIMAL ENVELOPE ONLY
6. **Type Registry** (Section 6) — validation middleware
7. **Credential Viewer API** (Section 7) — Lane 2 authenticated endpoints
8. **Delegation Chain Verification** (Section 9.3) — EAGER verification REQUIRED

---

## File Structure

```
observer-protocol-repo/
├── aip_core.py              # Core data models, Type Registry, DID Resolver
├── aip_manager.py           # Business logic: issuance, revocation, verification
├── aip_api.py              # FastAPI routes for AIP endpoints
├── aip_integration.py      # Integration with main API server
├── migrations/
│   └── 003_add_aip_tables.sql  # Database schema
└── test_aip.py            # Comprehensive test suite
```

---

## Database Schema

### Tables Created

1. **kyb_verifiable_credentials** — W3C VCs for KYB attestations
2. **delegation_credentials** — AIP Delegation Credentials
3. **credential_revocations** — Append-only revocation records
4. **aip_type_registry** — Canonical enumerated values
5. **aip_remediation_options** — Remediation action registry
6. **agent_trust_scores** — Computed trust scores
7. **aip_audit_log** — Audit trail for all AIP operations

---

## Key Implementation Details

### 1. DID Method: did:web ONLY (Section 9.2)

```python
# AIP only supports did:web
agent_did = "did:web:acme-corp.com:agent:001"
org_did = "did:web:acme-corp.com:op-identity"

# Domain mismatch = fraud signal
if DIDResolver.extract_domain(agent_did) != DIDResolver.extract_domain(org_did):
    raise DomainMismatchError("Fraud signal: domain mismatch")
```

**Resolution Pattern:**
- `did:web:observerprotocol.org:agents:{id}` → `https://observerprotocol.org/agents/{id}/did.json`

### 2. Type Registry (Section 6)

All typed fields MUST use Type Registry values:

```python
validator = TypeRegistryValidator()

# Validate counterparty types
validator.validate_counterparty_type("verified_merchant")  # ✓
validator.validate_counterparty_type("invalid_type")       # ✗

# Validate revocation reasons
validator.validate_revocation_reason("agent_compromised")  # ✓

# Validate denial reasons  
validator.validate_denial_reason("score_below_threshold")  # ✓
```

**Categories:**
- `counterparty_type` — 6 values (verified_merchant, kyb_verified_org, etc.)
- `revocation_reason` — 8 values (agent_compromised, org_kyb_expired, etc.)
- `denial_reason` — 13 values (score_below_threshold, scope_mismatch, etc.)

### 3. Delegation Chain Verification: EAGER (Section 9.3)

```python
# EAGER: Always verify full chain, regardless of depth
is_valid, message, chain = aip_manager.chain_verifier.verify_chain(
    credential_id="aip-cred-...",
    agent_did="did:web:...",
    expected_org_did="did:web:..."
)

# No lazy evaluation permitted — every link cryptographically verified
```

### 4. Remediation: MINIMAL ENVELOPE (Section 9.1)

AIP defines ONLY the envelope structure. AT provides option content.

```python
# AIP provides:
{
    "status": "denied",
    "reason": "score_below_threshold",
    "score": 58,
    "threshold": 75,
    "gap": 17,
    "remediation_options": [
        {"option_id": 1, "action": "...", "action_endpoint": "..."}
    ]
}

# AT populates option content (title, description, etc.)
```

---

## API Endpoints

### Public Endpoints (Lane 1)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/aip/did/resolve/{did}` | GET | Resolve did:web to URL |
| `/aip/type-registry/{category}` | GET | Get Type Registry values |
| `/aip/credentials/kyb/{id}` | GET | Retrieve KYB VC |
| `/aip/credentials/delegation/{id}` | GET | Retrieve Delegation Credential |
| `/aip/credential-status/{id}` | GET | Check credential status |
| `/aip/chain/verify/{id}` | GET | Verify delegation chain (EAGER) |

### Authenticated Endpoints (Lane 2)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/credentials/{agent_did}` | GET | Bearer | Full credential set |
| `/api/v1/credential-status/{id}` | GET | Bearer | Status check |

### Issuance/Revocation (Authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/aip/credentials/kyb` | POST | Issue KYB VC |
| `/aip/credentials/delegation` | POST | Issue Delegation Credential |
| `/aip/revoke` | POST | Revoke credential with cascade |
| `/aip/remediation/build` | POST | Build remediation envelope |

---

## Integration with Main API Server

Add to `api-server-v2.py`:

```python
from aip_integration import add_aip_routes

# After app = FastAPI()
add_aip_routes(app)
```

---

## Testing

Run the test suite:

```bash
python3 test_aip.py
```

Tests cover:
- DID resolution and validation (Section 2, 9.2)
- Type Registry validation (Section 6)
- Minimal remediation envelopes (Section 9.1)
- KYB VC issuance and retrieval
- Delegation credential issuance with validation
- Credential revocation with cascade
- Chain verification (EAGER)

---

## Architectural Decisions Implemented

| Decision | Section | Implementation |
|----------|---------|----------------|
| Remediation — application layer only | 9.1 | Minimal envelope structure only |
| Delegation chain — eager verification | 9.3 | `DelegationChainVerifier.verify_chain()` always full |
| DID method — did:web only, no fallback | 9.2 | `DIDResolver` rejects non-did:web; domain mismatch = fraud |
| Remediation endpoints — AT-owned | 9.4 | OP passes through, doesn't validate |
| Type Registry extension — PR to spec | 9.5 | Database table with active status |

---

## Trust Chain Flow (Section 8)

```
Agent initiates settlement transaction
  │
  ▼
DID Resolution (did:web, Section 2)
  → Agent DID resolved and verified
  → Domain match validated (Section 9.2)
  │
  ▼
VAC Query (Observer Protocol)
  → VAC retrieved
  │
  ▼
KYB VC Verification
  → kyb_credential_id resolved
  → proof verified against issuer DID
  → kybResult: pass confirmed
  │
  ▼
AIP Delegation Credential Check
  → Valid, non-expired, non-revoked?
  → Scope covers transaction?
  → Chain verified EAGERLY (Section 9.3)
  │
  ├── NO → Deny with reason (Type Registry) + remediation envelope
  │
  ▼
Trust Score Computation (AT layer)
  │
  ▼
Policy Engine — Threshold Check
  │
  ├── NO → Deny with remediation envelope
  │
  ▼
✅ Transaction approved
```

---

## Migration

Run the database migration:

```bash
psql $DB_URL -f migrations/003_add_aip_tables.sql
```

This creates:
- All AIP tables with indexes
- Type Registry default values (counterparty types, revocation reasons, denial reasons)
- Default remediation options
- Foreign key constraints to organizations table

---

## Security Considerations

1. **did:web ONLY** — No fallback to did:key or other methods
2. **Domain Mismatch = Fraud** — Reject transactions where agent and org domains don't match
3. **Eager Chain Verification** — Always verify full delegation chain
4. **Type Registry Validation** — Reject unrecognized values at API layer
5. **Append-Only Revocation** — Revocations cannot be undone
6. **Authenticated Viewer** — Full credentials only via authenticated Lane 2

---

## Next Steps

1. **Integrate with api-server-v2.py** — Add `add_aip_routes(app)`
2. **Add authentication middleware** — For Lane 2 endpoints
3. **Implement cryptographic signing** — For production credential signing
4. **Add VAC extension integration** — Embed Delegation Credentials in VAC
5. **Policy engine integration** — Consume AIP credentials for transaction decisions

---

## References

- AIP v0.3.1 Specification: `/media/inbound/AIP_v0.3.1---65ad2c5a-f2b5-4ba6-bd10-79470808f7b1`
- W3C DID Specification: https://www.w3.org/TR/did-core/
- did:web Specification: https://w3c-ccg.github.io/did-method-web/
- W3C VC Specification: https://www.w3.org/TR/vc-data-model/
