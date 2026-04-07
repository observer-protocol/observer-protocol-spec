# AIP Type Registry

**Version:** 0.3.1  
**Governance:** PR-based extensions per Section 9.5  
**Last Updated:** April 6, 2026

---

## Overview

The Type Registry defines canonical enumerated values for AIP (Agentic Identity Protocol) credentials. All values are versioned and require OP maintainer review for changes.

**Extension Process:** See [PULL_REQUEST_TEMPLATE/type-registry-extension.md](../.github/PULL_REQUEST_TEMPLATE/type-registry-extension.md)

---

## 6.1 allowed_counterparty_types

Valid counterparty types for delegation scope restrictions.

| Value | Description | Use Case |
|-------|-------------|----------|
| `verified_merchant` | Merchant with verified payment processing | E-commerce, service providers |
| `kyb_verified_org` | Organization with valid KYB attestation | B2B transactions, enterprise |
| `did_verified_agent` | Agent with verified DID ownership | A2A payments, agent services |
| `aip_delegated_agent` | Agent operating under AIP delegation | Sub-delegation scenarios |
| `sovereign_individual` | Individual with Sovereign identity | P2P, personal agents |
| `unverified` | No verification required (open) | Public services, tips |

**Default:** `unverified` (least restrictive)

---

## 6.2 Revocation Reason Codes

Valid reasons for credential revocation per Section 4.

| Code | Description | Cascade Impact |
|------|-------------|----------------|
| `agent_compromised` | Agent keys suspected compromised | Revoke all child delegations |
| `agent_decommissioned` | Agent intentionally shut down | Revoke all child delegations |
| `scope_violation` | Agent exceeded delegated scope | Review, may revoke children |
| `org_kyb_expired` | Organization KYB attestation expired | Revoke all org delegations |
| `org_kyb_revoked` | Organization KYB attestation revoked | Revoke all org delegations |
| `org_offboarded` | Organization removed from platform | Revoke all org delegations |
| `fraud_suspected` | Fraudulent activity detected | Immediate cascade revoke |
| `admin_override` | Administrative emergency action | Immediate cascade revoke |

**Note:** All revocations are append-only and permanent.

---

## 6.3 Denial Reason Codes

Valid reasons for transaction denial with remediation.

| Code | Description | Remediation Available |
|------|-------------|----------------------|
| `score_below_threshold` | Trust score below minimum | Yes — improve reputation |
| `delegation_expired` | Delegation credential expired | Yes — request renewal |
| `scope_exceeded` | Transaction exceeds scope limits | Yes — request scope expansion |
| `rail_not_allowed` | Payment rail not in allowed list | Yes — use allowed rail |
| `counterparty_type_blocked` | Counterparty type restricted | Yes — use allowed counterparty |
| `credential_revoked` | Active credential was revoked | No — permanent denial |
| `rate_limit_exceeded` | Too many requests | Yes — wait and retry |

---

## Extension History

| Date | PR | Changes | Author |
|------|-----|---------|--------|
| 2026-04-06 | Initial | v0.3.1 baseline types | Leo Bebchuk, Boyd Cohen |

---

## Implementation

```python
from aip_core import CounterpartyType, RevocationReason, DenialReason

# Validate counterparty type
counterparty = CounterpartyType("verified_merchant")  # ✓ Valid

# Get all valid values
all_types = [t.value for t in CounterpartyType]
```

---

*For extension requests, open a PR using the Type Registry Extension template.*
