# Agentic Identity Protocol (AIP)

**Version:** 0.5 — Capability Consolidation
**Date:** April 25, 2026
**Authors:** Boyd Cohen, Leo Bebchuk, Claude
**Status:** Draft — Leo review incorporated, pending final sign-off
**Supersedes:** AIP v0.3.1 (April 6, 2026)

---

## Changelog (v0.3.1 → v0.5)

This is not a minor update. Eight capabilities (Specs 3.1–3.8) shipped between April 6 and April 24, 2026. Several architectural decisions by Leo Bebchuk changed the protocol's shape. This changelog traces each change to its source.

| Change | Source | Status |
|--------|--------|--------|
| **VAC redefined as static identity credential.** Transaction history and trust score components removed from VAC. These now live in the audit trail (agent-issued audit VCs) and AT-layer trust scoring. | Leo Q4 review | Architectural |
| **Audit trails repositioned from OP-hosted to agent-self-signed.** Agents issue their own audit VCs. OP does not store event logs. | Leo C4 decision | Architectural |
| **Revocation authority uses ACL-on-delegation-chain model.** Original issuer + ancestor issuers + explicit ACL. | Leo C3, Spec 3.3 §6 | Live |
| **Mid-transaction revocation blocks the transaction** (if not yet broadcast). | Leo C3, Spec 3.3 | Live |
| **Delegation upgraded to recursive DID-to-DID.** One credential type, no type hierarchy. Depth is emergent. Scope attenuation is intrinsic. | Spec 3.2 | Live (single-edge); recursive pending |
| **Policy consultation added as protocol operation.** OP defines the interface; any engine implements it. Fail-closed default. | Spec 3.5, Leo Q8 | Live |
| **Suspension added as distinct from revocation.** Reversible pause via Bitstring Status List `statusPurpose: "suspension"`. | Spec 3.3 §3.2 | Live |
| **Counterparty state feeds policy context.** Org-level counterparty tracking with auto-discovery. | Spec 3.6 | Live |
| **W3C VC Data Model v2.0 as default.** New credential issuance uses `validFrom`/`validUntil`, not v1 `issuanceDate`/`expirationDate`. | Leo Q2 | Migrating |
| **SSO identity binding for human principals.** Humans as first-class DIDs in the delegation graph. | Spec 3.8 | Live |
| **KYB upgraded to signed W3C VC.** | v0.3.1 → Spec 3.1 | Live |
| **Type registries expanded.** `allowed_counterparty_types`, reason codes, policy decision codes, `transaction_category`. | Specs 3.2/3.5/3.6 | Live |
| **VAC extension protocol.** Third-party attestation extensions attachable to the VAC by reference. Self-serve registration with namespace guardrails. | AT Verify Phase 1B | Live |
| **Chain-agnostic verification.** `ChainAdapter` interface with Lightning (3-tier verification), TRON, and Stacks (stub) adapters. | AT Verify Phase 1B | Live |

---

## 1. Overview

The Agentic Identity Protocol (AIP) is a protocol layer built on Observer Protocol (OP) that governs how agents establish, exercise, and prove their authority to act.

### What AIP governs

AIP defines **three credential types** and **two protocol operations** that act on them.

**Credential types** (objects — what exists in the system):

| Credential | Purpose | Issuer |
|------------|---------|--------|
| **Delegation Credential** | Who authorized this agent, to do what, within what scope | Delegator DID (human, org, or parent agent) |
| **Attestation Credential** | Third-party verified facts about the agent | Partner registry member |
| **Audit Credential** | Agent's self-attested record of its own activity | The agent itself |

**Protocol operations** (actions — what the protocol enforces):

| Operation | Purpose | Mechanism |
|-----------|---------|-----------|
| **Revocation & Lifecycle** | Invalidate or suspend a credential | Bitstring Status List v1.0 |
| **Policy Consultation** | Pre-commit check: should this action proceed? | Registered engine per org, fail-closed |

A fourth credential type — the **VAC (Verified Agent Credential)** — is issued by OP instances to certify agent registration. The VAC is OP-layer, not AIP-layer. AIP governs what gets attached to the VAC (delegations, attestations, extensions) but not the VAC itself.

### Where AIP sits in the stack

```
┌─────────────────────────────────────────┐
│         Policy Engine                   │  ← enforces thresholds, gates transactions
├─────────────────────────────────────────┤
│      AIP — Agentic Identity Protocol    │  ← delegation, attestation, audit,
│                                         │     revocation, policy consultation
├─────────────────────────────────────────┤
│    OP — Observer Protocol               │  ← VAC, DID identity, schema hosting,
│                                         │     status list hosting
├─────────────────────────────────────────┤
│        Settlement Rails (Lightning,     │
│         TRON, Stacks, x402, etc.)       │  ← execution
└─────────────────────────────────────────┘
```

---

## 2. Identity Foundation — W3C DIDs

Unchanged from v0.3.1. OP's identity layer uses W3C Decentralized Identifiers, deployed on mainnet since February 2026.

**DID method:** `did:web` only. No fallback methods.
**Resolution:** Domain-based, publicly resolvable. `did:web:observerprotocol.org:agents:{id}` → `https://observerprotocol.org/agents/{id}/did.json`.
**Verification methods:** Ed25519VerificationKey2020.
**Human principals:** Humans have DIDs via Sovereign (`did:web:sovereign.agenticterminal.io:users:{user_id}`). SSO identity binding (Spec 3.8) connects the human's SSO identity to their DID.

---

## 3. Architectural Principles

1. **OP hosts bytes, never keys, never event logs.** OP hosts schemas, DID documents, and status lists. OP does not custody signing keys. OP does not store agent activity records — agents issue their own audit VCs, and consuming services (e.g., AT) ingest them. Current reality: audit events still live in OP's database. This is documented technical debt with a defined migration path.

2. **Issuer-direct signing for all credentials.** The party making the claim signs the credential with their own key. No intermediary signing on behalf of issuers. Exception: Sovereign's consumer tier offers SSO-custodied signing where AT signs on behalf of an authenticated human. This is explicitly documented as custodial, not self-sovereign. The Web3 signing upgrade path provides true self-sovereignty.

3. **W3C VC Data Model v2.0** as default credential format. Existing v1 credentials remain valid. New issuance uses v2 (`validFrom`/`validUntil`, context `https://www.w3.org/ns/credentials/v2`).

4. **Ed25519Signature2020** as default signature suite.

5. **`did:web` only.** No fallback DID methods in this version.

6. **One credential type for delegation.** No type hierarchy. "Org-to-agent," "human-to-agent," "agent-to-sub-agent" are usage patterns, not schema distinctions.

7. **Three-tier hosting.** OP: schemas, DIDs, status lists. AT/service layer: enterprise state, policy engines, trust scoring. Agent: own credentials, audit VCs.

8. **Instance-issuable VACs.** The VAC is not centrally issued by "OP the organization." Any OP instance can issue VACs for its registered agents. The VAC is a certificate of registration, not a centralized endorsement.

---

## 4. VAC — Verified Agent Credential

The VAC is the OP-layer credential certifying that an agent is registered. It is issued by an OP instance and held by the agent.

### What the VAC contains (v0.5)

- **Agent identity:** DID, registered name, creation timestamp
- **Registration status:** active, suspended, deregistered
- **Credential references:** links to delegation credentials and attestation credentials held by this agent
- **Extensions array:** references to third-party attestation extensions (VAC extension protocol)

### What the VAC does NOT contain (v0.5 change)

- ~~Transaction history summary~~ — moved to audit trail (agent-issued audit VCs)
- ~~Trust score components~~ — moved to AT-layer trust scoring, surfaced as a VAC extension
- ~~Counterparty diversity metrics~~ — moved to audit trail

**Rationale (Leo Q4):** The VAC is a certificate of identity. It should not require refresh every time the agent transacts. Dynamic behavioral data belongs in audit VCs (agent-issued) and trust scores (AT-computed). This separation keeps the VAC stable and lightweight.

**Consequence:** AT's trust score, currently computed from OP-hosted `verified_events`, becomes an AT-issued VAC extension — the same pattern as any third-party extension (e.g., AIBTC reputation). OP does not privilege its own scoring over third-party scoring at the protocol level.

### VAC extensions

Third parties attach attestation data to an agent's VAC via the extension protocol. Extensions are referenced by URI, not embedded. The VAC carries a summary; the full credential is fetchable.

**Extension registration:** Self-serve via `/v1/vac/extensions/register`. Namespace claiming with integrator-identity binding. Reserved prefixes for protocol-layer use (`op_`, `at_`, `lightning_`, `stacks_`, etc.).

**Trust model:** OP attests that the extension schema is registered and the issuer DID is resolvable. OP does NOT attest that extension data is truthful. Trust in extension data is the verifier's decision, based on their trust in the extension issuer.

See the VAC Extension Protocol specification for full details.

---

## 5. Delegation

Delegation is how one DID cryptographically authorizes another DID to take actions. It is the core primitive that makes agent commerce possible — an agent can prove "I am authorized to spend up to $50 on AI inference credits, by this human, until tomorrow."

### Design

- **One credential type: `DelegationCredential`.** No subclasses. Usage patterns ("principal authorizing agent," "CFO authorizing department") are interpretive labels, not type distinctions.
- **Recursive DID-to-DID.** Any DID can delegate to any DID. A delegation is an edge in a directed graph of authority assertions. An agent's effective authority is computed by walking the graph backward to a trust root.
- **Scope attenuation is intrinsic.** Every child delegation's scope MUST be a subset of its parent's scope, for both action scope and delegation scope. Verifiers enforce this at every edge.
- **Depth is emergent.** No configured `max_delegation_depth`. Whether a delegation can have children is expressed in the delegation scope.
- **ACL on each edge.** `acl.revocation_authority` and `acl.modification_authority` fields declare who can act on each specific delegation.
- **`enforcementMode` per edge.** `protocol_native` (rail enforces scope) or `pre_transaction_check` (gateway enforces scope before transaction commits).

### Schema (W3C VC 2.0)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://observerprotocol.org/contexts/delegation/v1"
  ],
  "type": ["VerifiableCredential", "DelegationCredential"],
  "id": "urn:uuid:<credential_uuid>",
  "issuer": { "id": "<delegator_did>" },
  "credentialSubject": {
    "id": "<delegatee_did>",
    "actionScope": {
      "rails": ["lightning", "tron_usdt"],
      "maxTransactionValue": { "amount": "50.00", "currency": "USD" },
      "allowedCounterpartyTypes": ["verified_merchant", "kyb_verified_org"],
      "allowedActions": ["payment_settlement"],
      "geographicRestriction": null
    },
    "delegationScope": {
      "canDelegate": false,
      "maxDepth": null,
      "scopeCeiling": null
    },
    "acl": {
      "revocationAuthority": [],
      "modificationAuthority": []
    },
    "enforcementMode": "pre_transaction_check",
    "parentDelegation": null
  },
  "validFrom": "2026-04-25T00:00:00Z",
  "validUntil": "2026-10-25T00:00:00Z",
  "credentialStatus": {
    "id": "https://api.observerprotocol.org/status/<list_id>#<index>",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "<index>",
    "statusListCredential": "https://api.observerprotocol.org/status/<list_id>"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-25T00:00:00Z",
    "verificationMethod": "<delegator_did>#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58-encoded-signature>"
  }
}
```

Full schema definition: `observerprotocol.org/schemas/delegation/v1.json`

### Deployment state

Single-edge delegation issuance and verification: **live**. Recursive chain walking, scope attenuation enforcement across chains, cycle detection: **pending**.

---

## 6. Attestation

Attestation is how third parties provide verified facts about an agent. KYB status, compliance certifications, operational attestations — all are attestation credentials signed by the attesting party.

### Design

- **Issuer-direct signing.** The attestation issuer signs with their own key. No intermediary.
- **Partner registry.** Issuers are registered in OP's partner registry with one of four categories: `corpo`, `verifier`, `counterparty`, `infrastructure`.
- **KYB as signed VC.** KYB attestation is a W3C Verifiable Credential, not a plain-text field. The KYB provider's identity is a cryptographically attested claim.
- **Status list integration.** Every attestation credential carries a `credentialStatus` field for revocation and suspension via Bitstring Status List v1.0.

### Attestation as VAC extension

Attestation credentials can also serve as VAC extensions — domain-specific data from third parties, attached to the agent's VAC by reference. The VAC extension protocol defines how issuers register schemas, issue attestations, and how verifiers consume them.

### Deployment state

Third-party attestation issuance and verification: **live** (Spec 3.1). VAC extension registration and attestation: **live**.

---

## 7. Revocation and Lifecycle

### Mechanism

**Bitstring Status List v1.0** (W3C Recommendation, May 2025). Each issuer maintains status lists — compressed bitstrings where each credential occupies one bit index. A bit value of 1 means the credential has been actioned (revoked or suspended). Status lists are themselves signed W3C VCs, hosted at stable URLs.

### Two status purposes

- **`revocation`** — permanent invalidation. Terminal.
- **`suspension`** — reversible pause. The bit can flip between 0 and 1. Use case: "pause my agent while I'm on vacation."

A credential may carry multiple `credentialStatus` entries with different purposes.

### Revocation authority

**For attestations:** Issuer-only. Only the original issuer can revoke or suspend.

**For delegations:** ACL-on-chain (Leo C3 decision):
- The original issuer retains revocation authority (implicit, always).
- Any ancestor issuer in the delegation chain inherits revocation authority (implicit, always).
- Additional parties may be granted authority via the `acl.revocationAuthority` field (explicit, optional).
- OP verifies the signing DID is in the union of all three before accepting a status list update.

### Mid-transaction revocation

If a revocation arrives before the transaction is broadcast to the settlement rail, the transaction is blocked. If the transaction has already been broadcast or confirmed, it cannot be retroactively unconfirmed — the revocation takes effect for future transactions only.

### Cascade

Revoking a parent delegation cascades to all children in the chain. A child delegation whose parent is revoked is invalid regardless of its own status.

### RevocationAgent pattern

Automated revocation agents can monitor conditions (KYB expiry, fraud score threshold, policy violation) and trigger revocations programmatically. This is a documented pattern, not a protocol primitive — the mechanism is the same (status list bit flip signed by an authorized party).

### Deployment state

Bitstring Status List v1.0, revocation, suspension, ACL-on-chain, mid-transaction revocation, cascade: **live** (Spec 3.3).

---

## 8. Policy Consultation

Policy consultation is new in v0.5. It is a protocol-level operation that did not exist in v0.3.1.

### Design

- **OP defines the interface.** Any engine can implement it. OP is not the policy engine — OP defines how engines are registered and consulted.
- **One engine per org.** Each organization registers its policy engine URL and public key in the `policy_engines` table.
- **AT ships a reference engine.** Registered as the default for organizations that don't bring their own.
- **Consultation flow.** Write paths (delegation issuance, transaction verification) call the registered engine before committing. The engine returns one of: `permit`, `deny`, `pending_approval`, `unavailable`, `signature_invalid`.
- **Fail-closed.** If the engine is unreachable, the action is denied. Not deferred, not approved-with-warning. Denied. Fail-open is documented as a future per-org configuration option.
- **Decision signing.** Policy decisions are signed by the engine's key, enabling verifiable audit trails of who decided what. Each engine has its own DID and Ed25519 keypair (registered in `policy_engines.engine_public_key_did`). AT's reference engine signs every decision. Third-party engines sign with their own key.
- **Decision logging.** Every consultation is logged in `policy_consultation_log` with the engine's response, signature, and evaluation duration.

### Counterparty state as policy context

The counterparty management system (Spec 3.6) feeds observed, accepted, and revoked counterparty state into policy evaluation. Counterparties are auto-discovered from `agent_transactions` and tracked at org-level granularity. Agent-level counterparty restrictions are achievable via delegation scope (`allowedCounterpartyTypes` and counterparty allowlists) without a separate mechanism.

### Deployment state

Policy engine registration and consultation logging: **live** (Spec 3.5, migration 013). Counterparty auto-discovery and lifecycle: **live** (Spec 3.6, migration 014).

---

## 9. Audit Trail

The audit trail is the biggest architectural shift in v0.5.

### The model

- **Agents are issuers of their own audit VCs.** An audit VC is a W3C Verifiable Credential where the agent self-signs a record of its own activity — transactions executed, counterparties interacted with, delegations exercised.
- **AT is a consumer of audit VCs.** AT ingests agent-issued audit VCs for dashboard display, compliance export, and trust scoring. AT does not author audit records — it receives and validates them.
- **OP does not host audit event data.** OP hosts schemas and DIDs. The audit trail is agent-issued, service-consumed.

### Verification model

An audit VC is a signed claim. The agent says "I executed this transaction." Trust in the claim comes from cross-referencing, not from the credential itself:

- **On-chain verification:** For transactions settled on public rails (Lightning, TRON, Stacks), the claim is cross-referenced against on-chain data via the ChainAdapter interface.
- **Counterparty attestation:** The counterparty can issue a receipt VC confirming their side of the transaction (dual-source evidence model from Spec 3.4).
- **Neither is required for the audit VC to be valid** — but cross-referenced audit VCs carry higher evidentiary weight than uncorroborated ones.

### Incremental Merkle tree

The audit trail uses an incremental (append-only) Merkle tree. New audit entries are appended as leaves without recomputing the entire tree — only the path from the new leaf to the root is recalculated.

- The agent periodically publishes a **Merkle root credential** that anchors all entries since the last root. Each root credential references the previous root via `parentRootCredentialId`, forming a chain.
- A verifier can prove any single entry exists in the tree without downloading the full audit history.
- The `agent_activity_credentials` table supports this with `is_merkle_root`, `merkle_root_hash`, and `parent_root_credential_id` fields (migration 010).
- This is the same pattern as Certificate Transparency (RFC 6962): append-only, incrementally verifiable, previous roots remain valid.

### Current reality (technical debt)

Audit events currently live in OP's Postgres: `verified_events`, `agent_activity_credentials`, `counterparty_receipts` (migration 010). AT's Enterprise dashboard reads from these tables. This is the OP-hosted model that the agent-self-signed model replaces.

### Migration path

1. Define the Audit VC schema (agent self-signs a W3C VC recording its activity).
2. AT provides an ingestion endpoint where agents submit their audit VCs.
3. AT validates authenticity (signature check) and optionally verifies truthfulness (cross-reference).
4. OP's audit tables become a read cache, not the source of truth.
5. Eventually, OP stops storing audit events entirely.

### Trust scoring

Trust scores are computed from audit VCs at the AT layer. The trust score is NOT embedded in the VAC — it is surfaced as an AT-issued VAC extension, the same pattern as any third-party extension. This means OP does not privilege AT's trust score over a third party's reputation score at the protocol level.

### Deployment state

Agent-self-signed audit VC schema: **architectural** (defined, not implemented). OP-hosted audit trail: **live** (migration 010, technical debt). Dual-source evidence model (agent activity + counterparty receipt): **live** (migration 010 tables). Trust scoring as VAC extension: **architectural**.

---

## 10. Chain Verification

Chain verification is new in v0.5. It provides a chain-agnostic interface for verifying that a transaction actually occurred on a settlement rail.

### ChainAdapter interface

Any settlement rail is supported through a `ChainAdapter` implementation. The adapter handles chain-specific verification logic. Adding a chain means implementing one adapter — no changes to the protocol, the verify endpoint, or the audit trail.

**Current adapters:**

| Chain | Adapter | Status |
|-------|---------|--------|
| Lightning | `LightningAdapter` | **Live.** Three-tier verification with payer/payee asymmetry. |
| TRON | `TronAdapter` | **Live.** TronGrid verification. Wraps existing TronRail. |
| Stacks | `StacksAdapter` | **Stub.** Interface defined, returns "not yet implemented." Ready for integration. |

### Lightning verification — three-tier model

Lightning has a fundamental payer/payee asymmetry. Possession of a preimage proves receipt (payee-side) but not payment (payer-side). The adapter handles this explicitly:

| Tier | Evidence | Strength | Who can use it |
|------|----------|----------|----------------|
| **1. Payee attestation** | Signed `LightningPaymentReceipt` VC from payee | Strongest | Payer (with receipt from payee) |
| **2. LND node query** | Direct query to Lightning node for settlement status | Medium | Either party (if LND access available) |
| **3. Preimage only** | SHA-256(preimage) == payment_hash | Weakest | Payee only |

**Key rule:** A payer presenting only a preimage (without payee attestation or LND evidence) is **rejected**. This prevents the attack where a payer claims a payment using a probed or intercepted preimage.

### Deployment state

`/v1/chain/verify` endpoint with adapter dispatch: **live**. Lightning three-tier verification: **live**. TRON verification: **live**. Stacks: **stub**.

---

## 11. Human Identity

Humans are first-class principals in the AIP delegation graph. This was implicit in v0.3.1; v0.5 makes it explicit.

- A human principal has a DID (`did:web:sovereign.agenticterminal.io:users:{user_id}`).
- A human issues delegation credentials to their agents using the same `DelegationCredential` primitive as org-to-agent delegation. No special credential type.
- SSO identity binding (Spec 3.8) connects the human's SSO identity to their DID via `sso_subject_id` on the user record. Per-org IdP configuration supports SAML.
- **Signing paths:**
  - **Custodial (MVP):** AT signs on behalf of the SSO-authenticated human. Explicitly documented as custodial, not self-sovereign.
  - **Web3 (self-sovereign):** Human signs with their own wallet key. Live in AT Enterprise; consumer-tier via Sovereign is pending.

---

## 12. Remediation

Remediation is how a blocked agent receives structured guidance to resolve its own trust deficit. Unchanged in structure from v0.3.1, with updates to reflect new denial reasons and the policy consultation interface.

### Remediation response structure

When an agent is denied, the response includes:
- **`reason`** — enumerated denial reason from the type registry
- **`remediation_options`** — array of machine-readable actions the agent can take
- Each option includes: action, description, estimated impact, complexity, preconditions, action endpoint

### Remediation URL protocol (new in v0.5)

For the AT Verify flow, soft-rejected verdicts include a **remediation URL** — a signed JWT deep-link to Sovereign where the human principal can authorize their agent. The JWT is:
- Signed by AT's remediation service key (EdDSA, Ed25519)
- Short-lived (60-minute TTL)
- Single-use (JTI tracking)
- Tamper-evident (any modification invalidates the signature)
- Forwardable through untrusted channels (the URL contains no secrets; only the authenticated human can complete the flow)

The proposed delegation scope in the JWT is a ceiling — the human can approve as-is, reduce scope, or reject. The human cannot increase scope beyond what the JWT proposes.

---

## 13. Verification and Testing

Three verification lanes, updated from v0.3.1:

### Lane 1 — Public DID verification (no auth)

Any party can resolve an agent's or organization's DID document via `did:web` resolution and verify credential signatures against the published public key. No OP account required. No API key required.

### Lane 2 — AT Credential Viewer (authenticated)

The AT Enterprise dashboard provides authenticated access to inspect, decode, and verify all credentials held by an organization's agents. Includes delegation chain visualization, attestation history, and revocation status.

### Lane 3 — AT Verify (API key auth)

The `/v1/verify` endpoint provides single-call transaction verification for integrators. One call, one verdict:
- **Approved:** with a signed W3C VC verification receipt, independently verifiable
- **Soft-rejected:** with a remediation URL for the human to authorize
- **Denied:** with a reason and no retry path

The verification receipt is a first-class W3C VC artifact — storable, portable, and verifiable without contacting AT.

---

## 14. Type Registries

Canonical enumerated values enforced across all AIP implementations.

### `allowed_counterparty_types`
`verified_merchant`, `kyb_verified_org`, `did_verified_agent`, `delegated_agent`, `individual`, `unverified`

### `revocation_reason`
`agent_compromised`, `agent_decommissioned`, `scope_violation`, `org_kyb_expired`, `org_kyb_revoked`, `org_offboarded`, `fraud_suspected`, `admin_override`

### `denial_reason`
`score_below_threshold`, `no_delegation_credential`, `delegation_credential_expired`, `delegation_credential_revoked`, `scope_mismatch`, `counterparty_not_eligible`, `kyb_credential_missing`, `kyb_credential_expired`, `kyb_credential_revoked`, `did_resolution_failed`, `delegation_depth_exceeded`, `geographic_restriction`, `rail_not_permitted`

### `policy_decision`
`permit`, `deny`, `pending_approval`, `unavailable`, `signature_invalid`

### `transaction_category`
`ai_inference_credits`, `compute_session`, `api_call`, `digital_goods`, `other`

Transaction categories are protocol-level (not AT-specific) because delegation credentials reference them in scope definitions. Interoperability requires a shared taxonomy.

---

## 15. Open Questions for v1.0

Items resolved architecturally in v0.5 but pending implementation or further design:

1. **Audit VC schema definition.** Architecture decided (agent self-signs). Schema not yet published. Required before agents can issue audit VCs in production.
2. **VAC schema migration.** Remove transaction history and trust score fields from VAC. Add extensions array. Coordinate with existing VAC consumers.
3. **Recursive delegation implementation.** Full recursive model specced. Single-edge implemented. Chain walking, attenuation enforcement, and cycle detection are implementation work.
4. **Trust scoring as VAC extension.** AT's trust score moves from VAC core to AT-issued extension. Requires extension registration and issuance flow.
5. **Sovereign suspension UI.** Protocol supports suspension. Sovereign consumer UI for "pause my agent" is Phase 2.

---

## 16. Deployment State

Every protocol component mapped to its actual implementation status.

| Component | State | Notes |
|-----------|-------|-------|
| DID resolution (did:web) | **Live** | Production since Feb 2026 |
| Ed25519 signing infrastructure | **Live** | Production since Feb 2026 |
| VAC issuance (current schema) | **Live** | Includes tx history — to be migrated per §4 |
| Third-party attestations (Spec 3.1) | **Live** | Partner registry, issuer-direct signing |
| VAC extension registration | **Live** | `/v1/vac/extensions/register`, namespace guardrails |
| VAC extension attestation | **Live** | `/v1/vac/extensions/attest`, pre-signed credentials |
| Delegation single-edge | **Live** | Spec 3.2 |
| Delegation recursive chain walking | **Architectural** | Schema supports it; verification walks single edge only |
| Bitstring Status List v1.0 | **Live** | Spec 3.3, revocation + suspension |
| Revocation ACL-on-chain | **Live** | Spec 3.3 §6 |
| Mid-transaction revocation | **Live** | Block if not broadcast |
| Policy engine registration | **Live** | Migration 013 |
| Policy consultation logging | **Live** | Migration 013 |
| Counterparty auto-discovery | **Live** | Migration 014 |
| SSO identity binding | **Live** | Migrations 011–012 |
| Chain verification (Lightning) | **Live** | Three-tier, payer/payee asymmetry |
| Chain verification (TRON) | **Live** | TronGrid verification |
| Chain verification (Stacks) | **Stub** | Interface defined, not implemented |
| Audit trail (agent-self-signed) | **Architectural** | Leo C4. Schema not defined. |
| Audit trail (OP-hosted) | **Live (tech debt)** | To be replaced by agent-self-signed model |
| VAC schema migration (remove tx history) | **Architectural** | Leo Q4. Implementation pending. |
| Trust scoring as VAC extension | **Architectural** | Depends on VAC schema migration |
| AT Verify (`/v1/verify`) | **Sandbox** | Developer onboarding tier |
| Remediation URL protocol | **Sandbox** | JWT-based, EdDSA signed |
| Recursive delegation cycle detection | **Deferred** | |
| ZK selective disclosure | **Deferred** | |
| Cross-currency price oracle | **Deferred** | |

---

## 17. What Is Not in AIP

Unchanged from v0.3.1, with additions:

- **Trust scoring algorithms.** AIP defines the inputs (audit VCs, attestations) and the extension mechanism (trust score as VAC extension). The scoring algorithm itself is AT-layer, not protocol-layer.
- **Payment execution.** AIP verifies authority and records activity. Settlement is handled by the rail (Lightning, TRON, Stacks). The ChainAdapter verifies transactions after the fact; it does not execute them.
- **KYB verification methodology.** AIP carries KYB attestation credentials. How a KYB provider conducts verification is outside AIP scope.
- **Real-world identity.** AIP operates on DIDs. Binding a DID to a legal person is the domain of KYB providers and identity attestors.
- **Legal enforceability.** AIP provides cryptographic evidence of authorization. Whether that evidence is legally binding in a given jurisdiction is outside protocol scope.
- **Notification infrastructure.** AIP does not define how agents communicate with humans (email, SMS, push). The remediation URL protocol provides the URL; delivery is the agent's responsibility.

---

*Observer Protocol, Inc. · AIP v0.5 · April 25, 2026*
