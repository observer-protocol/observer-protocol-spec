# OP/AT Build Principles
**Version:** 0.1
**Date:** April 21, 2026
**Authors:** Boyd Cohen, Claude
**Audience:** Maxi (primary), Leo Bebchuk (reviewer)
**Status:** Living document — updated as Leo's architectural decisions accumulate

---

## Purpose

This document is the durable reference for how OP/AT is built. It sits above individual capability specs. Every capability spec will cite a specific version of this doc. When this doc changes, specs that reference older versions may need review.

Two things belong here:

1. **Principles** — how to approach implementation decisions when the spec is silent or ambiguous.
2. **Established architectural positions** — specific decisions that have been made, cited so they don't get re-litigated in each spec.

If a principle applies to only one capability, it belongs in that capability's spec, not here.

---

## 1. Cryptographic and Protocol Standards

These are non-negotiable. Every credential, every signature, every identity in OP/AT uses these standards. If an implementation path requires deviating from them, surface it as a blocker before writing code.

- **DID method:** `did:web`, resolved via OP's DID resolver at `https://api.observerprotocol.org/did/<did-url-encoded>`. Other DID methods are accepted only for verification of external counterparties, never for OP/AT-issued DIDs.
- **VC data model:** W3C Verifiable Credentials Data Model v2.0. JSON-LD serialization with embedded `proof` block.
- **Signature suite:** Ed25519Signature2020 as default. `JsonWebSignature2020` accepted for interop with external issuers using other key types. No other suites in current phase.
- **VC-JWT serialization:** Accepted by verifiers. NOT issued by AIP-native implementations in current phase.
- **Status list mechanism:** W3C Bitstring Status List v1.0. StatusList2021 (the predecessor) is functionally compatible but not the target. All new code targets Bitstring Status List v1.0.
- **Credential schema reference:** Every credential carries a `credentialSchema` field pointing at a JSON Schema hosted under `https://observerprotocol.org/schemas/`. No credentials issued without a published schema.
- **Key formats:** Ed25519 public keys in multibase-encoded form (base58btc) in DID documents, following `Ed25519VerificationKey2020`.

Changes to this section require Leo sign-off.

---

## 2. Decentralization Posture

OP is infrastructure, not a custodian. AT is a commercial tool, not a trust intermediary. These positions shape every architectural choice. When an implementation path would centralize trust in OP or AT, push back before writing code.

### 2.1 OP hosts bytes, never keys

OP MAY host credential JSON files, status list VCs, and DID documents as a convenience for Issuers who cannot run their own infrastructure. OP MUST NEVER hold Issuers' private keys or sign on Issuers' behalf.

The practical test: if OP were to disappear tomorrow, could a counterparty still cryptographically verify an existing credential given only the Issuer's DID? If no, the architecture is wrong.

### 2.2 Issuer-direct signing for all credentials

Every credential is signed by the party whose DID appears in the `issuer` field, using their own signing key, under their own control. This applies to:

- Third-party attestations (KYB providers, compliance issuers, etc.)
- Delegation Credentials (organizations delegating to agents)
- `PrincipalAuthorizationCredential` (human principals delegating to agents)
- Status list VCs (the Issuer signs their own status list)

No "OP signs on the Issuer's behalf" shortcuts, even for demo purposes.

### 2.3 Three-tier hosting model

Credentials fall into three hosting tiers. Every credential type in every capability spec MUST specify which tier it targets:

- **Tier 1 — Non-revokable, Issuer-hosted.** Point-in-time facts (transaction receipts, one-time attestations of completion). No status list. Issuer hosts the VC at a stable URL on their own infrastructure.
- **Tier 2 — Revokable, Issuer-hosted.** KYB providers, compliance providers, any Issuer running their own infrastructure. Issuer hosts the VC AND the status list. OP provides DID resolution only.
- **Tier 3 — Revokable, OP-hosted.** Individual principals issuing `PrincipalAuthorizationCredential`, small Issuers without their own hosting. OP hosts the VC bytes and the status list bytes. Issuer still signs both. OP serves; OP does not sign.

Default hosting tier for new credential types: Tier 2. Tier 3 is available when the Issuer cannot reasonably host their own infrastructure.

### 2.4 OP is never in the critical path of a transaction

Transaction verification between two agents, or between an agent and a counterparty, MUST be possible without an API call to OP at the moment of verification. DID documents and status lists MAY be cached per the verifier's policy. OP provides resolution and schema endpoints for preparation and refresh; it is not a real-time oracle during transaction flow.

### 2.5 AT is a tool, not a trust anchor

AT stores cached credentials in `partner_attestations` and other tables for rendering and scoring. These caches carry no protocol weight. The authoritative credential is the signed VC itself. A counterparty verifying a credential MUST NOT depend on AT being reachable.

---

## 3. Sovereign Implementability

Every primitive in every capability spec MUST work for individual principals, not just enterprise organizations. This is a design constraint, not a polish item.

### 3.1 Concrete implications

- **No enterprise-only primitives.** If a feature requires an org_id, there must be an equivalent flow for a self-sovereign individual.
- **No assumed admin UI.** Individual principals are their own admin. Flows that require a separate admin role to function do not work for Sovereign.
- **No enterprise-only hosting dependencies.** Principal authorizations, status list hosting, and attestation delivery must work without the Issuer having their own server — that's Tier 3 from Section 2.3.
- **No crypto-expert UX in Sovereign flows.** Human principals do not understand DIDs, VCs, or signatures. The UI surfaces semantic meaning ("authorize this agent to spend up to $X at merchant Y until date Z") and the cryptographic mechanics happen under the hood.
- **Client-side signing by default.** Principal keys live in browser storage or connected wallets (MetaMask/Alby). Keys never leave the client. The OP server never sees a principal's private key.

### 3.2 The test for Sovereign implementability

Before marking a feature complete, ask: "Could a solo human principal with no technical background use this feature in Sovereign, with only a browser and a connected wallet?" If the answer requires assumptions about org admins, IT support, or cryptographic literacy, the feature is not Sovereign-ready.

---

## 4. Schema-First Development

### 4.1 The rule

Every credential type has a JSON Schema. The schema is hosted at a stable URL. The schema is published BEFORE the first implementation touches it. No exceptions.

### 4.2 Why

Credentials that get issued without a schema become undocumented contracts. Verifiers end up reverse-engineering structure from sample payloads. When the structure needs to change, there's no single source of truth to update against. The project accumulates credential-shaped technical debt that becomes progressively harder to untangle.

### 4.3 Practical workflow

1. Capability spec defines the credential type and its fields.
2. JSON Schema is written as part of the spec, or as a companion artifact referenced by the spec.
3. Schema is published to `https://observerprotocol.org/schemas/<type>/v<version>.json` via the observer-protocol-website auto-deploy pipeline.
4. Implementation validates every issued credential against the schema. Issuance fails if validation fails.
5. Verifiers validate every received credential against the schema. Verification fails if validation fails.

### 4.4 Schema versioning

Schemas are versioned in the URL path (`/v1.json`, `/v2.json`). A breaking change to a schema requires a new version URL. The old URL continues to serve the old schema indefinitely. Credentials issued against `/v1.json` remain valid forever; new issuance moves to `/v2.json`.

---

## 5. Spec-to-Implementation Contract

### 5.1 How to read a capability spec

Each capability spec has four kinds of content:

- **Normative requirements** — uses MUST, SHOULD, MAY per RFC 2119. These are the contract. Implementation that doesn't satisfy these is incorrect.
- **Illustrative examples** — JSON payloads, sample flows, walkthroughs. These clarify intent but are not binding in every detail. If an example conflicts with a normative requirement, the normative requirement wins.
- **Rationale and commentary** — why a decision was made. Not binding. Useful for understanding; ignore for implementation.
- **Open questions** — flagged for Leo's review. Do not implement against open questions; wait for resolution.

### 5.2 When the spec is silent or ambiguous

Ask. Do not guess. An ambiguous spec point resolved by a guess during implementation becomes a durable source of drift between what the spec says and what the code does.

The default path: flag the ambiguity in the implementation thread, get clarification from Boyd or Leo, update the spec in the same pass if the clarification reveals a gap.

### 5.3 When an implementation path would require reducing scope

Surface the blocker explicitly. Do not silently reduce scope. The format: "Implementing X as specified would require Y, which is outside current scope. Options: (a) reduce scope by dropping Z, (b) expand scope to include Y, (c) defer to next phase." Boyd decides.

### 5.4 What "complete" means

A capability is complete when:

- All normative requirements in the spec are implemented.
- Every credential type has a published schema and credentials validate against it.
- Every revokable credential has working status list integration.
- Verification works end-to-end without depending on OP/AT as real-time oracles.
- Sovereign implementability (Section 3) holds for every user-facing flow.
- Tests cover the normative requirements.

---

## 6. Cross-Cutting Implementation Conventions

### 6.1 Error codes and reason fields

Every error response that rejects a credential or denies an action MUST include a machine-readable reason code from the Type Registry (AIP Section 10). Human-readable details MAY be included as a separate `reasonDetails` field. Reason codes are enumerated; adding a new one requires a spec update.

### 6.2 Database migrations

Every schema change lands as a numbered migration file in the spec repo's `migrations/` directory. Migration file format: `NNN_brief_description.py`. Migrations are idempotent where possible. Migrations are applied via the standard pipeline; direct schema changes to production are forbidden.

Each migration file includes:

- What the migration changes.
- Which capability spec section motivates the change.
- Rollback notes (if non-trivial).

### 6.3 Verification endpoints

Every credential type has a corresponding verification endpoint under `https://api.observerprotocol.org/verify/<type>`. Endpoints accept the full VC JSON in the request body and return a structured verification result including:

- Signature verification status.
- Schema validation status.
- Status list check status (for revokable types).
- Expiry check status.
- Overall pass/fail.

These endpoints are convenience endpoints. Verifiers are free to perform verification themselves and SHOULD do so for high-stakes contexts to avoid a network dependency.

### 6.4 Authenticated vs. unauthenticated routes

- **Unauthenticated routes:** DID resolution, schema retrieval, status list fetch, credential verification. These are public utilities; adding auth to them defeats the decentralization posture.
- **Authenticated routes:** Sovereign inbox, AT Enterprise dashboard APIs, admin operations, credential issuance on behalf of a specific principal or org. Authentication uses the existing DID-based auth flow (nonce-based signature).

### 6.5 Logging

Structured logs at every credential issuance, verification, status list update, and authenticated API call. Log entries include: actor DID (where applicable), operation, target credential/resource, outcome, timestamp. No private keys, no signed content bodies in logs. Log retention per AT's compliance posture; logs are a candidate for tamper-evident storage in future phases.

### 6.6 Testing expectations

Before a capability is marked complete:

- Unit tests for each normative requirement in the spec.
- Integration tests for the full issuance → verification → revocation lifecycle.
- End-to-end test that runs without OP/AT as real-time dependencies (simulates the "can a counterparty verify without calling OP?" property).
- Negative tests: expired credentials reject, revoked credentials reject, tampered signatures reject, schema-invalid payloads reject.

---

## 7. Established Architectural Positions

Positions Leo has established through capability review. These are binding. They override earlier draft decisions in prior specs if a conflict exists.

### From Capability 1 (Third-party attestations)

- Attestations are W3C VCs, signed directly by the Issuer using the Issuer's own DID.
- External issuers never interact with AT. External parties only interact with the agent; the agent mediates any AT-facing handoff.
- OP provides DID resolution, JSON schemas, and (optionally) Tier 3 hosting. OP does not sign attestations on Issuers' behalf.
- Revocation uses status-list-based mechanism (W3C standards track).

### From Capability 2 (Delegation)

- Delegation Credentials use structured fields for scope (not free-form JSON).
- Enforcement at the protocol level is REQUIRED where the rail supports it natively. OWS policy layer is the reference implementation for Lightning. EVM smart-contract wallet wrappers are deferred to Phase 4.
- AT pre-transaction check is the baseline fallback for rails without native policy enforcement.
- Delegation chains follow the MCP-I model (W3C VCs with chain references, scope attenuation enforced at every link).

### From Capability 3 (Revocation and Lifecycle)

- Bitstring Status List v1.0 (current W3C Recommendation) is the revocation mechanism for all revokable credentials. StatusList2021 is the predecessor spec; functionally compatible but not the target.
- OP stores revokable VCs and their status lists where the Issuer cannot host their own (the Tier 3 model from Section 2.3 of this doc).
- Transaction attestations are NOT revokable. They are point-in-time facts.
- If a delegation is revoked mid-transaction: if the transaction has not been broadcast, it MUST be invalidated. If it has been broadcast, it MUST NOT be confirmed.
- Revocation authority for delegations is ACL-on-chain: the original Issuer retains write-authority; sub-delegates inherit write-authority bounded by their sub-delegation scope.
- Revocation authority for third-party attestations is Issuer-only. There is no chain for attestations.
- DID key compromise is handled at the DID layer (DID document update), not at the AIP revocation layer.
- All revocation events are signed by the revoking party's DID using the same signing infrastructure as issuance. A revocation is valid only if the signature corresponds to an authorized party under the ACL model above.

### From Capabilities 4–8 (TBD)

Will be populated as Leo's review of remaining capabilities completes.

---

## 8. Versioning of This Document

This document is versioned. When Leo's review of a new capability establishes architectural positions, those positions land in Section 7 and the document version increments.

Every capability spec MUST cite a specific version of this document. When this document changes, capability specs written against earlier versions may need review. The test: does the change in this document invalidate any normative requirement in any prior spec? If yes, the affected spec is flagged for revision.

Version history:

- **v0.1 (April 21, 2026):** Initial draft. Incorporates positions from Capabilities 1, 2, and 3. Sections 4–8 pending.

---

*This document is a living reference. Feedback from Boyd and Leo shapes each version. When in doubt about any principle or position here, ask before implementing.*
