# Spec 3.1 — Third-Party Attestations (Push)
**Phase:** 3
**Capability:** 1 of 8
**Version:** 0.2
**Date:** April 21, 2026
**Authors:** Boyd Cohen, Claude
**Status:** Ready for implementation
**References:** OP/AT Build Principles v0.1

---

## 1. Purpose

This spec defines the push-side attestation layer: how third-party issuers create, sign, host, and deliver W3C Verifiable Credentials about agents and the organizations that control them, and how counterparties verify those credentials independently.

Push-side means the Issuer initiates. The Subject receives a credential because the Issuer decided to attest. The complementary pull-side flow (Subject requests an attestation) is Spec 3.3 and is out of scope here.

## 2. Scope

### In scope

- Issuer-direct signing of third-party attestation VCs
- Credential hosting model (Tier 1 and Tier 2 from Build Principles §2.3)
- W3C VC JSON Schemas for registered attestation types
- Delivery of signed VCs from Issuer to Subject
- Counterparty verification without OP or AT as real-time dependencies
- AT-side caching of presented credentials for dashboard rendering and AT-ARS scoring
- The AIP Type Registry entries for attestation credential types

### Out of scope

- Revocation mechanism and status list infrastructure (Spec 3.3)
- Attestation Request primitive and the pull-side flow (Spec 3.3)
- Delegation Credentials, including `PrincipalAuthorizationCredential` (Spec 3.2)
- Delegation chains (Spec 3.4)
- Protocol-level enforcement of credential scope at transaction time (Spec 3.5)
- Sovereign-side UI for attestation display (Spec 3.7)
- Enterprise dashboard UI for attestation management (Spec 3.8)

### Dependencies

- DID resolution endpoint at `https://api.observerprotocol.org/did/<did-url-encoded>` is live (completed Phase 2).
- `did:web` documents for OP-registered Issuers are served correctly (completed Phase 2).
- Ed25519 signing infrastructure in `api-server-v2.py` is operational (completed Phase 2).
- `partner_attestations` table exists in `agentic_terminal_db` (exists; schema replacement required in this spec — no backward compatibility needed since no data has been written to it).

## 3. Model

### 3.1 The three roles in a push attestation

- **Issuer** — the third-party organization making the claim. Holds their own DID (any resolvable DID method) and their own signing key. Hosts the signed VC at a stable URL under their own control.
- **Subject** — the entity the claim is about. Typically an agent (`did:web:api.observerprotocol.org:agents:<org>:<handle>`) or an organization that controls agents.
- **Counterparty** — any party that verifies the credential when it is presented. Could be another agent, a human user, a merchant's policy engine, or AT itself during caching.

AT is NOT one of these roles. AT is a downstream consumer of credentials, not a participant in the trust flow.

### 3.2 The lifecycle

1. Issuer evaluates the Subject (KYB process, compliance check, whatever the Issuer's internal procedure requires) and decides to attest.
2. Issuer constructs a W3C VC matching one of the registered types (§5).
3. Issuer signs the VC with their DID's private key using Ed25519Signature2020.
4. Issuer publishes the signed VC at the URL in its `id` field, under the Issuer's own domain.
5. Issuer delivers the VC (or the URL pointing at it) to the Subject out-of-band. Delivery mechanism is at the Issuer's discretion — email, direct API call, signed webhook, file attachment.
6. Subject stores the VC in their credential wallet (in Sovereign, or whatever wallet they use).
7. When the Subject needs to prove the claim, they present the VC (or a Verifiable Presentation derived from it) to a Counterparty.
8. Counterparty verifies independently per §6.

### 3.3 Key property: OP and AT are never in the signing path

Neither OP nor AT signs any third-party attestation. Neither holds the Issuer's private key. If OP and AT both disappeared, any existing third-party attestation could still be verified by a counterparty given the Issuer's DID and the VC JSON.

This is the test from Build Principles §2.1 and it is the dividing line between conformant and non-conformant implementations. Any implementation path that violates it is incorrect.

## 4. Credential Structure

### 4.1 Canonical schema

Every third-party attestation VC in scope for this spec follows this structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://observerprotocol.org/contexts/attestation/v1"
  ],
  "id": "https://<issuer-domain>/attestations/<credential-id>",
  "type": ["VerifiableCredential", "<RegisteredAttestationType>"],
  "issuer": "<issuer DID>",
  "validFrom": "<ISO 8601 timestamp>",
  "validUntil": "<ISO 8601 timestamp>",
  "credentialSubject": {
    "id": "<subject DID>",
    "<type-specific claim fields>": "..."
  },
  "credentialSchema": {
    "id": "https://observerprotocol.org/schemas/<type>/v1.json",
    "type": "JsonSchema"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO 8601 timestamp>",
    "verificationMethod": "<issuer DID>#<key-id>",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base58btc-encoded signature>"
  }
}
```

Note the deliberate absence of a `credentialStatus` field in this spec. Revokable credentials will add `credentialStatus` per Spec 3.3. Credentials issued under 3.1 are either:

- Non-revokable (Tier 1 from Build Principles §2.3) — no `credentialStatus`, permanent validity subject to `validUntil`.
- Revokable but temporarily unrevokable until 3.3 lands — issued without `credentialStatus`, updated to include it when Spec 3.3 completes. This is an explicit transitional state, not a long-term gap.

### 4.2 Field requirements

- `@context` MUST include the two contexts shown above. Additional contexts MAY be appended.
- `id` MUST be an HTTPS URL under the Issuer's control, resolvable to the exact signed VC JSON.
- `type` MUST include `VerifiableCredential` as the first element and one registered attestation type from §5 as the second.
- `issuer` MUST be a resolvable DID. Any DID method is accepted for external Issuers (not constrained to `did:web`). The DID MUST resolve and contain the verification method referenced in the `proof` block.
- `validFrom` and `validUntil` MUST be ISO 8601 UTC timestamps. `validUntil` MUST be later than `validFrom`.
- `credentialSubject.id` MUST be a resolvable DID. Counterparties verify based on signature and DID resolution, not DID method.
- `credentialSchema.id` MUST point at the canonical JSON Schema for the credential type.
- `proof` MUST use `Ed25519Signature2020` for this spec. Other suites may be added in future versions.

### 4.3 Sample KYB attestation

Illustrative, non-normative:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://observerprotocol.org/contexts/attestation/v1"
  ],
  "id": "https://kyb.example.com/attestations/kyb-20260421-7a3f",
  "type": ["VerifiableCredential", "KYBAttestationCredential"],
  "issuer": "did:web:kyb.example.com",
  "validFrom": "2026-04-21T00:00:00Z",
  "validUntil": "2027-04-21T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:api.observerprotocol.org:orgs:acme-corp",
    "legalName": "Acme Corp Ltd",
    "jurisdiction": "US-DE",
    "registrationNumber": "DE-1234567",
    "kybLevel": "standard",
    "verifiedAt": "2026-04-21T00:00:00Z"
  },
  "credentialSchema": {
    "id": "https://observerprotocol.org/schemas/kyb-attestation/v1.json",
    "type": "JsonSchema"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-21T00:00:00Z",
    "verificationMethod": "did:web:kyb.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXb2mD8..."
  }
}
```

## 5. Registered Attestation Types (This Spec)

Types registered under Spec 3.1. Each type has a JSON Schema hosted at the canonical URL pattern.

| Type | Schema URL | Typical Issuer | Notes |
|---|---|---|---|
| `KYBAttestationCredential` | `https://observerprotocol.org/schemas/kyb-attestation/v1.json` | KYB providers (MoonPay-tier, Sumsub, Persona, etc.) | Attests organizational KYB status |
| `KYAAttestationCredential` | `https://observerprotocol.org/schemas/kya-attestation/v1.json` | Agent identity providers | "Know Your Agent" — attests to agent identity verification |
| `ComplianceAttestationCredential` | `https://observerprotocol.org/schemas/compliance-attestation/v1.json` | Compliance providers | AML, sanctions, or specific regulatory attestations |
| `NetworkMembershipCredential` | `https://observerprotocol.org/schemas/network-membership/v1.json` | Network operators | Attests agent is a member of a named network |

`PrincipalAuthorizationCredential` is handled by Spec 3.2 (it is structurally a delegation credential, not a third-party attestation).

Each schema MUST be published before the first credential of that type is issued. Schema-first development per Build Principles §4.

### 5.1 Schema content (high level)

Each schema specifies:

- Required and optional fields in `credentialSubject`.
- Type constraints on each field (string, enum, ISO 8601 timestamp, etc.).
- Enum values where applicable, referencing the Type Registry.
- Validation constraints (minimum lengths, date ranges, format patterns).

Schemas are produced as companion artifacts alongside this spec. First schema delivery: `kyb-attestation/v1.json`. Others follow as the first Issuer for each type onboards.

## 6. Verification

### 6.1 Required verification steps

A Counterparty verifying a third-party attestation credential MUST perform all of the following:

1. **Resolve the Issuer DID.** Fetch the DID document via standard resolution for the DID method used. For `did:web` Issuers, this means fetching `https://<issuer-domain>/.well-known/did.json` directly, or via OP's DID resolver (both paths yield the same document for `did:web`). Other DID methods resolve per their respective specifications.

2. **Extract the verification method.** Locate the key in the DID document referenced by the credential's `proof.verificationMethod` field. If the key is not present or has been rotated out, verification fails.

3. **Verify the signature.** Use Ed25519Signature2020 verification. The signed payload is the canonicalized VC with the `proof.proofValue` field removed. Standard W3C VC Data Integrity verification.

4. **Validate the schema.** Fetch the JSON Schema from `credentialSchema.id`. Validate the full VC JSON against the schema. Validation failure = verification failure.

5. **Check temporal validity.** Current time MUST be at or after `validFrom` and before `validUntil`. Out-of-range = verification failure.

### 6.2 Counterparty verification without OP dependency

The verification flow works without calling OP's API. A Counterparty that has cached the Issuer's DID document and the credential schema can verify entirely offline. OP provides resolution endpoints for initial fetch and refresh; verification does not require a real-time OP call.

This is a conformance property. If an implementation requires OP to be reachable at verification time, the implementation is non-conformant per Build Principles §2.4.

### 6.3 OP's convenience verification endpoint

OP offers a convenience endpoint:

```
POST https://api.observerprotocol.org/verify
Content-Type: application/json

{
  "credential": { ... full VC JSON ... }
}
```

Response:

```json
{
  "verified": true,
  "checks": {
    "signature": "pass",
    "schema": "pass",
    "validity_period": "pass",
    "issuer_did_resolvable": "pass"
  },
  "issuer_did": "did:web:kyb.example.com",
  "subject_did": "did:web:api.observerprotocol.org:orgs:acme-corp",
  "credential_type": "KYBAttestationCredential"
}
```

This endpoint exists for convenience during development and low-stakes contexts. High-stakes verification (e.g., before executing a transaction) SHOULD be performed by the Counterparty directly to avoid the network dependency.

### 6.4 Schema caching

Counterparties MAY cache credential schemas following standard HTTP caching headers (Cache-Control, ETag, Last-Modified). Schemas are versioned in the URL path; a new schema version means a new URL, so caching at any horizon is safe for a given URL. Specific cache horizons are left to Counterparty policy.

## 7. Hosting

### 7.1 Issuer hosting (Tier 2)

Default for Spec 3.1. The Issuer hosts the VC at the URL in its `id` field, under a domain they control. The URL MUST:

- Serve over HTTPS.
- Return the exact signed VC JSON, byte-for-byte identical to what was signed.
- Remain stable for the credential's lifetime (`validFrom` to `validUntil`).
- Return a valid JSON content type (`application/json` or `application/ld+json`).

The Issuer MAY additionally publish the VC at secondary locations (IPFS, the Subject's wallet, public directories). The URL in `id` is authoritative.

### 7.2 Tier 1 hosting (non-revokable attestations)

Transaction receipts, one-time completion attestations, and similar point-in-time facts use Tier 1 hosting. Same mechanics as Tier 2; the difference is the absence of a `credentialStatus` field and the permanence of the credential. Tier 1 credentials MUST have a `validUntil` (even if set far in the future) to prevent indefinite validity claims.

### 7.3 Tier 3 hosting deferred

Tier 3 (OP-hosted VC and status list for Issuers without their own infrastructure) requires status list infrastructure, which is Spec 3.3. Attestation Issuers who need Tier 3 hosting wait for 3.3 or host on their own infrastructure in the interim.

## 8. Delivery from Issuer to Subject

AIP does not prescribe a single delivery mechanism. Issuers choose based on their operational context. Three supported patterns:

### 8.1 Direct handoff

Issuer sends the signed VC JSON directly to the Subject via email, API callback, or file transfer. Subject stores locally. Simplest pattern; appropriate for relationships where the Issuer and Subject communicate out-of-band already.

### 8.2 URL reference

Issuer publishes the VC at its `id` URL and sends the Subject only the URL. Subject fetches and stores. Minimizes payload in the initial handoff; requires the URL to be accessible to the Subject.

### 8.3 Webhook delivery

Issuer POSTs the signed VC to a URL the Subject provides. Used when the Subject operates a persistent endpoint. Requires the Subject to authenticate the webhook source (via the signed VC itself — the `issuer` DID authenticates the content regardless of transport).

All three patterns produce the same end state: the Subject holds the signed VC and can present it to Counterparties.

## 9. AT-Side Caching

### 9.1 The `partner_attestations` table

When a Subject presents a third-party attestation to AT (via Sovereign or Enterprise dashboard), AT caches the VC for rendering and for AT-ARS scoring. The cache is AT-local and carries no protocol weight. The authoritative credential is the signed VC itself, held by the Subject.

### 9.2 Schema replacement

The current `partner_attestations` table was designed against the v0.3 model where partner identity was a self-asserted string. That model is obsolete. Since no production data has been written to the table, the migration drops the old columns cleanly and replaces them with the VC-cache schema.

```sql
-- Migration 003_replace_partner_attestations_for_vc.py

-- Drop the obsolete schema (no data to preserve)
DROP TABLE IF EXISTS partner_attestations;

-- Recreate as a VC cache
CREATE TABLE partner_attestations (
  id                   SERIAL PRIMARY KEY,
  credential_id        TEXT UNIQUE NOT NULL,          -- the VC's id field (URL)
  credential_type      TEXT NOT NULL,                  -- e.g., 'KYBAttestationCredential'
  issuer_did           TEXT NOT NULL,                  -- the issuer's DID
  subject_did          TEXT NOT NULL,                  -- the subject's DID
  credential_jsonld    JSONB NOT NULL,                 -- the full signed VC
  credential_url       TEXT,                           -- the URL at issuer's hosting (may equal credential_id)
  valid_from           TIMESTAMPTZ NOT NULL,
  valid_until          TIMESTAMPTZ NOT NULL,
  cached_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_verified_at     TIMESTAMPTZ
);

CREATE INDEX idx_partner_attestations_subject  ON partner_attestations(subject_did);
CREATE INDEX idx_partner_attestations_issuer   ON partner_attestations(issuer_did);
CREATE INDEX idx_partner_attestations_type     ON partner_attestations(credential_type);
CREATE INDEX idx_partner_attestations_validity ON partner_attestations(valid_until);
```

### 9.3 Cache policy

- AT MUST re-verify a cached credential when `last_verified_at` is older than 24 hours AND the credential is being used for a transaction decision.
- AT MAY serve stale cached credentials for display purposes (dashboard rendering) without re-verification.
- AT MUST NOT treat a cached credential as valid past its `validUntil` regardless of cache state.

Revocation-aware cache invalidation depends on Spec 3.3; until 3.3 ships, AT has no way to learn that an issued credential has been revoked mid-validity-period. This is an explicit gap that 3.3 closes.

## 10. API Endpoints

### 10.1 Verification endpoint (implementation of §6.3)

```
POST https://api.observerprotocol.org/verify
```

Request body:
```json
{ "credential": { ... full VC JSON ... } }
```

Response body: see §6.3.

Status codes:
- `200 OK` — verification completed. Check `verified` field for pass/fail.
- `400 Bad Request` — request body is malformed (not a valid VC structure).
- `500 Internal Server Error` — verification could not be completed due to server-side error.

### 10.2 Schema retrieval

```
GET https://observerprotocol.org/schemas/<type>/v<version>.json
```

Returns the JSON Schema for the given attestation type and version. Static file; cacheable per standard HTTP caching headers.

### 10.3 Issuer onboarding

For Issuers registering a new `did:web` DID specifically for attestation issuance, the existing Phase 2 DID registration flow applies. External Issuers using other DID methods do not register with OP; their DIDs are resolved via their respective method's standard resolution. No new onboarding endpoint is introduced by this spec.

## 11. Type Registry Entries (Added by This Spec)

Added to the attestation credential types registry (AIP Type Registry §10.2). These entries become canonical when Spec 3.1 ships:

- `KYBAttestationCredential`
- `KYAAttestationCredential`
- `ComplianceAttestationCredential`
- `NetworkMembershipCredential`

No changes to other Type Registry sections in Spec 3.1 — denial and revocation reason codes stay as they were.

## 12. Implementation Order

The recommended order for Maxi:

1. Publish `kyb-attestation/v1.json` JSON Schema to `observer-protocol-website` repo, auto-deploys to `https://observerprotocol.org/schemas/kyb-attestation/v1.json`.
2. Implement the verification endpoint (§10.1). This is the foundation — other work depends on it.
3. Run migration `003_replace_partner_attestations_for_vc.py` against `agentic_terminal_db`.
4. Implement cache write path: when a VC is presented to AT, validate it against the schema, verify signature, write to cache with appropriate metadata.
5. Implement cache read path: Enterprise dashboard endpoints that read from the updated `partner_attestations` table and serve credential data for rendering.
6. Write negative tests: expired credentials reject, schema-invalid payloads reject, tampered signatures reject, wrong-issuer credentials reject.
7. Publish remaining schemas (`kya-attestation/v1.json`, `compliance-attestation/v1.json`, `network-membership/v1.json`) as corresponding first Issuers prepare to onboard.

Each of steps 1–6 is a standalone milestone. Surface blockers at each step per Build Principles §5.3.

## 13. Testing Expectations

Per Build Principles §6.6. Specifically for 3.1:

- **Unit tests:** Signature verification. Schema validation. DID resolution. Expiry checks. Ed25519 cryptographic operations.
- **Integration tests:** End-to-end issuance → verification flow using a test Issuer DID and test credentials. Cache write and cache read against the new table.
- **Negative tests:** Tampered signatures reject. Expired credentials reject. Credentials referencing unresolvable issuer DIDs reject. Schema-invalid payloads reject. Credentials referencing the wrong schema URL reject.
- **Decentralization conformance test:** Verification succeeds with OP API unreachable, using only cached DID documents and schemas. This test is the conformance property from Build Principles §2.4.

## 14. Next Steps

1. `kyb-attestation/v1.json` drafted as a companion artifact alongside this spec.
2. Maxi begins implementation in the order specified in §12.
3. Spec 3.2 (Delegation Credentials, including `PrincipalAuthorizationCredential`) drafted in parallel with 3.1 implementation.

---

*This spec is written against Build Principles v0.1. If that document changes, this spec may need review.*
