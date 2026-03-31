Observer Protocol — DID/VC Rebuild: Implementation Scope
Internal working document · March 30, 2026 · Not for external distribution
This document specifies the full scope of the OP rebuild for Claude Code execution. It defines every file to be created or replaced, the target architecture for each layer, and the sequencing constraints Maxi must follow during deployment.
Decisions are final. Do not proceed with any layer until its prerequisites are met.

1. Architecture decisions — final
All open decisions from whitepaper v1.2 are now closed. No further input is required before Claude Code execution begins.
DecisionResolutionDID methoddid:web — all principals (org, user, agent). No blockchain dependency.Identity modelFull replacement of public_key_hash. No layering or compatibility shim.Shared state / Option CAgent carries full VP. DB is cache only, not authoritative record.VAC formatW3C Verifiable Presentation containing W3C Verifiable Credentials.AttestationsEach attestation = one VC issued by OP, signed with OP's Ed25519 key.PermissionsExpressed as VCs issued by the granting principal's DID.Org relationshipsDelegation hierarchy (org → employee → agent) expressed as VCs.Selective disclosureAgent-level VP subset presentation. Agent presents relevant VCs per context.ZK-SNARKsDeferred — future directions. Not in v1.VAC self-verificationAgent signs the VP. OP signs individual VCs within it. No OP countersign on VP.On-chain anchoringOptional extension (OpenTimestamps, quarterly cadence). Not mandatory.Scoring / AT-ARS-1.0Lives in AT, not OP. OP issues no trust scores.Timestamp integrityOpenTimestamps with periodic Bitcoin anchoring — v1 delivery.Collusion detectionEconomic deterrence at protocol level. AT handles heuristic flagging.

2. What does not change
The following modules survive the rebuild without significant modification. Do not touch these files unless a specific issue is called out below.
Module / fileStatus and noteswebhook_delivery.pyStructure and delivery logic survive intact. Add four new event types: did.registered, did.rotated, vc.issued, vp.submitted. No other changes.attestation_scoping.pyTrustLevel enum and HybridAttestation structure reused. Remove get_effective_trust_score() — scoring belongs in AT.organization_models.pyPydantic models largely reused. Add did_document field to OrganizationResponse.migrations/002_add_quality_claims_notes.sqlNo changes. AT-layer concern, correctly separated.x402 rail verification logicCore blockchain verification (viem, USDC event parsing) untouched. Attestation payload format updates only.Lightning/L402 integrationContinues toward Level 3. No architectural changes from rebuild.Webhook DB tableswebhook_registry and webhook_deliveries tables unchanged.

3. Rebuild layers and sequencing
The rebuild is structured in five layers with strict sequencing dependencies.
Layer 1 → Layer 2 → Layer 3 (mandatory sequence)
Layers 4 and 5 can run in parallel with Layer 2 once Layer 1 is verified.

Layer 1 — DID identity ⚠️ BLOCKS EVERYTHING ELSE
Layer 1 replaces the public_key_hash identity model with did:web throughout the codebase.
DID Document format
Every principal (org, user, agent) gets a DID Document. Same format, different path.
Agent DID Document — served at GET https://observerprotocol.org/agents/{agent_id}/did.json
json{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:observerprotocol.org:agents:{agent_id}",
  "verificationMethod": [{
    "id": "did:web:observerprotocol.org:agents:{agent_id}#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:observerprotocol.org:agents:{agent_id}",
    "publicKeyMultibase": "{multibase_encoded_ed25519_public_key}"
  }],
  "authentication": ["did:web:observerprotocol.org:agents:{agent_id}#key-1"],
  "assertionMethod": ["did:web:observerprotocol.org:agents:{agent_id}#key-1"]
}
Organization DID — served at GET https://observerprotocol.org/orgs/{org_id}/did.json (same structure, :orgs: path segment)
OP's own DID — served at GET https://observerprotocol.org/.well-known/did.json

id: "did:web:observerprotocol.org"
This is the issuer DID for all OP-signed VCs.

New and updated API endpoints — Layer 1
EndpointDescriptionGET /.well-known/did.jsonOP's own DID Document. Required for any verifier to check OP-issued VC signatures.GET /agents/{agent_id}/did.jsonAgent DID Document. Returns current public key.GET /orgs/{org_id}/did.jsonOrganization DID Document.POST /agents/register (updated)Now accepts and returns a DID string. Generates and stores DID Document. Replaces public_key_hash registration.PUT /agents/{agent_id}/keys (new)Key rotation endpoint. Updates the DID Document without changing the DID.
DB schema changes — Layer 1
sql-- Migration 003: Replace public_key_hash with DID

-- 1. Add DID columns to observer_agents
ALTER TABLE observer_agents
  ADD COLUMN agent_did TEXT UNIQUE,
  ADD COLUMN did_document JSONB,
  ADD COLUMN did_created_at TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN did_updated_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX idx_observer_agents_did ON observer_agents(agent_did);

-- 2. Add DID to organizations table
ALTER TABLE organizations
  ADD COLUMN org_did TEXT UNIQUE,
  ADD COLUMN did_document JSONB;

-- 3. Store OP's own DID document
CREATE TABLE IF NOT EXISTS op_did_document (
  id SERIAL PRIMARY KEY,
  did TEXT NOT NULL,
  document JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- NOTE: public_key_hash columns are kept during transition.
-- They are dropped in Migration 004 after Layer 2 is verified.
Files created or replaced — Layer 1
FileActiondid_resolver.py (new)Core DID resolution module. resolve_did(did_string) fetches and validates DID Documents. Used by all VC verification flows.did_document_builder.py (new)Builds DID Documents for agents and orgs from Ed25519 public keys. Handles multibase encoding.api-server-v2.pyAdd DID resolution endpoints. Update /agents/register. Add key rotation endpoint.organization_registry.pyAdd org_did field. Call generate_org_did() on registration. Store DID Document in DB.migrations/003_add_did_columns.sql (new)Schema migration as above..env.exampleAdd OP_DID, OP_SIGNING_KEY, OP_PUBLIC_KEY. Remove hardcoded FutureBit path from default.
✅ Layer 1 verification gate — do not proceed to Layer 2 until all pass
bashcurl https://observerprotocol.org/.well-known/did.json
curl https://observerprotocol.org/agents/{test_agent_id}/did.json
curl https://observerprotocol.org/orgs/{test_org_id}/did.json
Each must return valid JSON with id, verificationMethod, and publicKeyMultibase. Also verify that key rotation via PUT /agents/{id}/keys updates the DID Document and that old verification fails with the old key.

4. Claude Code implementation rules

⚠️ Read this section before writing a single line of code. These constraints apply to every file in this rebuild.

Environment and paths

All new files go to /media/nvme. Never write to the SD card root.
Use os.environ.get() for all configuration. No hardcoded paths anywhere.
Required env vars: OP_SIGNING_KEY, OP_PUBLIC_KEY, OP_DID, DATABASE_URL, OP_WORKSPACE_PATH, OP_ALLOWED_ORIGINS, TRUSTED_ISSUERS.
OP_WORKSPACE_PATH default must be a generic relative path — not /home/futurebit/anything.
OP_SIGNING_KEY — hex-encoded Ed25519 private key, exactly 64 hex characters (32 bytes).
OP_PUBLIC_KEY — hex-encoded Ed25519 public key, exactly 64 hex characters (32 bytes).
Collusion detectionEconomic deterrence at protocol level. AT handles heuristic flagging.TRUSTED_ISSUERS — comma-separated list of trusted KYB provider DIDs.

Cryptographic requirements

All DID Documents must use publicKeyMultibase encoding (base58btc, prefix z).
All VC proofs must use Ed25519Signature2020 type.
All VP proofs must use Ed25519Signature2020 type.
Signature verification must be real — no stubs, no length checks, no return True.
OP's signing key is Ed25519. secp256k1 support maintained for legacy compatibility only.
Key rotation must update the DID Document in DB and at the resolution endpoint. The DID string itself never changes.

W3C conformance

Every VC must include @context: ["https://www.w3.org/2018/credentials/v1", "https://observerprotocol.org/context/v1"].
Every VC must include issuer as a DID string.
Every VC must include credentialSubject.id as the subject's DID.
Every VP must include holder as the presenting agent's DID.
Expiration is expirationDate (VC level) — never a custom expires_at at top level.
Optional fields are omitted entirely — never set to null.

DB rules

DB is cache only from Layer 3 onward. No verification flow may require a DB lookup.
public_key_hash columns are kept until Layer 3 is verified, then dropped in Migration 004.
All DB credentials via DATABASE_URL env var. The hardcoded postgresql://agentic_terminal string must be removed from all files.


Observer Protocol — DID/VC Rebuild Specification · v1.1 · March 30, 2026 · Internal
