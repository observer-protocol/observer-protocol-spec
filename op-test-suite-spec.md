# Observer Protocol — Phase 1 Internal Test Suite
Internal document · March 30, 2026

This document specifies the test suite for internal validation of the v1.1 DID/VC rebuild. The goal is a single script that runs end-to-end against the live API and produces a clear, readable report confirming every key architectural claim is working correctly in production.

## Scope

Phase 1 is internal only. Tests run against http://localhost:8000 (the live FutureBit node). Output is a structured report saved to `/media/nvme/observer-protocol/test-reports/` with a timestamp. No external exposure. No partner or investor audience yet.

Phase 2 (scoped with Leo) will address external-facing validation, public endpoints, and partner-consumable proof artifacts.

## Test file location

```
/media/nvme/observer-protocol/scripts/test_protocol_v1.py
```

Run with:
```bash
cd /media/nvme/observer-protocol
python scripts/test_protocol_v1.py
```

Output saved to:
```
/media/nvme/observer-protocol/test-reports/protocol-test-{timestamp}.json
/media/nvme/observer-protocol/test-reports/protocol-test-{timestamp}.txt
```

Both formats produced on every run — `.json` for programmatic use, `.txt` for human reading.

## Environment requirements

```bash
DATABASE_URL=postgresql://agentic_terminal:at_secure_2026@localhost/agentic_terminal_db
OP_SIGNING_KEY={hex_encoded_ed25519_private_key}
OP_PUBLIC_KEY={hex_encoded_ed25519_public_key}
OP_DID=did:web:observerprotocol.org
```

The test script reads these from the environment. It does not hardcode any credentials.

---

## Test groups

### Group 1 — DID resolution (Layer 1)

**T01 — OP DID Document resolves**
- Call `GET http://localhost:8000/.well-known/did.json`
- Assert: HTTP 200, `id == "did:web:observerprotocol.org"`, `verificationMethod` non-empty, type is `Ed25519VerificationKey2020`, `publicKeyMultibase` starts with `z`

**T02 — Agent DID Document resolves**
- Register a fresh test agent, call `GET /agents/{agent_id}/did.json`
- Assert: HTTP 200, `id` contains agent_id, `publicKeyMultibase` encodes registered key
- Clean up test agent after

**T03 — Key rotation preserves DID, updates key**
- Generate new key pair, call `PUT /agents/{agent_id}/keys`
- Assert: HTTP 200, `publicKeyMultibase` changed, `id` unchanged, historical key present with `revoked` timestamp

**T04 — Historical VC verifiable after key rotation**
- Issue a VC with old key, rotate key, verify old VC
- Assert: verification passes — old key was valid at `issuanceDate`

### Group 2 — Verifiable Credential issuance (Layer 2)

**T05 — VC issued with correct W3C structure**
- Submit test attestation, retrieve VC
- Assert: `@context` has W3C URL, `type` has `VerifiableCredential`, `issuer == "did:web:observerprotocol.org"`, `credentialSubject.id` starts with agent DID prefix, `proof.type == "Ed25519Signature2020"`, `proof.proofValue` starts with `z`

**T06 — VC signature is real Ed25519 (not a stub)**
- Extract `proof.proofValue`, decode multibase, reconstruct canonical JSON, verify against OP public key
- Assert: real cryptographic verification passes

**T07 — Tampered VC fails verification**
- Modify `credentialSubject.scope_level`, attempt verification
- Assert: verification fails

**T08 — OrgMembershipCredential issued and verifiable**
- Register test org, register agent as member, retrieve `OrgMembershipCredential`
- Assert: W3C structure correct, `issuer` is org DID, signature verifies against org public key

### Group 3 — Verifiable Presentation (Layer 2/3)

**T09 — VP assembles with correct W3C structure**
- Call `GET /vac/{agent_id}`
- Assert: `type` has `VerifiablePresentation`, `holder` is agent DID, `verifiableCredential` non-empty, each VC has valid `proof`

**T10 — VP signature verifies (agent-signed)**
- Call `POST /vac/{agent_id}/present`, extract and verify agent signature
- Assert: real Ed25519 verification passes against agent's DID-resolved public key

**T11 — Selective disclosure — subset VP verifies**
- Build VP with only one VC, submit to `POST /vp/verify`
- Assert: `valid == true`

**T12 — Tampered VP fails verification**
- Modify `holder` field, submit to `POST /vp/verify`
- Assert: `valid == false`

### Group 4 — Stateless verification (Layer 3 — Option C)

**T13 — VP verifies with no DB record**
- Temporarily rename `vp_cache` table, submit VP to `POST /vp/verify`, restore table (try/finally)
- Assert: `valid == true` with no DB — DID resolution only

**T14 — VP reconstruct from cache**
- Submit VP via `POST /vp/submit`, call `POST /vp/reconstruct`
- Assert: HTTP 200, returned VP contains agent's VCs, structurally valid

### Group 5 — Trusted issuers and KYB (Layer 2)

**T15 — KYBCredential from trusted issuer accepted**
- Generate test keypair, add DID to trusted_issuers temporarily, create mock KYBCredential, submit in VP
- Assert: `issuer_trusted == true` in VC result. Clean up after.

**T16 — KYBCredential from unknown issuer flagged**
- Create KYBCredential from DID not in trusted_issuers, submit in VP
- Assert: HTTP 200, `issuer_trusted == false`

**T17 — Cryptographically invalid credential rejected**
- Corrupt `proof.proofValue`, submit in VP
- Assert: `valid == false`, error indicates signature failure

### Group 6 — Infrastructure and environment (Layer 4)

**T18 — No hardcoded credentials in codebase**
- Grep `api/*.py` for `postgresql://agentic_terminal`, `/home/futurebit`, `/media/nvme/lnd-data`, `sys.path.insert` with absolute path
- Assert: zero matches on all patterns

**T19 — All required env vars present**
- Assert: `DATABASE_URL`, `OP_SIGNING_KEY` (64 hex chars), `OP_PUBLIC_KEY` (64 hex chars), `OP_DID` all set

**T20 — API health and DB connectivity**
- Call health endpoint
- Assert: HTTP 200, DB connection live, OP DID Document loaded

---

## Output format

Produce both `/media/nvme/observer-protocol/test-reports/protocol-test-{timestamp}.txt` and `.json` on every run. Text format:
```
═══════════════════════════════════════════════════════════════
OBSERVER PROTOCOL — INTERNAL TEST REPORT
Run at: {timestamp}
Node: FutureBit-Solo-Node
API: http://localhost:8000
Protocol version: v1.1
═══════════════════════════════════════════════════════════════

GROUP 1 — DID Resolution
  T01  OP DID Document resolves .......................... PASS
  ...

═══════════════════════════════════════════════════════════════
SUMMARY: {pass}/{total} tests passed  ({elapsed}s)
Exit 0 if all pass, 1 if any fail.
═══════════════════════════════════════════════════════════════
```

Target runtime: < 30 seconds. Tests must clean up after themselves (deregister test agents, remove test orgs, etc.).
