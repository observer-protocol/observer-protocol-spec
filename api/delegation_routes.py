"""
Spec 3.2 — Delegation verification endpoint (skeleton).

Single-edge verification only in this sprint:
  POST /verify/delegation — verify one delegation credential

Deferred (stubs documented):
  - Recursive chain verification (§5.2, §5.3)
  - Attenuation checks
  - Cycle detection (§5.5)
  - Sovereign hosting endpoints (§9.2, §9.3)
"""

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

router = APIRouter()

_get_db_connection = None
_resolve_did = None


def configure(get_db_connection_fn, resolve_did_fn):
    global _get_db_connection, _resolve_did
    _get_db_connection = get_db_connection_fn
    _resolve_did = resolve_did_fn


def _require_configured():
    if _get_db_connection is None or _resolve_did is None:
        raise RuntimeError("delegation_routes not configured")


# ---------------------------------------------------------------------------
# POST /verify/delegation — Single-edge delegation verification
# ---------------------------------------------------------------------------

@router.post("/verify/delegation")
async def verify_delegation(request: Request):
    """
    Verify a delegation credential (single-edge).

    Checks:
      - Signature valid against issuer DID
      - Not expired (validFrom ≤ now < validUntil)
      - Not revoked (delegation_credentials.revoked_at is null)
      - Not suspended (delegation_credentials.suspended_at is null)

    Does NOT (in this sprint):
      - Walk parent chains (resolve_chain is accepted but ignored)
      - Check attenuation
      - Detect cycles

    NOTE: Flat-model credentials from the existing _issue_delegation_vc helper
    may not fully match Spec 3.2 §4.1 structure. This endpoint validates
    structure as specified; flat-model credentials may fail validation until
    reconciled in a future sprint.
    """
    _require_configured()

    body = await request.json()
    credential = body.get("credential")
    if not credential or not isinstance(credential, dict):
        raise HTTPException(status_code=400, detail="Request body must contain a 'credential' field")

    resolve_chain = body.get("resolve_chain", False)

    checks = {
        "signature": False,
        "not_expired": False,
        "not_revoked": True,
        "not_suspended": True,
    }
    errors = []

    # Extract basic fields
    credential_id = credential.get("id")
    issuer_did = credential.get("issuer")
    if isinstance(issuer_did, dict):
        issuer_did = issuer_did.get("id")

    subject = credential.get("credentialSubject", {})
    subject_did = subject.get("id")

    cred_types = credential.get("type", [])
    if "DelegationCredential" not in cred_types:
        errors.append("credential type must include DelegationCredential")

    # 1. Signature verification
    proof = credential.get("proof", {})
    if not proof:
        errors.append("credential missing proof")
    else:
        try:
            # Resolve issuer DID to get public key
            did_doc = _resolve_did(issuer_did)
            vm_id = proof.get("verificationMethod")
            methods = did_doc.get("verificationMethod", [])
            vm = next((m for m in methods if m.get("id") == vm_id), None)
            if vm is None and methods:
                vm = methods[0]
            if vm is None:
                errors.append(f"No verification method found for {issuer_did}")
            else:
                # Verify signature
                from crypto_utils import verify_ed25519_proof, load_public_key_from_multibase
                multibase = vm.get("publicKeyMultibase", "")
                try:
                    pub_key = load_public_key_from_multibase(multibase)
                    ok, reason = verify_ed25519_proof(credential, pub_key)
                    if ok:
                        checks["signature"] = True
                    else:
                        errors.append(f"Signature verification failed: {reason}")
                except Exception as e:
                    errors.append(f"Key loading failed: {str(e)}")
        except Exception as e:
            errors.append(f"DID resolution failed for {issuer_did}: {str(e)}")

    # 2. Expiry check
    valid_from = credential.get("validFrom")
    valid_until = credential.get("validUntil")

    if valid_from and valid_until:
        try:
            now = datetime.now(timezone.utc)
            vf = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
            vu = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
            if vf <= now < vu:
                checks["not_expired"] = True
            else:
                if now < vf:
                    errors.append(f"Credential not yet valid (validFrom: {valid_from})")
                else:
                    errors.append(f"Credential expired (validUntil: {valid_until})")
        except Exception as e:
            errors.append(f"Date parsing failed: {str(e)}")
    else:
        errors.append("Missing validFrom or validUntil")

    # 3. Revocation/suspension check (lookup in delegation_credentials table)
    if credential_id:
        conn = _get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT revoked_at, suspended_at FROM delegation_credentials WHERE credential_id = %s",
                (credential_id,),
            )
            row = cursor.fetchone()
            if row:
                if row[0] is not None:
                    checks["not_revoked"] = False
                    errors.append("Credential has been revoked")
                if row[1] is not None:
                    checks["not_suspended"] = False
                    errors.append("Credential is currently suspended")
            # If not in DB, assume not revoked/suspended (credential may not be cached)
            cursor.close()
        finally:
            conn.close()

    # Build result
    all_valid = all(checks.values()) and len(errors) == 0

    result = {
        "verified": all_valid,
        "checks": checks,
        "errors": errors,
        "issuer_did": issuer_did,
        "subject_did": subject_did,
        "credential_type": "DelegationCredential",
    }

    # Stub: chain info (deferred)
    if resolve_chain:
        result["chain"] = None
        result["chain_note"] = "Recursive chain verification deferred to full Spec 3.2 build"
        result["effective_action_scope"] = None

    return JSONResponse(content=result)
