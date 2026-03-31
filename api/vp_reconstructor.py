#!/usr/bin/env python3
"""
VP Reconstructor — Observer Protocol (Layer 3)

DB is cache only from Layer 3 onward.  No verification flow requires a DB
lookup.  This module:
  - Retrieves a cached VP from the DB if one exists and is not expired.
  - Falls back to generating a fresh VP via VACGenerator (which re-issues
    VCs from live transaction data and stores the result as a new cache entry).
  - Provides VP structural validation that works entirely from the VP document
    itself — no DB access required.

Architecture note (Option C / shared state):
  The agent carries the authoritative VP.  The DB row is a convenience cache
  written by the server each time a VP is generated or submitted.  A verifier
  that receives a VP from an agent can validate it solely from the VP + the
  OP public key (fetched from /.well-known/did.json or the OP_PUBLIC_KEY env
  var).  No DB lookup is needed or performed during verification.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
W3C_VP_TYPE = "VerifiablePresentation"
W3C_VC_TYPE = "VerifiableCredential"


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return url


# ── Structural validation (no DB, no network) ────────────────────────────────

def validate_vp_structure(vp: dict) -> dict:
    """
    Validate the W3C structure of a VP without any DB or network access.

    Returns:
        {
            "valid": bool,
            "checks": {<check_name>: bool, ...},
            "errors": [str, ...],
        }
    """
    errors = []
    checks: dict = {}

    # @context
    ctx = vp.get("@context", [])
    checks["has_context"] = W3C_VC_CONTEXT in ctx
    if not checks["has_context"]:
        errors.append(f"@context must include '{W3C_VC_CONTEXT}'")

    # type includes VerifiablePresentation
    vp_types = vp.get("type", [])
    checks["has_vp_type"] = W3C_VP_TYPE in vp_types
    if not checks["has_vp_type"]:
        errors.append("type must include 'VerifiablePresentation'")

    # holder is a DID string
    holder = vp.get("holder", "")
    checks["has_holder_did"] = isinstance(holder, str) and holder.startswith("did:")
    if not checks["has_holder_did"]:
        errors.append("holder must be a DID string (e.g. did:web:...)")

    # verifiableCredential array is present and non-empty
    vcs = vp.get("verifiableCredential", [])
    checks["has_credentials"] = isinstance(vcs, list) and len(vcs) > 0
    if not checks["has_credentials"]:
        errors.append("verifiableCredential must be a non-empty array")

    # Each embedded VC has required W3C fields
    vc_errors = []
    for i, vc in enumerate(vcs):
        if W3C_VC_CONTEXT not in vc.get("@context", []):
            vc_errors.append(f"vc[{i}] missing W3C @context")
        if W3C_VC_TYPE not in vc.get("type", []):
            vc_errors.append(f"vc[{i}] missing 'VerifiableCredential' type")
        if not isinstance(vc.get("issuer"), str) or not vc["issuer"].startswith("did:"):
            vc_errors.append(f"vc[{i}] issuer must be a DID string")
        subj = vc.get("credentialSubject", {})
        if not isinstance(subj.get("id"), str) or not subj["id"].startswith("did:"):
            vc_errors.append(f"vc[{i}] credentialSubject.id must be a DID string")
        if "proof" not in vc:
            vc_errors.append(f"vc[{i}] missing proof")
        elif vc["proof"].get("type") != "Ed25519Signature2020":
            vc_errors.append(f"vc[{i}] proof.type must be 'Ed25519Signature2020'")

    checks["vcs_well_formed"] = len(vc_errors) == 0
    errors.extend(vc_errors)

    # Proof on VP (optional — unsigned VPs are allowed for drafts)
    proof = vp.get("proof")
    if proof is not None:
        checks["vp_proof_type_ok"] = proof.get("type") == "Ed25519Signature2020"
        checks["vp_proof_purpose_ok"] = proof.get("proofPurpose") == "authentication"
        checks["vp_proof_value_ok"] = (
            isinstance(proof.get("proofValue"), str)
            and proof["proofValue"].startswith("z")
        )
        if not checks["vp_proof_type_ok"]:
            errors.append("VP proof.type must be 'Ed25519Signature2020'")
        if not checks["vp_proof_purpose_ok"]:
            errors.append("VP proof.proofPurpose must be 'authentication'")
        if not checks["vp_proof_value_ok"]:
            errors.append("VP proof.proofValue must be multibase base58btc (prefix 'z')")
    else:
        checks["vp_proof_type_ok"] = None   # unsigned — not an error, just absent
        checks["vp_proof_purpose_ok"] = None
        checks["vp_proof_value_ok"] = None

    return {"valid": len(errors) == 0, "checks": checks, "errors": errors}


# ── DB cache access ───────────────────────────────────────────────────────────

class VPReconstructor:
    """
    Retrieves or regenerates the W3C VP for an agent.

    The DB is treated as a cache.  If the cache has a fresh VP it is returned
    directly.  Otherwise a new VP is generated (and the cache is updated) via
    VACGenerator.
    """

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _get_db_url()

    def _get_db_connection(self):
        return psycopg2.connect(self.db_url)

    def get_cached_vp(self, agent_id: str) -> Optional[dict]:
        """
        Return the freshest non-revoked, non-expired VP from the DB cache,
        or None if no valid cache entry exists.

        This is a read-only DB operation — it does NOT regenerate anything.
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT vp_document, expires_at
                FROM vac_credentials
                WHERE agent_id = %s
                  AND is_revoked = FALSE
                  AND expires_at > NOW()
                  AND vp_document IS NOT NULL
                ORDER BY issued_at DESC
                LIMIT 1
                """,
                (agent_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            doc = row["vp_document"]
            if isinstance(doc, str):
                return json.loads(doc)
            return dict(doc)
        finally:
            cursor.close()
            conn.close()

    def reconstruct_vp(
        self,
        agent_id: str,
        holder_private_key_hex: Optional[str] = None,
        force_regenerate: bool = False,
    ) -> dict:
        """
        Return the VP for an agent.

        1. If force_regenerate is False and a valid cached VP exists, return it.
        2. Otherwise, generate a fresh VP via VACGenerator (which re-issues the
           VC from live transaction data and writes the new VP to the DB cache).

        Args:
            agent_id: The agent's identifier.
            holder_private_key_hex: If given, the regenerated VP will be signed
                by the agent. Ignored when returning a cached VP.
            force_regenerate: If True, always regenerate regardless of cache.

        Returns:
            W3C VP dict.
        """
        if not force_regenerate:
            cached = self.get_cached_vp(agent_id)
            if cached is not None:
                return cached

        # Cache miss or forced regeneration — generate fresh
        from vac_generator import VACGenerator
        generator = VACGenerator(db_url=self.db_url)
        return generator.generate_vac(
            agent_id,
            holder_private_key_hex=holder_private_key_hex,
        )

    def store_submitted_vp(self, agent_id: str, vp: dict) -> None:
        """
        Persist an agent-submitted VP to the DB cache.

        This is called when an agent POSTs their own VP (e.g. after signing it
        on-device).  The embedded VC is used to populate the legacy stat columns
        so existing queries continue to work.
        """
        import uuid
        from datetime import timedelta

        vcs = vp.get("verifiableCredential", [])
        first_vc = vcs[0] if vcs else {}
        cs = first_vc.get("credentialSubject", {})
        raw_id = first_vc.get("id") or f"urn:uuid:{uuid.uuid4()}"
        # credential_id column is UUID type — strip urn:uuid: prefix if present
        credential_id = raw_id.removeprefix("urn:uuid:")

        now = datetime.now(timezone.utc)
        # Honour expirationDate from the embedded VC; fall back to 7 days
        exp_str = first_vc.get("expirationDate")
        if exp_str:
            try:
                expires_at = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            except ValueError:
                expires_at = now + timedelta(days=7)
        else:
            expires_at = now + timedelta(days=7)

        op_sig = first_vc.get("proof", {}).get("proofValue", "")

        import hashlib
        canonical = json.dumps(first_vc, sort_keys=True, separators=(",", ":"))
        payload_hash = hashlib.sha256(canonical.encode()).hexdigest()

        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO vac_credentials (
                    credential_id, agent_id, vac_version,
                    total_transactions, total_volume_sats, unique_counterparties,
                    rails_used, first_transaction_at, last_transaction_at,
                    issued_at, expires_at, op_signature, vac_payload_hash,
                    vp_document
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (credential_id) DO UPDATE
                    SET vp_document = EXCLUDED.vp_document,
                        issued_at   = EXCLUDED.issued_at,
                        expires_at  = EXCLUDED.expires_at
                """,
                (
                    credential_id,
                    agent_id,
                    "2.0.0",
                    cs.get("totalTransactions", 0),
                    cs.get("totalVolumeSats", 0),
                    cs.get("uniqueCounterparties", 0),
                    cs.get("railsUsed", []),
                    cs.get("firstTransactionAt"),
                    cs.get("lastTransactionAt"),
                    now.isoformat(),
                    expires_at.isoformat(),
                    op_sig,
                    payload_hash,
                    json.dumps(vp),
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()
