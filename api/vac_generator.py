#!/usr/bin/env python3
"""
VAC Generator — Observer Protocol (Layer 2 rebuild)

Generates W3C Verifiable Presentations (VPs) containing W3C Verifiable
Credentials (VCs) for agents.  The old custom VACCredential format is
replaced entirely.

Architecture:
  - OP issues and signs each VC (AgentActivityCredential) using vc_issuer.
  - vp_builder assembles the VP.  The VP is unsigned by default; the agent
    can sign it via PUT /agents/{id}/present or via the /vac/{id}/refresh
    endpoint if a private key is provided.
  - DB stores the VP document as cache.  It is not the authoritative record
    (Layer 3 promotes the VP to be the truth; DB becomes read-through cache).

Environment variables required:
    DATABASE_URL    PostgreSQL connection string
    OP_SIGNING_KEY  Hex-encoded Ed25519 private key (64 hex chars)
    OP_DID          OP's DID string
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple, Dict, Any

import psycopg2
import psycopg2.extras

from vc_issuer import issue_vc
from vp_builder import build_vp
from did_document_builder import build_agent_did

VAC_MAX_AGE_DAYS = 7
VAC_REFRESH_HOURS = 24


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return url


class VACGenerator:
    """
    Generates W3C VPs (Verified Agent Credentials) for agents.

    Replaces the old custom VACCredential format with W3C-conformant VPs.
    """

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _get_db_url()

    def _get_db_connection(self):
        return psycopg2.connect(self.db_url)

    # ── Data aggregation (unchanged logic, fixed DB connection) ──────────────

    def _aggregate_core_fields(self, agent_id: str) -> Dict[str, Any]:
        """Aggregate verified transaction data for an agent."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_transactions,
                    COALESCE(SUM(
                        CASE WHEN metadata->>'amount_sats' IS NOT NULL
                             THEN (metadata->>'amount_sats')::bigint
                             ELSE 0 END
                    ), 0) AS total_volume_sats,
                    COUNT(DISTINCT counterparty_id) AS unique_counterparties
                FROM verified_events
                WHERE agent_id = %s AND verified = TRUE
                """,
                (agent_id,),
            )
            agg = cursor.fetchone()

            cursor.execute(
                "SELECT DISTINCT protocol FROM verified_events WHERE agent_id = %s AND verified = TRUE",
                (agent_id,),
            )
            rails = [row["protocol"] for row in cursor.fetchall()]

            cursor.execute(
                """
                SELECT MIN(created_at) AS first_transaction,
                       MAX(created_at) AS last_transaction
                FROM verified_events
                WHERE agent_id = %s AND verified = TRUE
                """,
                (agent_id,),
            )
            ts = cursor.fetchone()

            return {
                "totalTransactions": int(agg["total_transactions"] or 0),
                "totalVolumeSats": int(agg["total_volume_sats"] or 0),
                "uniqueCounterparties": int(agg["unique_counterparties"] or 0),
                "railsUsed": rails,
                **(
                    {"firstTransactionAt": ts["first_transaction"].isoformat()}
                    if ts and ts["first_transaction"] else {}
                ),
                **(
                    {"lastTransactionAt": ts["last_transaction"].isoformat()}
                    if ts and ts["last_transaction"] else {}
                ),
            }
        finally:
            cursor.close()
            conn.close()

    def _load_partner_attestations(
        self, agent_id: str, credential_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Load partner attestations for an agent."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT pa.attestation_id, pa.claims, pa.issued_at, pa.expires_at,
                       pr.partner_id, pr.partner_name, pr.partner_type
                FROM partner_attestations pa
                JOIN partner_registry pr ON pr.partner_id = pa.partner_id
                JOIN vac_credentials vc ON vc.credential_id = pa.credential_id
                WHERE vc.agent_id = %s
                  AND vc.is_revoked = FALSE
                  AND (pa.expires_at IS NULL OR pa.expires_at > NOW())
                ORDER BY pa.issued_at DESC
                """,
                (agent_id,),
            )
            attestations = []
            for row in cursor.fetchall():
                a: Dict[str, Any] = {
                    "partnerId": str(row["partner_id"]),
                    "partnerName": row["partner_name"],
                    "partnerType": row["partner_type"],
                    "claims": row["claims"],
                    "issuedAt": row["issued_at"].isoformat(),
                }
                if row["expires_at"]:
                    a["expiresAt"] = row["expires_at"].isoformat()
                attestations.append(a)
            return attestations
        finally:
            cursor.close()
            conn.close()

    def _get_agent_did(self, agent_id: str) -> str:
        """Look up the agent's DID from the DB, falling back to derived DID."""
        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT agent_did FROM observer_agents WHERE agent_id = %s", (agent_id,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                return row[0]
        finally:
            cursor.close()
            conn.close()
        return build_agent_did(agent_id)

    # ── Core generation ───────────────────────────────────────────────────────

    def generate_vac(
        self,
        agent_id: str,
        include_extensions: bool = True,
        holder_private_key_hex: Optional[str] = None,
    ) -> dict:
        """
        Generate a W3C VP (Verified Agent Credential) for an agent.

        Issues one AgentActivityCredential VC signed by OP, assembles a VP,
        stores it in the DB, and returns the VP dict.

        Args:
            agent_id: The agent's identifier.
            include_extensions: Whether to include partner attestation claims.
            holder_private_key_hex: If given, the VP is signed by the agent.

        Returns:
            W3C VP dict.
        """
        agent_did = self._get_agent_did(agent_id)

        # Build credentialSubject claims
        claims = self._aggregate_core_fields(agent_id)

        if include_extensions:
            attestations = self._load_partner_attestations(agent_id)
            if attestations:
                claims["partnerAttestations"] = attestations

        # Issue the VC (OP-signed)
        vc = issue_vc(
            subject_did=agent_did,
            credential_type="AgentActivityCredential",
            claims=claims,
            expiration_days=VAC_MAX_AGE_DAYS,
        )

        # Assemble the VP (optionally agent-signed)
        vp = build_vp(
            holder_did=agent_did,
            vcs=[vc],
            holder_private_key_hex=holder_private_key_hex,
        )

        # Persist to DB
        self._store_vp(vc, vp, agent_id)

        return vp

    def get_vac(self, agent_id: str) -> Optional[dict]:
        """
        Retrieve the active W3C VP for an agent from the DB cache.

        Returns the VP dict if found and not expired, else None.
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT vp_document, credential_id, expires_at
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

    def _store_vp(self, vc: dict, vp: dict, agent_id: str) -> None:
        """Store the W3C VP in vac_credentials."""
        # Extract stats from the VC's credentialSubject for legacy columns
        cs = vc.get("credentialSubject", {})
        raw_id = vc.get("id") or f"urn:uuid:{uuid.uuid4()}"
        # credential_id column is UUID type — strip urn:uuid: prefix if present
        credential_id = raw_id.removeprefix("urn:uuid:")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=VAC_MAX_AGE_DAYS)
        # Use expirationDate from VC if present
        exp_str = vc.get("expirationDate")
        if exp_str:
            try:
                expires_at = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            except ValueError:
                pass

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
                    vc.get("proof", {}).get("proofValue", ""),
                    _hash_document(vc),
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

    def verify_vac(self, vp: dict) -> bool:
        """
        Verify the VC(s) inside a VP against OP's public key.

        Returns True only if ALL embedded VCs have valid Ed25519Signature2020 proofs.
        """
        from vc_verifier import verify_vc
        op_public_key = os.environ.get("OP_PUBLIC_KEY")
        if not op_public_key:
            raise RuntimeError("OP_PUBLIC_KEY environment variable is not set.")
        for vc in vp.get("verifiableCredential", []):
            ok, _reason = verify_vc(vc, op_public_key)
            if not ok:
                return False
        return True

    def revoke_vac(
        self,
        credential_id: str,
        reason: str,
        revoked_by: Optional[str] = None,
    ) -> None:
        """Revoke a VAC credential (soft delete)."""
        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE vac_credentials
                SET is_revoked = TRUE, revoked_at = NOW(), revocation_reason = %s
                WHERE credential_id = %s
                RETURNING agent_id
                """,
                (reason, credential_id),
            )
            result = cursor.fetchone()
            if not result:
                raise ValueError(f"Credential {credential_id} not found")
            agent_id = result[0]
            cursor.execute(
                """
                INSERT INTO vac_revocation_registry (credential_id, agent_id, revoked_by, reason)
                VALUES (%s, %s, %s, %s)
                """,
                (credential_id, agent_id, revoked_by, reason),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()


def _hash_document(doc: dict) -> str:
    import hashlib
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def refresh_all_vacs() -> int:
    """Refresh all VACs older than VAC_REFRESH_HOURS."""
    generator = VACGenerator()
    conn = psycopg2.connect(_get_db_url())
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT DISTINCT agent_id FROM observer_agents
            WHERE agent_id NOT IN (
                SELECT agent_id FROM vac_credentials
                WHERE is_revoked = FALSE
                  AND issued_at > NOW() - INTERVAL '%s hours'
            ) AND verified = TRUE
            """,
            (VAC_REFRESH_HOURS,),
        )
        agents = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    refreshed = 0
    for (agent_id,) in agents:
        try:
            generator.generate_vac(agent_id)
            refreshed += 1
        except Exception as exc:
            print(f"Failed to refresh VAC for {agent_id}: {exc}")
    print(f"Refreshed {refreshed} VACs")
    return refreshed
