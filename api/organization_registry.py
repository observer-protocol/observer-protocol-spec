#!/usr/bin/env python3
"""
Organization Registry — Observer Protocol
Manages organization registration, DID generation, key storage, and lifecycle.
Organizations are credential issuers, not agents.
"""

import hashlib
import json
import os
import re
from datetime import datetime
from typing import Optional, Dict, Any

import psycopg2
import psycopg2.extras

from did_document_builder import build_org_did, build_org_did_document


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Set it to a valid PostgreSQL connection string."
        )
    return url


class OrganizationRegistryError(Exception):
    pass


class OrganizationAlreadyExistsError(OrganizationRegistryError):
    pass


class OrganizationNotFoundError(OrganizationRegistryError):
    pass


class OrganizationRevokedError(OrganizationRegistryError):
    pass


class OrganizationRegistry:
    """
    Manages the organization registry for Observer Protocol.

    Organizations are credential issuers (not agents) that can:
    - Issue attestations that agents include in their VAC credentials
    - Sign credentials on behalf of their domain
    - Revoke their own credentials if compromised

    Each organization gets a did:web DID on registration.
    The DID Document is stored in the DB and served at GET /orgs/{org_id}/did.json.
    """

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _get_db_url()

    def _get_db_connection(self):
        return psycopg2.connect(self.db_url)

    def _compute_public_key_hash(self, public_key: str) -> str:
        normalized = public_key.lower().replace("0x", "")
        return hashlib.sha256(normalized.encode()).hexdigest()

    def _validate_domain(self, domain: str) -> str:
        domain = domain.lower().strip()
        if "." not in domain or len(domain) < 4:
            raise ValueError(f"Invalid domain format: {domain}")
        if not re.match(r"^[a-z0-9][a-z0-9-]*\.[a-z]{2,}$", domain):
            raise ValueError(f"Domain must be a valid format (e.g., example.com): {domain}")
        return domain

    def register_organization(
        self,
        name: str,
        domain: str,
        master_public_key: str,
        revocation_public_key: str,
        key_type: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        contact_email: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Register a new organization.

        Generates a did:web DID and DID Document using the master public key.
        The org_id returned by the DB becomes part of the DID path.

        Raises:
            OrganizationAlreadyExistsError: Duplicate domain or key hash.
            ValueError: Validation failure.
        """
        domain = self._validate_domain(domain)
        master_public_key = master_public_key.lower().replace("0x", "")
        revocation_public_key = revocation_public_key.lower().replace("0x", "")

        if master_public_key == revocation_public_key:
            raise ValueError("Master and revocation public keys must be different")

        master_key_hash = self._compute_public_key_hash(master_public_key)
        revocation_key_hash = self._compute_public_key_hash(revocation_public_key)

        if not display_name:
            display_name = name

        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            # Insert without DID first so we get the org_id from the DB
            cursor.execute(
                """
                INSERT INTO organizations (
                    name, domain, display_name, description,
                    master_public_key, master_public_key_hash,
                    revocation_public_key, revocation_public_key_hash,
                    key_type, contact_email, metadata,
                    status, verification_status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', 'self_attested')
                RETURNING org_id, name, domain, registered_at
                """,
                (
                    name, domain, display_name, description,
                    master_public_key, master_key_hash,
                    revocation_public_key, revocation_key_hash,
                    key_type, contact_email, json.dumps(metadata or {}),
                ),
            )
            result = cursor.fetchone()
            org_id = str(result["org_id"])

            # Generate DID and DID Document now that we have the org_id
            org_did = build_org_did(org_id)
            try:
                did_document = build_org_did_document(org_id, master_public_key)
            except Exception:
                # key_type may be secp256k1 — still record the DID, no document yet
                did_document = None

            cursor.execute(
                """
                UPDATE organizations
                SET org_did = %s, did_document = %s
                WHERE org_id = %s
                """,
                (org_did, json.dumps(did_document) if did_document else None, org_id),
            )
            conn.commit()

            response: Dict[str, Any] = {
                "org_id": org_id,
                "org_did": org_did,
                "name": result["name"],
                "domain": result["domain"],
                "master_public_key_hash": master_key_hash,
                "revocation_public_key_hash": revocation_key_hash,
                "key_type": key_type,
                "status": "active",
                "verification_status": "self_attested",
                "registered_at": result["registered_at"].isoformat(),
                "message": (
                    "Organization registered successfully. "
                    "Note: This is a self-attested registration. "
                    "OP does not verify real-world identity at this stage."
                ),
            }
            if did_document:
                response["did_document"] = did_document
            return response

        except psycopg2.IntegrityError as e:
            conn.rollback()
            msg = str(e).lower()
            if "domain" in msg:
                raise OrganizationAlreadyExistsError(
                    f"Organization with domain '{domain}' already exists"
                )
            if "master_public_key_hash" in msg:
                raise OrganizationAlreadyExistsError(
                    "Organization with this master public key already exists"
                )
            if "revocation_public_key_hash" in msg:
                raise OrganizationAlreadyExistsError(
                    "Organization with this revocation public key already exists"
                )
            raise OrganizationAlreadyExistsError(f"Organization already exists: {e}")
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def get_organization(self, org_id: str, include_public_keys: bool = False) -> Dict[str, Any]:
        """Get organization by ID."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if include_public_keys:
                cursor.execute(
                    """
                    SELECT org_id, name, domain, display_name, description,
                           org_did, did_document,
                           master_public_key, master_public_key_hash,
                           revocation_public_key, revocation_public_key_hash,
                           key_type, status, verification_status,
                           registered_at, updated_at, revoked_at, metadata
                    FROM organizations WHERE org_id = %s
                    """,
                    (org_id,),
                )
            else:
                cursor.execute(
                    """
                    SELECT org_id, name, domain, display_name, description,
                           org_did, did_document,
                           master_public_key_hash, revocation_public_key_hash,
                           key_type, status, verification_status,
                           registered_at, updated_at, revoked_at, metadata
                    FROM organizations WHERE org_id = %s
                    """,
                    (org_id,),
                )
            row = cursor.fetchone()
            if not row:
                raise OrganizationNotFoundError(f"Organization '{org_id}' not found")
            return self._format_org_row(dict(row))
        finally:
            cursor.close()
            conn.close()

    def get_organization_by_domain(self, domain: str) -> Dict[str, Any]:
        """Get organization by domain."""
        domain = self._validate_domain(domain)
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT org_id, name, domain, display_name, description,
                       org_did, did_document,
                       master_public_key_hash, revocation_public_key_hash,
                       key_type, status, verification_status,
                       registered_at, updated_at, revoked_at, metadata
                FROM organizations WHERE domain = %s
                """,
                (domain,),
            )
            row = cursor.fetchone()
            if not row:
                raise OrganizationNotFoundError(f"Organization with domain '{domain}' not found")
            return self._format_org_row(dict(row))
        finally:
            cursor.close()
            conn.close()

    def get_organization_by_key_hash(self, key_hash: str) -> Dict[str, Any]:
        """Get organization by public key hash (master or revocation)."""
        key_hash = key_hash.lower().replace("0x", "")
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                """
                SELECT org_id, name, domain, display_name, description,
                       org_did, did_document,
                       master_public_key_hash, revocation_public_key_hash,
                       key_type, status, verification_status,
                       registered_at, updated_at, revoked_at, metadata
                FROM organizations
                WHERE master_public_key_hash = %s OR revocation_public_key_hash = %s
                """,
                (key_hash, key_hash),
            )
            row = cursor.fetchone()
            if not row:
                raise OrganizationNotFoundError(f"Organization with key hash '{key_hash}' not found")
            return self._format_org_row(dict(row))
        finally:
            cursor.close()
            conn.close()

    def list_organizations(
        self,
        status: Optional[str] = "active",
        verification_status: Optional[str] = None,
        domain_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List organizations with optional filtering."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            where_clauses = []
            params: list = []

            if status and status != "all":
                where_clauses.append("status = %s")
                params.append(status)
            if verification_status and verification_status != "all":
                where_clauses.append("verification_status = %s")
                params.append(verification_status)
            if domain_filter:
                where_clauses.append("domain ILIKE %s")
                params.append(f"%{domain_filter}%")

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            cursor.execute(f"SELECT COUNT(*) FROM organizations {where_sql}", params)
            total_count = cursor.fetchone()["count"]

            cursor.execute(
                f"""
                SELECT org_id, name, domain, display_name, description,
                       org_did,
                       master_public_key_hash, revocation_public_key_hash,
                       key_type, status, verification_status,
                       registered_at, metadata
                FROM organizations
                {where_sql}
                ORDER BY registered_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )

            organizations = [self._format_org_row(dict(row)) for row in cursor.fetchall()]
            return {
                "organizations": organizations,
                "count": len(organizations),
                "total": total_count,
                "limit": limit,
                "offset": offset,
            }
        finally:
            cursor.close()
            conn.close()

    def revoke_organization(
        self,
        org_id: str,
        reason: str,
        revocation_signature: Optional[str] = None,
        revoked_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Revoke an organization (soft delete)."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(
                "SELECT status FROM organizations WHERE org_id = %s", (org_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise OrganizationNotFoundError(f"Organization '{org_id}' not found")
            if row["status"] == "revoked":
                raise OrganizationRevokedError(f"Organization '{org_id}' is already revoked")

            cursor.execute(
                """
                UPDATE organizations
                SET status = 'revoked',
                    revoked_at = NOW(),
                    revocation_reason = %s,
                    updated_at = NOW()
                WHERE org_id = %s
                RETURNING org_id, revoked_at
                """,
                (reason, org_id),
            )
            result = cursor.fetchone()
            conn.commit()
            return {
                "org_id": str(result["org_id"]),
                "status": "revoked",
                "revoked_at": result["revoked_at"].isoformat(),
                "reason": reason,
                "message": "Organization revoked. All credentials issued by this organization are now invalid.",
            }
        except (OrganizationNotFoundError, OrganizationRevokedError):
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _format_org_row(self, row: dict) -> dict:
        """Normalize DB row to a clean dict for API responses."""
        row["org_id"] = str(row["org_id"])
        for key in ("registered_at", "updated_at", "revoked_at"):
            if row.get(key):
                row[key] = row[key].isoformat()
        if row.get("metadata"):
            if isinstance(row["metadata"], str):
                row["metadata"] = json.loads(row["metadata"])
        else:
            row["metadata"] = {}
        # did_document may already be a dict from JSONB
        if row.get("did_document") and isinstance(row["did_document"], str):
            row["did_document"] = json.loads(row["did_document"])
        return row
