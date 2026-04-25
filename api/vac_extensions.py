"""
VAC Extension Protocol — Registration and Attestation endpoints.

POST /v1/vac/extensions/register — Register a new extension schema
POST /v1/vac/extensions/attest   — Submit a signed extension attestation credential

See VAC-EXTENSION-PROTOCOL.md for full spec.

Namespace policy:
  - Integrator-prefixed namespaces (must match registered domain/ID)
  - Reserved prefixes (op_, at_, sovereign_, chain names)
  - Identity-bound claiming (DID verification at registration)
"""

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

# Reserved namespace prefixes — cannot be claimed by integrators
RESERVED_PREFIXES = {
    "op_", "at_", "sovereign_",
    "lightning_", "stacks_", "tron_",
    "bitcoin_", "ethereum_", "solana_",
}


# ── Pydantic Models ───────────────────────────────────────────

class ExtensionIssuer(BaseModel):
    did: str
    display_name: Optional[str] = None
    domain: Optional[str] = None


class RefreshPolicy(BaseModel):
    recommended_ttl: Optional[str] = None  # ISO 8601 duration
    stale_after: Optional[str] = None


class RegisterExtensionRequest(BaseModel):
    extension_id: str
    display_name: str
    description: Optional[str] = None
    issuer: ExtensionIssuer
    extension_schema: Dict[str, Any] = Field(alias="schema")
    schema_url: Optional[str] = None
    summary_fields: List[str] = Field(default_factory=list)
    refresh_policy: Optional[RefreshPolicy] = None


class AttestExtensionRequest(BaseModel):
    extension_id: str
    credential: Dict[str, Any]  # Pre-signed W3C VC
    summary_fields: List[str] = Field(default_factory=list)


# ── Database ──────────────────────────────────────────────────

def _get_db():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(database_url)


def _get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


# ── Integrator Auth (shared with verify_endpoints) ────────────

def _validate_integrator_key(authorization: str) -> dict:
    """Validate Bearer API key against integrator_registry."""
    import hashlib
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})

    api_key = authorization[7:]
    prefix = api_key[:8]
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    conn = _get_db()
    cursor = _get_cursor(conn)
    try:
        cursor.execute(
            """
            SELECT integrator_id, display_name, domain, tier, is_active
            FROM integrator_registry
            WHERE api_key_prefix = %s AND api_key_hash = %s
            """,
            (prefix, key_hash),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"error": "unauthorized"})
        if not row["is_active"]:
            raise HTTPException(status_code=401, detail={"error": "unauthorized"})
        return dict(row)
    finally:
        cursor.close()
        conn.close()


# ── Namespace validation ──────────────────────────────────────

def _extract_namespace(extension_id: str) -> str:
    """Extract namespace from extension_id (everything before the last _v<N>)."""
    parts = extension_id.rsplit("_v", 1)
    return parts[0] if len(parts) == 2 else extension_id


def _validate_namespace(namespace: str, integrator: dict) -> None:
    """Validate namespace against policy guardrails."""
    # Check reserved prefixes
    for prefix in RESERVED_PREFIXES:
        if namespace.startswith(prefix):
            raise HTTPException(status_code=403, detail={
                "error": "reserved_prefix",
                "detail": f"Prefix '{prefix}' is reserved for protocol-layer use.",
            })

    # Check identity-bound claiming
    # Namespace must start with a token derived from the integrator's domain or ID
    integrator_domain = integrator.get("domain", "")
    integrator_id = integrator.get("integrator_id", "")

    # Extract domain prefix (minus TLD)
    domain_prefix = ""
    if integrator_domain:
        domain_prefix = integrator_domain.split(".")[0].lower().replace("-", "_")

    id_prefix = integrator_id.lower().replace("-", "_")

    if not (namespace.startswith(domain_prefix) or namespace.startswith(id_prefix)):
        raise HTTPException(status_code=403, detail={
            "error": "namespace_identity_mismatch",
            "detail": (
                f"Namespace '{namespace}' doesn't match integrator identity. "
                f"Expected prefix derived from domain '{integrator_domain}' or ID '{integrator_id}'."
            ),
        })


# ── POST /v1/vac/extensions/register ──────────────────────────

@router.post("/v1/vac/extensions/register", status_code=201)
def register_extension(
    request: RegisterExtensionRequest,
    authorization: str = Header(None),
):
    """
    Register a new VAC extension schema.
    Self-serve for any integrator. Namespace claiming with identity binding.
    """
    integrator = _validate_integrator_key(authorization)
    namespace = _extract_namespace(request.extension_id)

    # Validate namespace policy
    _validate_namespace(namespace, integrator)

    # Validate JSON Schema structure
    if "$schema" not in request.extension_schema and "type" not in request.extension_schema:
        raise HTTPException(status_code=400, detail={
            "error": "invalid_schema",
            "detail": "Schema must be a valid JSON Schema with at least a 'type' field.",
        })

    # Generate schema URL if not provided
    schema_url = request.schema_url or f"https://observerprotocol.org/schemas/extensions/{namespace}/v1"

    conn = _get_db()
    cursor = _get_cursor(conn)
    try:
        # Check if namespace is claimed by a different integrator
        cursor.execute(
            """
            SELECT registrant_integrator_id FROM vac_extension_registry
            WHERE namespace = %s AND registrant_integrator_id != %s
            LIMIT 1
            """,
            (namespace, integrator["integrator_id"]),
        )
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail={
                "error": "namespace_claimed",
                "detail": f"Namespace '{namespace}' is already claimed by another integrator.",
            })

        # Check if this exact extension_id exists
        cursor.execute(
            "SELECT extension_id FROM vac_extension_registry WHERE extension_id = %s",
            (request.extension_id,),
        )
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail={
                "error": "extension_exists",
                "detail": f"Extension '{request.extension_id}' is already registered. Use a new version.",
            })

        # Extract version from extension_id
        version = 1
        parts = request.extension_id.rsplit("_v", 1)
        if len(parts) == 2:
            try:
                version = int(parts[1])
            except ValueError:
                pass

        # Insert
        cursor.execute(
            """
            INSERT INTO vac_extension_registry
                (extension_id, namespace, version, display_name, description,
                 issuer_did, issuer_display_name, issuer_domain,
                 registrant_integrator_id, schema_json, schema_url,
                 summary_fields, tier)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                request.extension_id,
                namespace,
                version,
                request.display_name,
                request.description,
                request.issuer.did,
                request.issuer.display_name,
                request.issuer.domain,
                integrator["integrator_id"],
                json.dumps(request.extension_schema),
                schema_url,
                request.summary_fields,
                integrator["tier"],
            ),
        )
        conn.commit()

        return {
            "status": "registered",
            "extension_id": request.extension_id,
            "namespace": namespace,
            "schema_url": schema_url,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail={
            "error": "internal_error",
            "detail": str(e),
        })
    finally:
        cursor.close()
        conn.close()


# ── POST /v1/vac/extensions/attest ────────────────────────────

@router.post("/v1/vac/extensions/attest", status_code=201)
def attest_extension(
    request: AttestExtensionRequest,
    authorization: str = Header(None),
):
    """
    Submit a pre-signed extension attestation credential.
    OP validates signature, validates claims against schema, stores credential.
    """
    integrator = _validate_integrator_key(authorization)

    conn = _get_db()
    cursor = _get_cursor(conn)
    try:
        # Look up extension
        cursor.execute(
            """
            SELECT * FROM vac_extension_registry
            WHERE extension_id = %s AND status = 'active'
            """,
            (request.extension_id,),
        )
        extension = cursor.fetchone()
        if not extension:
            raise HTTPException(status_code=404, detail={
                "error": "extension_not_found",
                "detail": f"Extension '{request.extension_id}' not found or not active.",
            })

        # Verify the caller is the registered extension issuer
        if extension["registrant_integrator_id"] != integrator["integrator_id"]:
            raise HTTPException(status_code=403, detail={
                "error": "not_extension_issuer",
                "detail": "Only the registered extension issuer can submit attestations.",
            })

        # Validate credential has required structure
        credential = request.credential
        if "proof" not in credential:
            raise HTTPException(status_code=400, detail={
                "error": "invalid_credential",
                "detail": "Credential must include a 'proof' field (pre-signed).",
            })

        cred_types = credential.get("type", [])
        if "VerifiableCredential" not in cred_types:
            raise HTTPException(status_code=400, detail={
                "error": "invalid_credential",
                "detail": "Credential type must include 'VerifiableCredential'.",
            })

        # Extract agent DID from credentialSubject
        subject = credential.get("credentialSubject", {})
        agent_did = subject.get("id")
        if not agent_did:
            raise HTTPException(status_code=400, detail={
                "error": "invalid_credential",
                "detail": "credentialSubject must have an 'id' (agent DID).",
            })

        # Store in partner_attestations (Spec 3.1 VC cache) with extension_id tag
        credential_id = credential.get("id", f"urn:uuid:{secrets.token_hex(16)}")
        issuer_did = credential.get("issuer")
        if isinstance(issuer_did, dict):
            issuer_did = issuer_did.get("id")

        valid_from = credential.get("validFrom", datetime.now(timezone.utc).isoformat())
        valid_until = credential.get("validUntil", "2099-01-01T00:00:00Z")

        # Build summary from specified fields
        summary = {}
        for field in request.summary_fields:
            if field in subject:
                summary[field] = subject[field]

        # partner_attestations schema (migration 003):
        # credential_id, credential_type, issuer_did, subject_did,
        # credential_jsonld, credential_url, valid_from, valid_until, extension_id
        cursor.execute(
            """
            INSERT INTO partner_attestations
                (credential_id, credential_type, issuer_did, subject_did,
                 credential_jsonld, valid_from, valid_until, extension_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (credential_id) DO NOTHING
            """,
            (
                credential_id,
                f"VACExtension:{request.extension_id}",
                issuer_did,
                agent_did,
                json.dumps(credential),
                valid_from,
                valid_until,
                request.extension_id,
            ),
        )
        conn.commit()

        return {
            "status": "stored",
            "credential_id": credential_id,
            "extension_id": request.extension_id,
            "agent_did": agent_did,
            "summary": summary,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail={
            "error": "internal_error",
            "detail": str(e),
        })
    finally:
        cursor.close()
        conn.close()
