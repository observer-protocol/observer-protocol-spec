"""
Remediation routes — magic link generation, verification, and credential retrieval.

Implements the AIP v0.5.1 magic link package spec for the chargeback prevention flow.
The agent is the courier: OP generates the signed magic link JWT, the counterparty
wraps it in the soft-reject AIP response, and the agent forwards it to its human.
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import psycopg2.extras
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])

_get_db_connection = None


def configure(get_db_connection_fn):
    global _get_db_connection
    _get_db_connection = get_db_connection_fn


# ── Models ───────────────────────────────────────────────────

class MagicLinkRequest(BaseModel):
    agent_id: str
    counterparty_did: str
    counterparty_name: str
    amount: str
    currency: str
    rail: str
    purchase_description: str
    intro: Optional[str] = None
    ttl_minutes: Optional[int] = 15


class MagicLinkVerifyRequest(BaseModel):
    token: str


class CredentialStoreRequest(BaseModel):
    credential: dict


# ── JWT signing (EdDSA / Ed25519) ────────────────────────────

def _load_signing_key():
    """Load OP's Ed25519 signing key for JWT signing."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_hex = os.environ.get("OP_SIGNING_KEY")
    if not key_hex:
        raise RuntimeError("OP_SIGNING_KEY not set")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))


def _op_did() -> str:
    did = os.environ.get("OP_DID")
    if not did:
        raise RuntimeError("OP_DID not set")
    return did


def _sign_jwt(payload: dict) -> str:
    """Sign a JWT with OP's Ed25519 key (EdDSA algorithm)."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = _load_signing_key()
    return pyjwt.encode(payload, key, algorithm="EdDSA")


def _verify_jwt(token: str) -> dict:
    """Verify and decode a JWT signed with OP's Ed25519 key."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = _load_signing_key()
    public_key = key.public_key()
    return pyjwt.decode(token, public_key, algorithms=["EdDSA"])


# ── Endpoints ────────────────────────────────────────────────

@router.post("/magic-link")
def generate_magic_link(req: MagicLinkRequest):
    """
    Generate a signed magic link JWT for agent-to-human authorization.

    Called by the counterparty (e.g. NeuralBridge) when an agent lacks a
    delegation credential. The counterparty wraps the returned package in
    its AIP soft-reject response. The agent forwards the magic link to its
    human via the agent's configured comms channel.

    The intro field is a default message the agent can forward verbatim or
    adapt for its specific comms style. The agent owns delivery.
    """
    conn = _get_db_connection()
    cur = conn.cursor()
    try:
        jti = f"mlk_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=req.ttl_minutes or 15)

        # Look up agent DID
        cur.execute(
            "SELECT agent_did FROM observer_agents WHERE agent_id = %s",
            (req.agent_id,)
        )
        row = cur.fetchone()
        agent_did = row[0] if row else f"did:web:observerprotocol.org:agents:{req.agent_id}"

        transaction_context = {
            "counterparty": req.counterparty_name,
            "counterparty_did": req.counterparty_did,
            "amount": req.amount,
            "currency": req.currency,
            "rail": req.rail,
            "purchase_description": req.purchase_description,
        }

        # Default intro if not provided
        intro = req.intro or (
            f"I tried to purchase ${req.amount} in {req.purchase_description} "
            f"from {req.counterparty_name} and need your authorization. "
            f"Tap here to approve:"
        )

        # JWT payload
        # JWT issuer: did:web:observerprotocol.org (OP's key — asserts magic link legitimacy)
        # Delegation credential issuer will be the user's DID (principal's key — asserts authorization)
        # These are intentionally different issuers. Do not collapse.
        jwt_payload = {
            "iss": _op_did(),
            "sub": agent_did,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "type": "magic_link",
            "transaction": transaction_context,
            "intro": intro,
            "agent_id": req.agent_id,
        }

        token = _sign_jwt(jwt_payload)

        # Store in DB for single-use enforcement
        cur.execute("""
            INSERT INTO magic_link_tokens
                (jti, agent_id, agent_did, counterparty_did, counterparty_name,
                 transaction_context, intro, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            jti, req.agent_id, agent_did, req.counterparty_did,
            req.counterparty_name, json.dumps(transaction_context),
            intro, expires_at,
        ))
        conn.commit()

        sovereign_base = os.environ.get(
            "SOVEREIGN_BASE_URL",
            "https://app.agenticterminal.io"
        )

        return {
            "token": token,
            "url": f"{sovereign_base}/sovereign/authorize?token={token}",
            "intro": intro,
            "transaction_context": transaction_context,
            "expires_at": expires_at.isoformat(),
            "jti": jti,
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.post("/verify-magic-link")
def verify_magic_link(req: MagicLinkVerifyRequest):
    """
    Verify a magic link JWT and return the decoded payload.

    Called by the Sovereign authorize page to validate the token before
    rendering the authorization options.
    """
    try:
        payload = _verify_jwt(req.token)
    except Exception as e:
        return {"valid": False, "payload": None, "error": f"Invalid token: {str(e)}"}

    jti = payload.get("jti")
    if not jti:
        return {"valid": False, "payload": None, "error": "Missing JTI"}

    # Check single-use and expiry in DB
    conn = _get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(
            "SELECT redeemed_at, declined_at, expires_at FROM magic_link_tokens WHERE jti = %s",
            (jti,)
        )
        row = cur.fetchone()
        if not row:
            return {"valid": False, "payload": None, "error": "Token not found"}
        if row["redeemed_at"]:
            return {"valid": False, "payload": None, "error": "Token already redeemed"}
        if row["declined_at"]:
            return {"valid": False, "payload": None, "error": "Token was declined"}
        if row["expires_at"] < datetime.now(timezone.utc):
            return {"valid": False, "payload": None, "error": "Token expired"}

        return {
            "valid": True,
            "payload": {
                "jti": jti,
                "agent_id": payload.get("agent_id"),
                "agent_did": payload.get("sub"),
                "transaction": payload.get("transaction"),
                "intro": payload.get("intro"),
                "expires_at": payload.get("exp"),
            },
        }
    finally:
        cur.close()
        conn.close()


@router.post("/{jti}/credential")
def store_credential(
    jti: str,
    req: CredentialStoreRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Store a signed delegation credential after human authorization.

    Called by the Sovereign authorize page after the human approves.
    The original magic link JWT is passed in the Authorization header
    to prove the caller has the token.

    The delegation credential issuer is the user's DID (principal's key),
    NOT OP's DID. OP only signs the magic link JWT.
    """
    # Verify the bearer token is the original magic link JWT
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization required")

    token = authorization.replace("Bearer ", "")
    try:
        payload = _verify_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authorization token")

    if payload.get("jti") != jti:
        raise HTTPException(status_code=403, detail="Token JTI mismatch")

    conn = _get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Check token is still valid and unredeemed
        cur.execute(
            "SELECT redeemed_at, expires_at FROM magic_link_tokens WHERE jti = %s",
            (jti,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Token not found")
        if row["redeemed_at"]:
            raise HTTPException(status_code=409, detail="Token already redeemed")
        if row["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=410, detail="Token expired")

        # Store credential and mark redeemed
        cur.execute("""
            UPDATE magic_link_tokens
            SET credential_json = %s, redeemed_at = NOW()
            WHERE jti = %s
        """, (json.dumps(req.credential), jti))
        conn.commit()

        return {"stored": True, "jti": jti}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.get("/{jti}/credential")
def retrieve_credential(jti: str):
    """
    Retrieve a delegation credential by JTI.

    Polled by the agent after forwarding the magic link to its human.
    The JTI is a capability token (unguessable UUID) — no additional
    authentication required. The agent already has the JTI from the
    magic link package in the soft-reject response.

    Returns:
        202 — pending (human hasn't authorized yet)
        200 — authorized (credential available)
        410 — expired (magic link expired without authorization)
        200 with status=declined — human declined
    """
    conn = _get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT credential_json, redeemed_at, declined_at, expires_at
            FROM magic_link_tokens WHERE jti = %s
        """, (jti,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Token not found")

        if row["declined_at"]:
            return {"status": "declined", "message": "Human declined authorization"}

        if row["redeemed_at"] and row["credential_json"]:
            return {
                "status": "authorized",
                "credential": row["credential_json"],
                "authorized_at": row["redeemed_at"].isoformat(),
            }

        if row["expires_at"] < datetime.now(timezone.utc):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=410,
                content={"status": "expired", "message": "Magic link expired without authorization"},
                headers={"Retry-After": "0"},
            )

        # Still pending
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=202,
            content={"status": "pending", "message": "Awaiting human authorization"},
            headers={"Retry-After": "5"},
        )

    finally:
        cur.close()
        conn.close()


@router.post("/{jti}/decline")
def decline_authorization(jti: str):
    """Mark a magic link as declined by the human."""
    conn = _get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE magic_link_tokens SET declined_at = NOW()
            WHERE jti = %s AND redeemed_at IS NULL
        """, (jti,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Token not found or already redeemed")
        conn.commit()
        return {"declined": True, "jti": jti}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()
