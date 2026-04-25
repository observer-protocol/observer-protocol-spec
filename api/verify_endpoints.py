"""
AT Verify Production Endpoints

POST /v1/chain/verify       — Chain-agnostic transaction verification
POST /v1/audit/verified-event — Write verified event to audit trail

These are integrator-facing API surfaces. See CHAIN-ADAPTER-SPEC.md.

Integrator authentication via API key against integrator_registry table.
Idempotency keyed on receipt_reference (receipt UUID).
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

# Import chain adapters at module level — registration happens once at startup
from chain_adapter import get_adapter, get_supported_chains
try:
    import lightning_adapter  # noqa: F401 — registers LightningAdapter
except ImportError:
    pass
try:
    import stacks_adapter  # noqa: F401 — registers StacksAdapter
except ImportError:
    pass

router = APIRouter()


# ── Pydantic Models ───────────────────────────────────────────

# Chain verify models
class ChainTransactionAmount(BaseModel):
    value: str
    currency: str


class ChainTransaction(BaseModel):
    reference: Optional[str] = None
    amount: Optional[ChainTransactionAmount] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None


class ChainVerifyRequest(BaseModel):
    receipt_reference: str
    chain: str
    transaction: Optional[ChainTransaction] = None
    chain_specific: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Audit models
class AuditAgent(BaseModel):
    did: Optional[str] = None
    agent_id: str


class AuditTransactionAmount(BaseModel):
    value: str
    currency: str


class AuditCounterparty(BaseModel):
    identifier: Optional[str] = None
    display_name: Optional[str] = None


class AuditTransaction(BaseModel):
    amount: AuditTransactionAmount
    category: str
    counterparty: Optional[AuditCounterparty] = None
    rail: Optional[str] = None
    integrator_reference: Optional[str] = None


class AuditSettlementReference(BaseModel):
    transaction_hash: Optional[str] = None
    rail: Optional[str] = None
    settled_at: Optional[str] = None


class AuditVerification(BaseModel):
    verdict: str = "approved"
    delegation_id: Optional[str] = None
    verified_at: Optional[str] = None


class AuditEventRequest(BaseModel):
    receipt_reference: str
    agent: AuditAgent
    transaction: AuditTransaction
    settlement_reference: Optional[AuditSettlementReference] = None
    verification: Optional[AuditVerification] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── Database ──────────────────────────────────────────────────

def _get_db():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(database_url)


def _get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


# ── Integrator Auth ───────────────────────────────────────────

def _validate_integrator_key(authorization: str) -> dict:
    """Validate Bearer API key against integrator_registry. Returns integrator record."""
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
            raise HTTPException(status_code=401, detail={"error": "unauthorized", "detail": "Integrator account is inactive"})
        return dict(row)
    finally:
        cursor.close()
        conn.close()


# ── POST /v1/chain/verify ─────────────────────────────────────

@router.post("/v1/chain/verify")
def chain_verify(
    request: ChainVerifyRequest,
    authorization: str = Header(None),
):
    """
    Verify a transaction on any supported chain.
    Chain-agnostic dispatch to the registered ChainAdapter.
    Idempotent on receipt_reference. Chain mismatch = 409.
    """
    integrator = _validate_integrator_key(authorization)

    adapter = get_adapter(request.chain)
    if not adapter:
        raise HTTPException(status_code=400, detail={
            "error": "unsupported_chain",
            "detail": f"Chain '{request.chain}' is not supported. Supported: {get_supported_chains()}",
        })

    conn = _get_db()
    cursor = _get_cursor(conn)
    try:
        # Check idempotency
        cursor.execute(
            "SELECT * FROM chain_verifications WHERE receipt_reference = %s",
            (request.receipt_reference,),
        )
        existing = cursor.fetchone()

        if existing:
            # Chain mismatch detection
            if existing["chain"] != request.chain:
                raise HTTPException(status_code=409, detail={
                    "error": "chain_mismatch",
                    "detail": f"Receipt already verified on chain '{existing['chain']}', not '{request.chain}'",
                })

            if existing["status"] == "verified":
                return {
                    "verified": True,
                    "receipt_reference": request.receipt_reference,
                    "chain": existing["chain"],
                    "transaction_reference": existing["transaction_reference"],
                    "explorer_url": existing["explorer_url"],
                    "confirmed_at": existing["confirmed_at"].isoformat() if existing["confirmed_at"] else None,
                    "chain_specific": existing["chain_specific"] or {},
                    "idempotent_replay": True,
                }
            elif existing["status"] == "pending":
                raise HTTPException(status_code=409, detail={
                    "error": "verification_in_progress",
                    "detail": "Verification for this receipt is already in progress",
                })
            # status == 'failed': allow retry
            cursor.execute(
                "DELETE FROM chain_verifications WHERE receipt_reference = %s",
                (request.receipt_reference,),
            )
            conn.commit()

        # Insert pending record
        cursor.execute(
            """
            INSERT INTO chain_verifications
                (receipt_reference, integrator_id, chain, amount, currency, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            """,
            (
                request.receipt_reference,
                integrator["integrator_id"],
                request.chain,
                request.transaction.amount.value if request.transaction and request.transaction.amount else None,
                request.transaction.amount.currency if request.transaction and request.transaction.amount else None,
            ),
        )
        conn.commit()

        # Dispatch to adapter
        tx_dict = {}
        if request.transaction:
            tx_dict = request.transaction.model_dump(exclude_none=True)

        result = adapter.verify_transaction(tx_dict, request.chain_specific)

        if result.verified:
            cursor.execute(
                """
                UPDATE chain_verifications
                SET status = 'verified',
                    transaction_reference = %s,
                    explorer_url = %s,
                    verified = TRUE,
                    verification_tier = %s,
                    chain_specific = %s,
                    confirmed_at = %s
                WHERE receipt_reference = %s
                """,
                (
                    result.transaction_reference,
                    result.explorer_url,
                    result.chain_specific.get("verification_tier"),
                    json.dumps(result.chain_specific),
                    result.confirmed_at,
                    request.receipt_reference,
                ),
            )
        else:
            cursor.execute(
                """
                UPDATE chain_verifications
                SET status = 'failed',
                    error_detail = %s,
                    chain_specific = %s
                WHERE receipt_reference = %s
                """,
                (
                    result.error,
                    json.dumps(result.chain_specific),
                    request.receipt_reference,
                ),
            )
        conn.commit()

        if not result.verified:
            raise HTTPException(status_code=422, detail={
                "error": "verification_failed",
                "detail": result.error,
                "chain": request.chain,
                "receipt_reference": request.receipt_reference,
            })

        return {
            "verified": True,
            "receipt_reference": request.receipt_reference,
            "chain": request.chain,
            "transaction_reference": result.transaction_reference,
            "explorer_url": result.explorer_url,
            "confirmed_at": result.confirmed_at,
            "chain_specific": result.chain_specific,
            "idempotent_replay": False,
        }

    finally:
        cursor.close()
        conn.close()


# ── POST /v1/audit/verified-event ─────────────────────────────

def _amount_bucket(value_str: str) -> str:
    """Determine amount bucket from transaction value."""
    try:
        val = float(value_str)
        if val < 1:
            return "micro"
        elif val < 10:
            return "small"
        elif val < 100:
            return "medium"
        else:
            return "large"
    except (ValueError, TypeError):
        return "unknown"


@router.post("/v1/audit/verified-event", status_code=201)
def audit_verified_event(
    request: AuditEventRequest,
    authorization: str = Header(None),
):
    """
    Write a verified transaction event to the audit trail.
    Dual-write: verified_events (dashboard cache) + agent_activity_credentials (audit SoT).
    Idempotent on receipt_reference.

    Consistency model: soft failure with log. If verified_events write succeeds
    but agent_activity_credentials write fails, log the failure and return success.
    The dashboard works. The audit gap is detectable via audit_coverage_rollup.
    """
    integrator = _validate_integrator_key(authorization)

    conn = _get_db()
    cursor = _get_cursor(conn)
    try:
        # Check idempotency via metadata JSONB
        cursor.execute(
            """
            SELECT event_id FROM verified_events
            WHERE metadata->>'receipt_reference' = %s
            """,
            (request.receipt_reference,),
        )
        existing = cursor.fetchone()
        if existing:
            event_id = existing["event_id"]
            return {
                "status": "exists",
                "event_id": event_id,
                "receipt_reference": request.receipt_reference,
                "dashboard_url": f"https://app.agenticterminal.io/dashboard/events/{event_id}",
                "idempotent_replay": True,
            }

        # Validate agent exists
        cursor.execute(
            "SELECT agent_id FROM observer_agents WHERE agent_id = %s",
            (request.agent.agent_id,),
        )
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail={
                "error": "agent_not_found",
                "detail": f"Agent {request.agent.agent_id} not found in observer_agents",
            })

        # Build event
        event_id = f"evt_{secrets.token_hex(8)}"
        bucket = _amount_bucket(request.transaction.amount.value)

        counterparty_id = None
        if request.transaction.counterparty:
            counterparty_id = request.transaction.counterparty.identifier

        # Build metadata with distinguishability markers
        metadata = {
            "receipt_reference": request.receipt_reference,
            "source": "at-verify",
            "integrator_tier": integrator["tier"],
            "integrator_id": integrator["integrator_id"],
        }
        if request.settlement_reference:
            metadata["settlement"] = {
                "transaction_hash": request.settlement_reference.transaction_hash,
                "rail": request.settlement_reference.rail,
                "settled_at": request.settlement_reference.settled_at,
            }
        if request.verification:
            metadata["verification"] = {
                "verdict": request.verification.verdict,
                "delegation_id": request.verification.delegation_id,
                "verified_at": request.verification.verified_at,
            }
        metadata.update(request.metadata)

        protocol = request.transaction.rail or "at_verify"
        tx_hash = request.settlement_reference.transaction_hash if request.settlement_reference else None

        # Write 1: verified_events (dashboard cache)
        cursor.execute(
            """
            INSERT INTO verified_events
                (event_id, agent_id, counterparty_id, event_type, protocol,
                 transaction_hash, amount_bucket, direction,
                 service_description, metadata, verified)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event_id,
                request.agent.agent_id,
                counterparty_id,
                "at_verify",
                protocol,
                tx_hash,
                bucket,
                "outbound",
                f"AT Verify: {request.transaction.category} ({request.transaction.amount.value} {request.transaction.amount.currency})",
                json.dumps(metadata),
                True,
            ),
        )
        conn.commit()

        # Write 2: agent_activity_credentials (audit SoT) — soft failure
        try:
            now = datetime.now(timezone.utc)
            credential_id = f"urn:uuid:activity-{secrets.token_hex(8)}"
            activity_credential = {
                "type": "at_verify_activity",
                "receipt_reference": request.receipt_reference,
                "event_id": event_id,
                "integrator_id": integrator["integrator_id"],
                "transaction": request.transaction.model_dump(exclude_none=True),
                "verification": request.verification.model_dump(exclude_none=True) if request.verification else None,
                "settlement": request.settlement_reference.model_dump(exclude_none=True) if request.settlement_reference else None,
            }

            cursor.execute(
                """
                INSERT INTO agent_activity_credentials
                    (credential_id, agent_did, activity_type, activity_timestamp,
                     counterparty_did, transaction_rail, transaction_reference,
                     transaction_amount, transaction_currency,
                     delegation_credential_id, credential_jsonld)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (credential_id) DO NOTHING
                """,
                (
                    credential_id,
                    request.agent.did or f"did:web:observerprotocol.org:agents:{request.agent.agent_id}",
                    "at_verify_transaction",
                    now,
                    counterparty_id,
                    request.transaction.rail,
                    tx_hash,
                    float(request.transaction.amount.value) if request.transaction.amount.value else None,
                    request.transaction.amount.currency,
                    request.verification.delegation_id if request.verification else None,
                    json.dumps(activity_credential),
                ),
            )
            conn.commit()
        except Exception as e:
            # Soft failure: log but don't fail the request
            # Dashboard still works via verified_events
            import logging
            logging.getLogger("at-verify").warning(
                f"agent_activity_credentials write failed for {request.receipt_reference}: {e}"
            )

        return {
            "status": "created",
            "event_id": event_id,
            "receipt_reference": request.receipt_reference,
            "dashboard_url": f"https://app.agenticterminal.io/dashboard/events/{event_id}",
            "idempotent_replay": False,
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
