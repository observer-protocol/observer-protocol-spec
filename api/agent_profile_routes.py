"""
Spec 3.7 — Agent Profile endpoints.

Three new endpoints:
  GET /api/v1/agents/{agent_id}/profile       — aggregation endpoint (public + auth)
  GET /api/v1/agents/{agent_id}/counterparties — per-agent counterparty list
  GET /api/v1/trust/score/{agent_id}           — generalized trust score

Public callers (no session) get a privacy-safe subset.
Authenticated callers (enterprise session for the agent's org) get the full
dataset plus a permissions array for admin action gating.
"""

import json
import os
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import JSONResponse


router = APIRouter()

_get_db_connection = None
_validate_session = None  # Returns (user_id, org_id, email, role) or raises


def configure(get_db_connection_fn, validate_session_fn):
    global _get_db_connection, _validate_session
    _get_db_connection = get_db_connection_fn
    _validate_session = validate_session_fn


def _require_configured():
    if _get_db_connection is None:
        raise RuntimeError("agent_profile_routes not configured")


def _get_session_or_none(request: Request) -> Optional[tuple]:
    """Try to get session; return None if no session (public caller)."""
    try:
        return _validate_session(request)
    except HTTPException:
        return None


def _get_permissions(role: str) -> list:
    """Map role to permitted admin actions for frontend button gating."""
    from role_enforcement import ROLE_HIERARCHY
    level = ROLE_HIERARCHY.get(role.lower() if role else "", 0)
    perms = []
    if level >= 1:  # operator+
        perms.extend(["register_agent", "update_agent", "submit_transaction", "cache_attestation"])
    if level >= 2:  # admin+
        perms.extend(["approve_delegation", "revoke_credential", "rotate_keys", "invite_user"])
    return perms


# ---------------------------------------------------------------------------
# GET /api/v1/agents/{agent_id}/profile — Aggregation endpoint
# ---------------------------------------------------------------------------

@router.get("/api/v1/agents/{agent_id}/profile")
def get_agent_profile(agent_id: str, request: Request):
    """
    Aggregated agent profile. Single call for the profile page header and
    summary data across all tabs.

    Public: returns public-safe subset (no org-private fields).
    Authenticated (same org): returns full dataset + permissions.
    """
    _require_configured()

    session = _get_session_or_none(request)
    is_authenticated = session is not None
    session_org_id = session[1] if session else None
    session_role = session[3] if session else None

    conn = _get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Agent basic info
        cursor.execute("""
            SELECT a.agent_id, a.agent_name, a.alias, a.public_key,
                   a.agent_did, a.trust_score, a.framework, a.verified,
                   a.verified_at, a.created_at, a.org_id,
                   o.org_name, o.domain
            FROM observer_agents a
            LEFT JOIN organizations o ON a.org_id = o.id
            WHERE a.agent_id = %s
        """, (agent_id,))
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        (aid, name, alias, pub_key, did, trust_score, framework,
         verified, verified_at, created_at, org_id,
         org_name, domain) = agent

        is_same_org = is_authenticated and session_org_id == org_id

        # 2. Trust score (TRON-specific for now)
        trust_data = None
        try:
            cursor.execute("""
                SELECT tr.receipt_count, tr.unique_senders, tr.total_trx_volume,
                       tr.total_stablecoin_volume, tr.last_activity
                FROM tron_receipt_stats tr
                WHERE tr.agent_id = %s
            """, (agent_id,))
            stats = cursor.fetchone()
            if stats:
                trust_data = {
                    "receipt_count": stats[0],
                    "unique_counterparties": stats[1],
                    "total_volume_trx": str(stats[2]) if stats[2] else "0",
                    "total_volume_stablecoin": str(stats[3]) if stats[3] else "0",
                    "last_activity": stats[4].isoformat() if hasattr(stats[4], "isoformat") else str(stats[4]) if stats[4] else None,
                }
        except Exception:
            pass  # Table may not exist; trust data is optional

        # 3. Rails from DID document service entries
        rails = []
        try:
            cursor.execute(
                "SELECT did_document FROM observer_agents WHERE agent_id = %s",
                (agent_id,),
            )
            dd_row = cursor.fetchone()
            if dd_row and dd_row[0]:
                dd = dd_row[0] if isinstance(dd_row[0], dict) else json.loads(dd_row[0])
                for svc in dd.get("service", []):
                    if svc.get("type") == "PaymentRail":
                        rails.append({
                            "network": svc.get("network"),
                            "asset": svc.get("asset"),
                        })
        except Exception:
            pass

        # 4. Transaction count
        tx_count = 0
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM tron_receipts WHERE agent_id = %s",
                (agent_id,),
            )
            tx_count = cursor.fetchone()[0]
        except Exception:
            pass

        # 5. Attestation count
        attestation_count = 0
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM partner_attestations WHERE subject_did = %s",
                (did or "",),
            )
            attestation_count = cursor.fetchone()[0]
        except Exception:
            pass

        # 6. Delegation status
        delegation_status = None
        if is_same_org:
            try:
                cursor.execute(
                    "SELECT status FROM delegation_requests WHERE agent_id = %s ORDER BY created_at DESC LIMIT 1",
                    (agent_id,),
                )
                del_row = cursor.fetchone()
                delegation_status = del_row[0] if del_row else "none"
            except Exception:
                delegation_status = "unknown"

        # Build response
        profile = {
            "agent_id": aid,
            "agent_name": name,
            "alias": alias,
            "did": did,
            "framework": framework,
            "verified": verified,
            "verified_at": verified_at.isoformat() if hasattr(verified_at, "isoformat") else str(verified_at) if verified_at else None,
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at) if created_at else None,
            "trust_score": float(trust_score) if trust_score else None,
            "trust_data": trust_data,
            "rails": rails,
            "transaction_count": tx_count,
            "attestation_count": attestation_count,
            "view_context": "authenticated" if is_same_org else "public",
        }

        # Public fields always included
        profile["org_name"] = org_name

        # Authenticated-only fields
        if is_same_org:
            profile["org_id"] = org_id
            profile["org_domain"] = domain
            profile["public_key"] = pub_key
            profile["delegation_status"] = delegation_status
            profile["permissions"] = _get_permissions(session_role)
        else:
            # Public view: redact sensitive fields
            profile["public_key"] = None
            profile["delegation_status"] = None
            profile["permissions"] = []

            # Round volumes for public view
            if trust_data:
                for vol_key in ["total_volume_trx", "total_volume_stablecoin"]:
                    if vol_key in trust_data and trust_data[vol_key]:
                        try:
                            val = float(trust_data[vol_key])
                            trust_data[vol_key] = str(round(val / 100) * 100)
                        except (ValueError, TypeError):
                            pass

        return JSONResponse(content=profile)

    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------------------------
# GET /api/v1/agents/{agent_id}/counterparties — Counterparty list
# ---------------------------------------------------------------------------

@router.get("/api/v1/agents/{agent_id}/counterparties")
def get_agent_counterparties(
    agent_id: str,
    request: Request,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    Counterparties this agent has transacted with.

    Public: counterparty count + aggregated volume only.
    Authenticated (same org): full per-counterparty breakdown.
    """
    _require_configured()

    session = _get_session_or_none(request)
    is_authenticated = session is not None

    conn = _get_db_connection()
    try:
        cursor = conn.cursor()

        # Verify agent exists and get org_id
        cursor.execute("SELECT org_id, agent_did FROM observer_agents WHERE agent_id = %s", (agent_id,))
        agent_row = cursor.fetchone()
        if not agent_row:
            raise HTTPException(status_code=404, detail="Agent not found")

        agent_org_id = agent_row[0]
        session_org_id = session[1] if session else None
        is_same_org = is_authenticated and session_org_id == agent_org_id

        # Query counterparties from TRON receipts
        try:
            cursor.execute("""
                SELECT
                    COALESCE(r.sender_address, 'unknown') as counterparty_address,
                    COUNT(*) as tx_count,
                    SUM(CAST(r.amount AS DECIMAL)) as total_volume,
                    MIN(r.tx_timestamp) as first_interaction,
                    MAX(r.tx_timestamp) as last_interaction,
                    r.rail,
                    r.asset
                FROM tron_receipts r
                WHERE r.agent_id = %s
                GROUP BY r.sender_address, r.rail, r.asset
                ORDER BY MAX(r.tx_timestamp) DESC
                LIMIT %s OFFSET %s
            """, (agent_id, limit, offset))
            rows = cursor.fetchall()
        except Exception:
            rows = []

        # Count total
        total_count = 0
        total_volume = 0
        try:
            cursor.execute("""
                SELECT COUNT(DISTINCT sender_address), SUM(CAST(amount AS DECIMAL))
                FROM tron_receipts WHERE agent_id = %s
            """, (agent_id,))
            summary = cursor.fetchone()
            total_count = summary[0] or 0
            total_volume = float(summary[1]) if summary[1] else 0
        except Exception:
            pass

        if is_same_org:
            counterparties = [
                {
                    "counterparty_address": r[0],
                    "tx_count": r[1],
                    "total_volume": str(r[2]) if r[2] else "0",
                    "first_interaction": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]) if r[3] else None,
                    "last_interaction": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]) if r[4] else None,
                    "rail": r[5],
                    "asset": r[6],
                }
                for r in rows
            ]
        else:
            counterparties = []  # Public: no per-counterparty breakdown

        return JSONResponse(content={
            "agent_id": agent_id,
            "total_counterparties": total_count,
            "total_volume": str(round(total_volume / 100) * 100) if not is_same_org else str(total_volume),
            "counterparties": counterparties,
            "view_context": "authenticated" if is_same_org else "public",
        })

    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------------------------
# GET /api/v1/trust/score/{agent_id} — Generalized trust score
# ---------------------------------------------------------------------------

@router.get("/api/v1/trust/score/{agent_id}")
def get_generalized_trust_score(agent_id: str):
    """
    Returns the highest available trust score across supported rails.
    Thin wrapper over rail-specific score endpoints.
    """
    _require_configured()

    conn = _get_db_connection()
    try:
        cursor = conn.cursor()

        # Check agent exists
        cursor.execute("SELECT agent_id, trust_score FROM observer_agents WHERE agent_id = %s", (agent_id,))
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Try TRON score (currently the only rail with scoring)
        tron_score = None
        try:
            cursor.execute("""
                SELECT tr.receipt_count, tr.unique_senders,
                       tr.total_trx_volume, tr.total_stablecoin_volume,
                       tr.last_activity
                FROM tron_receipt_stats tr
                WHERE tr.agent_id = %s
            """, (agent_id,))
            stats = cursor.fetchone()
            if stats and stats[0] > 0:
                # Use the trust_score from observer_agents (computed by AT-ARS)
                tron_score = float(agent[1]) if agent[1] else 0
        except Exception:
            pass

        # Return best available score
        best_score = tron_score or (float(agent[1]) if agent[1] else 0)
        source_rail = "tron" if tron_score else "aggregate"

        return JSONResponse(content={
            "agent_id": agent_id,
            "trust_score": round(best_score, 2),
            "source_rail": source_rail,
            "score_band": _score_band(best_score),
        })

    finally:
        cursor.close()
        conn.close()


def _score_band(score: float) -> dict:
    """Trust score band per spec §6."""
    if score < 40:
        return {"label": "Untrusted", "color": "red", "min": 0, "max": 39}
    elif score < 60:
        return {"label": "Developing", "color": "orange", "min": 40, "max": 59}
    elif score < 80:
        return {"label": "Established", "color": "yellow", "min": 60, "max": 79}
    else:
        return {"label": "Trusted", "color": "green", "min": 80, "max": 100}
