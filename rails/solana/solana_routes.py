"""
Solana API routes for Observer Protocol.

Endpoints:
  POST /api/v1/solana/verify     - Verify a Solana payment and issue SolanaPaymentCredential
  GET  /api/v1/solana/credentials/{agent_id} - List Solana credentials for an agent
"""

import json
from datetime import datetime, timezone
from typing import Optional

import psycopg2.extras
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/solana", tags=["solana"])

_get_db_connection = None


def configure(get_db_connection_fn):
    global _get_db_connection
    _get_db_connection = get_db_connection_fn


class SolanaVerifyRequest(BaseModel):
    agent_id: str
    agent_did: str
    counterparty: str
    tx_signature: str
    sender_address: str
    recipient_address: str
    amount: str
    asset: str = "USDC"
    network: str = "mainnet-beta"


@router.post("/verify")
def verify_solana_payment(req: SolanaVerifyRequest):
    """
    Verify a Solana payment and issue a SolanaPaymentCredential.

    Verifies the on-chain transaction via Solana RPC, confirms the
    transfer matches expected parameters, and issues a W3C VC.
    """
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

    from solana_verify import verify_solana_transaction, TOKEN_METADATA

    # Determine mint and amount units
    asset_upper = req.asset.upper()
    token_info = TOKEN_METADATA.get(asset_upper, {"decimals": 6, "symbol": asset_upper, "mint": None})
    mint = token_info.get("mint", asset_upper)
    if mint is None:
        mint = "SOL"

    # Parse amount (could be atomic or human-readable)
    try:
        amount_int = int(req.amount)
    except ValueError:
        amount_int = int(float(req.amount) * (10 ** token_info.get("decimals", 6)))

    # Verify on-chain
    try:
        result = verify_solana_transaction(
            tx_signature=req.tx_signature,
            sender_address=req.sender_address,
            recipient_address=req.recipient_address,
            amount_lamports=amount_int,
            mint=mint,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    if not result.get("verified"):
        raise HTTPException(status_code=400, detail=f"Transaction verification failed: {result.get('error', 'unknown')}")

    # Issue credential
    from vc_issuer import issue_vc

    decimals = token_info.get("decimals", 6)
    amount_human = f"{amount_int / (10 ** decimals):.{decimals}f}" if decimals > 0 else str(amount_int)

    claims = {
        "txSignature": req.tx_signature,
        "senderAddress": req.sender_address,
        "recipientAddress": req.recipient_address,
        "amount": str(amount_int),
        "amountHuman": amount_human,
        "asset": {
            "symbol": asset_upper,
            "mint": token_info.get("mint"),
            "decimals": decimals,
        },
        "network": req.network,
        "slot": result.get("slot"),
        "blockTime": result.get("block_time"),
        "confirmationStatus": "finalized",
        "counterparty": req.counterparty,
        "agentId": req.agent_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    vc = issue_vc(
        subject_did=req.agent_did,
        credential_type="SolanaPaymentCredential",
        claims=claims,
        expiration_days=30,
    )

    # Store credential
    conn = _get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO solana_credentials
                (credential_id, agent_id, agent_did, counterparty, network,
                 asset_symbol, amount, tx_signature, sender_address,
                 recipient_address, credential_json, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            vc.get("id"), req.agent_id, req.agent_did, req.counterparty,
            req.network, asset_upper, str(amount_int), req.tx_signature,
            req.sender_address, req.recipient_address, json.dumps(vc),
        ))

        # Insert into verified_events for AT-ARS integration
        import uuid as _uuid
        event_id = f"event-solana-{_uuid.uuid4().hex[:12]}"
        cur.execute("""
            INSERT INTO verified_events
                (event_id, agent_id, event_type, protocol, transaction_hash,
                 time_window, amount_bucket, amount_sats, direction,
                 verified, created_at, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
        """, (
            event_id, req.agent_id, "payment.executed", "solana",
            req.tx_signature,
            datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            _classify_amount(amount_human, asset_upper),
            0,  # amount_sats = 0 for Solana (use metadata for actual amount)
            "outbound",
            True,
            json.dumps({
                "asset": asset_upper,
                "amount_usdc": amount_human if asset_upper == "USDC" else None,
                "amount_usdt": amount_human if asset_upper == "USDT" else None,
                "amount_sol": amount_human if asset_upper == "SOL" else None,
                "network": req.network,
                "solana_credential_id": vc.get("id"),
            }),
        ))

        conn.commit()

        return {
            "credential": vc,
            "verification": {
                "onchain_verified": True,
                "slot": result.get("slot"),
                "block_time": result.get("block_time"),
                "confirmation_status": "finalized",
            },
            "event_id": event_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()


@router.get("/credentials/{agent_id}")
def get_solana_credentials(agent_id: str, limit: int = 20):
    """List SolanaPaymentCredentials for an agent."""
    conn = _get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT credential_id, counterparty, network, asset_symbol, amount,
                   tx_signature, sender_address, recipient_address, created_at
            FROM solana_credentials
            WHERE agent_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (agent_id, limit))
        rows = cur.fetchall()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return {"agent_id": agent_id, "credentials": [dict(r) for r in rows], "count": len(rows)}
    finally:
        cur.close()
        conn.close()


def _classify_amount(amount_human: str, symbol: str) -> str:
    try:
        val = float(amount_human)
        if symbol in ("SOL",):
            val = val * 150  # rough SOL->USD
        if val < 1:
            return "micro"
        elif val < 100:
            return "medium"
        else:
            return "large"
    except (ValueError, ZeroDivisionError):
        return "medium"
