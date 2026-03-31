#!/usr/bin/env python3
"""
Agentic Terminal API - FastAPI skeleton
Canonical API for machine-native settlement systems data
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import psycopg2.extras
from typing import Optional, List
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import uuid
import base64
import json


def get_db_connection():
    """Get PostgreSQL database connection using DATABASE_URL env var."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )
    return psycopg2.connect(database_url)


# Import VAC and Partner Registry modules
from vac_generator import VACGenerator, VAC_MAX_AGE_DAYS, VAC_REFRESH_HOURS
from partner_registry import PartnerRegistry, register_corpo_partner, issue_corpo_attestation

# Import Organization Registry modules
from organization_models import (
    OrganizationRegistrationRequest,
    OrganizationRevocationRequest,
)
from organization_registry import (
    OrganizationRegistry,
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    OrganizationRevokedError,
)

# Import crypto verification module
from crypto_verification import (
    persist_public_key,
    load_all_public_keys_from_db,
    verify_signature,
    verify_signature_simple,
    verify_ed25519_signature,
    get_cached_public_key,
    get_cached_key_type,
    detect_key_type,
)

# Import DID modules (Layer 1)
from did_document_builder import (
    build_agent_did,
    build_agent_did_document,
    build_op_did_document,
)
from did_resolver import resolve_did, validate_did_document

# Flag for crypto availability - cryptography library is confirmed available
ECDSA_AVAILABLE = True

# Initialize organization registry
org_registry = OrganizationRegistry()

# OWS (Open Wallet Standard) Constants and Validation
OWS_VALID_CHAINS = {"evm", "solana", "bitcoin"}
OWS_KEY_PREFIXES = ["02", "03", "04"]  # Compressed/uncompressed secp256k1
OWS_ED25519_LENGTH = 32  # Ed25519 public key length in bytes (base58 encoded)

def validate_ows_key_format(public_key: str, wallet_standard: Optional[str] = None) -> tuple[bool, str]:
    """Validate OWS key format with meaningful error messages"""
    if not public_key or len(public_key) < 32:
        return False, "Public key must be at least 32 characters long"
    
    if wallet_standard == "ows":
        # Check for valid base58 characters (common in Solana/OWS keys)
        import re
        base58_pattern = re.compile(r'^[1-9A-HJ-NP-Za-km-z]+$')
        if not base58_pattern.match(public_key):
            return False, "OWS public key must be valid base58 encoded string"
        
        # Check length (typical Ed25519 public key is 32 bytes = ~44 chars base58)
        if len(public_key) < 40 or len(public_key) > 50:
            return False, f"OWS Ed25519 public key should be 40-50 chars (got {len(public_key)})"
    
    return True, ""

def validate_chains(chains: Optional[List[str]]) -> tuple[bool, str]:
    """Validate OWS chains parameter"""
    if chains is None:
        return True, ""
    
    if not isinstance(chains, list):
        return False, "chains must be an array of strings"
    
    invalid_chains = [c for c in chains if c not in OWS_VALID_CHAINS]
    if invalid_chains:
        return False, f"Invalid chain(s): {', '.join(invalid_chains)}. Valid: {', '.join(OWS_VALID_CHAINS)}"
    
    return True, ""


class AgentUpdateRequest(BaseModel):
    """Request body for updating agent metadata."""
    agent_name: Optional[str] = None
    alias: Optional[str] = None
    framework: Optional[str] = None
    legal_entity_id: Optional[str] = None
    
    class Config:
        extra = "forbid"  # Only allow specified fields


def _build_transaction_message(agent_id: str, transaction_reference: str, protocol: str, timestamp: str) -> bytes:
    """
    Build the canonical transaction message for signing.
    
    Format: "agent_id:transaction_reference:protocol:timestamp"
    
    Args:
        agent_id: The agent's unique ID
        transaction_reference: The transaction hash or reference
        protocol: The protocol used (e.g., 'lightning', 'ethereum')
        timestamp: ISO format timestamp
        
    Returns:
        bytes: The canonical message to be signed
    """
    return f"{agent_id}:{transaction_reference}:{protocol}:{timestamp}".encode()


app = FastAPI(
    title="Agentic Terminal API",
    description="Canonical structured database for machine-native settlement systems",
    version="1.0.0"
)

_default_origins = (
    "https://observerprotocol.org,"
    "https://www.observerprotocol.org,"
    "https://agenticterminal.ai,"
    "https://www.agenticterminal.ai"
)
_allowed_origins = [
    o.strip()
    for o in os.environ.get("OP_ALLOWED_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "PUT", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Load public keys from database and initialise OP DID Document on startup."""
    print("Loading public keys from database...")
    try:
        loaded = load_all_public_keys_from_db()
        print(f"✓ Loaded {len(loaded)} public keys into memory cache")
    except Exception as e:
        print(f"Warning: Could not load public keys from database: {e}")
        print("  This is expected if the migration hasn't been run yet.")

    op_public_key = os.environ.get("OP_PUBLIC_KEY")
    if op_public_key:
        try:
            _ensure_op_did_document(op_public_key)
            print("✓ OP DID Document ready")
        except Exception as e:
            print(f"Warning: Could not initialise OP DID Document: {e}")
    else:
        print("Warning: OP_PUBLIC_KEY not set — /.well-known/did.json will not be served")

    if not os.environ.get("OP_WEBHOOK_SECRET"):
        print(
            "Warning: OP_WEBHOOK_SECRET is not set — outbound webhook payloads will "
            "NOT be signed. Set OP_WEBHOOK_SECRET in the environment to enable "
            "HMAC-SHA256 payload signing."
        )


def _ensure_op_did_document(op_public_key: str) -> None:
    """Insert OP's DID Document into op_did_document if not already present."""
    doc = build_op_did_document(op_public_key)
    op_did = doc["id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM op_did_document WHERE did = %s", (op_did,))
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO op_did_document (did, document) VALUES (%s, %s)",
                (op_did, json.dumps(doc)),
            )
            conn.commit()
        else:
            # Refresh key on restart so key rotations propagate
            cursor.execute(
                "UPDATE op_did_document SET document = %s, updated_at = NOW() WHERE did = %s",
                (json.dumps(doc), op_did),
            )
            conn.commit()
    finally:
        cursor.close()
        conn.close()


@app.get("/api/v1/health")
def health_check():
    """Health check endpoint."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return {"status": "ok", "db": "connected", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail={"status": "error", "db": "disconnected", "error": str(e)})

@app.get("/api/v1/protocols")
def list_protocols():
    """List all protocols."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT id, name, category, status, description, official_url, launch_date, created_at
        FROM protocols
        ORDER BY name
    """)
    
    protocols = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return {"protocols": [dict(p) for p in protocols], "count": len(protocols)}

@app.get("/api/v1/protocols/{protocol_id}")
def get_protocol(protocol_id: str):
    """Get single protocol with latest metrics."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Get protocol details
    cursor.execute("""
        SELECT id, name, category, status, description, official_url, launch_date, created_at
        FROM protocols
        WHERE id = %s
    """, (protocol_id,))
    
    protocol = cursor.fetchone()
    if not protocol:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Protocol not found")
    
    # Get latest metrics for this protocol
    cursor.execute("""
        SELECT DISTINCT ON (metric_name)
            metric_name, value, unit, timestamp, source
        FROM metrics
        WHERE protocol_id = %s
        ORDER BY metric_name, timestamp DESC
    """, (protocol_id,))
    
    latest_metrics = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return {
        "protocol": dict(protocol),
        "latest_metrics": [dict(m) for m in latest_metrics]
    }

@app.get("/api/v1/metrics")
def get_metrics(
    protocol: Optional[str] = Query(None, description="Protocol name to filter by"),
    metric_name: Optional[str] = Query(None, description="Specific metric name"),
    limit: int = Query(30, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get time-series metrics."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    query = """
        SELECT m.id, m.metric_name, m.value, m.unit, m.timestamp, m.source, m.source_url,
               p.name as protocol_name, p.id as protocol_id
        FROM metrics m
        JOIN protocols p ON m.protocol_id = p.id
        WHERE 1=1
    """
    params = []
    
    if protocol:
        query += " AND p.name = %s"
        params.append(protocol)
    
    if metric_name:
        query += " AND m.metric_name = %s"
        params.append(metric_name)
    
    query += " ORDER BY m.timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    metrics = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return {"metrics": [dict(m) for m in metrics], "count": len(metrics), "limit": limit, "offset": offset}

@app.get("/api/v1/signals")
def get_signals(
    protocol: Optional[str] = Query(None, description="Protocol name to filter by"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Get latest signals (discrete observable events)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    query = """
        SELECT s.id, s.event_type, s.title, s.description, s.impact_score, 
               s.timestamp, s.source_url, p.name as protocol_name
        FROM signals s
        JOIN protocols p ON s.protocol_id = p.id
        WHERE 1=1
    """
    params = []
    
    if protocol:
        query += " AND p.name = %s"
        params.append(protocol)
    
    if event_type:
        query += " AND s.event_type = %s"
        params.append(event_type)
    
    query += " ORDER BY s.timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    signals = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return {"signals": [dict(s) for s in signals], "count": len(signals), "limit": limit, "offset": offset}

@app.get("/api/v1/stats")
def get_stats():
    """Get database statistics."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    stats = {}
    
    # Count tables
    cursor.execute("SELECT COUNT(*) as count FROM protocols")
    stats["protocols_count"] = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM metrics")
    stats["metrics_count"] = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM signals")
    stats["signals_count"] = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM entities")
    stats["entities_count"] = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM analysis")
    stats["analysis_count"] = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM ingestion_logs")
    stats["ingestion_logs_count"] = cursor.fetchone()["count"]
    
    # Latest ingestion
    cursor.execute("""
        SELECT source, status, timestamp, rows_inserted
        FROM ingestion_logs
        ORDER BY timestamp DESC
        LIMIT 5
    """)
    stats["latest_ingestion_runs"] = [dict(r) for r in cursor.fetchall()]
    
    # Observer registry stats for frontend
    try:
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents")
        stats["total_agents"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM verified_events")
        stats["total_transactions"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM vac_credentials WHERE expires_at IS NULL OR expires_at > NOW()")
        stats["total_vacs"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(DISTINCT protocol) as count FROM verified_events")
        stats["active_rails"] = cursor.fetchone()["count"]
    except Exception:
        stats["total_agents"] = 0
        stats["total_transactions"] = 0
        stats["total_vacs"] = 0
        stats["active_rails"] = 0

    # Observer registry stats for frontend
    try:
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents")
        stats["total_agents"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM verified_events")
        stats["total_transactions"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM vac_credentials WHERE expires_at IS NULL OR expires_at > NOW()")
        stats["total_vacs"] = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(DISTINCT protocol) as count FROM verified_events")
        stats["active_rails"] = cursor.fetchone()["count"]
    except Exception:
        stats["total_agents"] = 0
        stats["total_transactions"] = 0
        stats["total_vacs"] = 0
        stats["active_rails"] = 0

    cursor.close()
    conn.close()

    return {"stats": stats, "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/v1/agent-events")
def get_agent_events(limit: int = 20, agent_id: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if agent_id:
        cursor.execute("""
            SELECT id, agent_id, event_type, economic_role, amount, unit, 
                   context_tag, economic_intent, verified, timestamp
            FROM agent_events 
            WHERE agent_id = %s
            ORDER BY timestamp DESC LIMIT %s
        """, (agent_id, limit))
    else:
        cursor.execute("""
            SELECT id, agent_id, event_type, economic_role, amount, unit,
                   context_tag, economic_intent, verified, timestamp
            FROM agent_events 
            ORDER BY timestamp DESC LIMIT %s
        """, (limit,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    columns = ['id', 'agent_id', 'event_type', 'economic_role', 'amount', 'unit', 'context_tag', 'economic_intent', 'verified', 'timestamp']
    events = [dict(zip(columns, [str(v) if hasattr(v, 'hex') else v for v in row])) for row in rows]
    return {"count": len(events), "events": events}

# ============================================================
# OBSERVER PROTOCOL ENDPOINTS
# ============================================================

@app.post("/observer/register-agent")
def register_agent(
    public_key: str,
    agent_name: Optional[str] = None,
    framework: Optional[str] = None,
    alias: Optional[str] = None,
    legal_entity_id: Optional[str] = None,
    wallet_standard: Optional[str] = None,
    ows_vault_name: Optional[str] = None,
    chains: Optional[str] = None
):
    """Register a new agent with the Observer Protocol.
    
    OWS (Open Wallet Standard) Support:
    - wallet_standard: Set to "ows" for OWS-compatible agents
    - ows_vault_name: Name of the OWS vault
    - chains: JSON array string of supported chains ["evm", "solana", "bitcoin"]
    """
    # Validate OWS key format if wallet_standard is provided
    if wallet_standard:
        is_valid, error_msg = validate_ows_key_format(public_key, wallet_standard)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid OWS key format: {error_msg}")
    
    # Parse and validate chains if provided
    chains_list = None
    if chains:
        try:
            chains_list = json.loads(chains)
            if not isinstance(chains_list, list):
                raise HTTPException(status_code=400, detail="chains must be a JSON array")
            is_valid, error_msg = validate_chains(chains_list)
            if not is_valid:
                raise HTTPException(status_code=400, detail=error_msg)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="chains must be valid JSON array string")
    
    # Generate agent_id as SHA256 hash of public_key
    agent_id = hashlib.sha256(public_key.encode()).hexdigest()[:32]

    # Generate DID and DID Document
    agent_did = build_agent_did(agent_id)
    did_document = None
    try:
        did_document = build_agent_did_document(agent_id, public_key)
    except Exception as _did_err:
        # Key format may not be directly encodable (e.g. compressed secp256k1);
        # record the DID without a document for now.
        pass

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO observer_agents (agent_id, agent_name, alias, framework, legal_entity_id, verified, created_at, public_key, wallet_standard, ows_vault_name, chains, agent_did, did_document, did_created_at, did_updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT (agent_id) DO UPDATE SET
                agent_name = EXCLUDED.agent_name,
                alias = EXCLUDED.alias,
                framework = EXCLUDED.framework,
                legal_entity_id = EXCLUDED.legal_entity_id,
                wallet_standard = EXCLUDED.wallet_standard,
                ows_vault_name = EXCLUDED.ows_vault_name,
                chains = EXCLUDED.chains,
                agent_did = EXCLUDED.agent_did,
                did_document = EXCLUDED.did_document,
                did_updated_at = NOW()
            RETURNING agent_id
        """, (
            agent_id, agent_name, alias or agent_name,
            framework, legal_entity_id, False, public_key,
            wallet_standard, ows_vault_name,
            json.dumps(chains_list) if chains_list else None,
            agent_did,
            json.dumps(did_document) if did_document else None,
        ))

        conn.commit()

        # Persist the public key to database (and cache in memory)
        persist_public_key(agent_id, public_key, verified=False)

        # Build response
        response = {
            "agent_id": agent_id,
            "agent_did": agent_did,
            "agent_name": agent_name,
            "verification_status": "registered",
            "message": "Registration successful. Agent identity recorded in Observer Protocol registry.",
            "note": "Public key cached for challenge-response verification",
            "next_steps": [
                "1. Generate challenge: POST /observer/challenge?agent_id=<id>",
                "2. Sign and verify: POST /observer/verify-agent",
                "3. Badge available at: GET /observer/badge/{agent_id}.svg",
                f"4. DID Document at: GET /agents/{agent_id}/did.json",
            ],
            "badge_url": f"https://api.agenticterminal.ai/observer/badge/{agent_id}.svg",
            "profile_url": f"https://observerprotocol.org/agents/{agent_id}",
            "did_document_url": f"https://observerprotocol.org/agents/{agent_id}/did.json",
        }

        if did_document:
            response["did_document"] = did_document

        if wallet_standard:
            response["wallet_standard"] = wallet_standard
            response["ows_badge"] = wallet_standard == "ows"
        if ows_vault_name:
            response["ows_vault_name"] = ows_vault_name
        if chains_list:
            response["chains"] = chains_list

        return response
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.patch("/observer/agent/{agent_id}")
def update_agent(agent_id: str, update: AgentUpdateRequest):
    """Update an existing agent's information.
    
    Allows updating agent metadata including the optional legal_entity_id
    for Corpo integration (legal entity wrapper for AI agents).
    
    Request body should be JSON with fields to update:
    - agent_name: Optional[str]
    - alias: Optional[str]
    - framework: Optional[str]
    - legal_entity_id: Optional[str]
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Check if agent exists
        cursor.execute("""
            SELECT agent_id, agent_name, alias, framework, legal_entity_id, verified
            FROM observer_agents WHERE agent_id = %s
        """, (agent_id,))
        
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Build dynamic update query from request body
        update_fields = []
        params = []
        
        if update.agent_name is not None:
            update_fields.append("agent_name = %s")
            params.append(update.agent_name)
        if update.alias is not None:
            update_fields.append("alias = %s")
            params.append(update.alias)
        if update.framework is not None:
            update_fields.append("framework = %s")
            params.append(update.framework)
        if update.legal_entity_id is not None:
            update_fields.append("legal_entity_id = %s")
            params.append(update.legal_entity_id)
        
        if not update_fields:
            # No fields to update, return current state
            return {
                "agent_id": agent_id,
                "agent_name": agent["agent_name"],
                "alias": agent["alias"],
                "framework": agent["framework"],
                "legal_entity_id": agent["legal_entity_id"],
                "verified": agent["verified"],
                "message": "No fields provided for update"
            }
        
        params.append(agent_id)
        
        cursor.execute(f"""
            UPDATE observer_agents
            SET {', '.join(update_fields)}
            WHERE agent_id = %s
            RETURNING agent_id, agent_name, alias, framework, legal_entity_id, verified, created_at, verified_at
        """, tuple(params))
        
        updated = cursor.fetchone()
        conn.commit()
        
        return {
            "agent_id": updated["agent_id"],
            "agent_name": updated["agent_name"],
            "alias": updated["alias"],
            "framework": updated["framework"],
            "legal_entity_id": updated["legal_entity_id"],
            "verified": updated["verified"],
            "created_at": updated["created_at"].isoformat() if updated["created_at"] else None,
            "verified_at": updated["verified_at"].isoformat() if updated["verified_at"] else None,
            "message": "Agent updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.post("/observer/challenge")
def generate_challenge(agent_id: str):
    """Generate a cryptographic challenge for agent verification.
    
    Phase 2 Implementation:
    - Generates a unique nonce
    - Stores challenge with 5-minute expiry
    - Agent must sign this challenge to prove key ownership
    """
    # Generate cryptographically secure random nonce (32 bytes = 64 hex chars)
    nonce = secrets.token_hex(32)
    
    # Challenge expires in 5 minutes (300 seconds)
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(seconds=300)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify agent exists
        cursor.execute("""
            SELECT agent_id FROM observer_agents
            WHERE agent_id = %s
        """, (agent_id,))
        
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Clean up old expired challenges for this agent
        cursor.execute("""
            DELETE FROM verification_challenges 
            WHERE agent_id = %s AND expires_at < NOW()
        """, (agent_id,))
        
        # Store the new challenge
        cursor.execute("""
            INSERT INTO verification_challenges 
            (agent_id, nonce, created_at, expires_at, used)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING challenge_id
        """, (agent_id, nonce, created_at, expires_at, False))
        
        challenge_id = cursor.fetchone()[0]
        conn.commit()
        
        return {
            "challenge_id": str(challenge_id),
            "nonce": nonce,
            "agent_id": agent_id,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_in_seconds": 300,
            "message": "Sign this nonce with your private key and submit to /observer/verify-agent",
            "instruction": "Sign the 'nonce' value using your registered private key, then submit the signature to the verify-agent endpoint within 5 minutes."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Challenge generation failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.post("/observer/verify-agent")
def verify_agent(agent_id: str, signed_challenge: str, challenge_id: Optional[str] = None):
    """Verify an agent with signed challenge using challenge-response protocol.
    
    Phase 2 Implementation:
    - Verifies the challenge exists and is valid (not expired, not used)
    - Verifies signature against agent's registered public key
    - Marks challenge as used to prevent replay
    - Upgrades agent status to verified upon successful verification
    
    Args:
        agent_id: The agent's unique ID
        signed_challenge: The nonce signed with the agent's private key (hex string)
        challenge_id: Optional challenge ID if known (for tracking purposes)
    """
    if not signed_challenge or len(signed_challenge) == 0:
        raise HTTPException(status_code=400, detail="Signed challenge required")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # Get agent details including public key
        cursor.execute("""
            SELECT agent_id, verified
            FROM observer_agents
            WHERE agent_id = %s
        """, (agent_id,))
        
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        if agent["verified"]:
            return {
                "verified": True,
                "agent_id": agent_id,
                "message": "Agent already verified",
                "verification_method": "challenge_response",
                "already_verified": True
            }
        
        # Find the most recent valid challenge for this agent
        cursor.execute("""
            SELECT challenge_id, nonce, expires_at, used
            FROM verification_challenges
            WHERE agent_id = %s 
            AND used = FALSE
            AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
        """, (agent_id,))
        
        challenge = cursor.fetchone()
        
        if not challenge:
            raise HTTPException(
                status_code=400, 
                detail="No valid challenge found. Generate a new challenge with POST /observer/challenge"
            )
        
        # Check if challenge is expired (defense in depth, DB query already filters)
        # Handle both offset-aware and offset-naive datetimes
        from datetime import timezone
        now = datetime.now(timezone.utc)
        expires_at = challenge["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            raise HTTPException(status_code=400, detail="Challenge has expired. Generate a new challenge.")
        
        if challenge["used"]:
            raise HTTPException(status_code=400, detail="Challenge has already been used. Generate a new challenge.")
        
        # Phase 2: Real cryptographic signature verification
        # Verify the signature cryptographically against the stored public key
        # Supports both SECP256k1 (Ethereum/Bitcoin) and Ed25519 (Solana) keys
        
        # Get the cached public key
        public_key_hex = get_cached_public_key(agent_id)
        key_type = get_cached_key_type(agent_id)
        
        if not public_key_hex:
            # Try to get from agent record if stored there
            # For now, we need the public key to verify
            raise HTTPException(
                status_code=400, 
                detail="Public key not found. Please re-register with the full public key."
            )
        
        # Verify the signature cryptographically
        nonce_bytes = challenge["nonce"].encode('utf-8')
        
        # Use the appropriate verification based on key type
        if key_type == 'ed25519':
            is_valid = verify_ed25519_signature(nonce_bytes, signed_challenge, public_key_hex)
            verification_method = "challenge_response_ed25519"
        elif key_type == 'secp256k1':
            is_valid = verify_signature_simple(nonce_bytes, signed_challenge, public_key_hex)
            verification_method = "challenge_response_secp256k1"
        else:
            # Auto-detect if type not cached
            is_valid = verify_signature(nonce_bytes, signed_challenge, public_key_hex)
            detected_type = detect_key_type(public_key_hex)
            verification_method = f"challenge_response_{detected_type}"
        
        if not is_valid:
            raise HTTPException(
                status_code=400, 
                detail="Signature verification failed. The signature does not match the public key."
            )
        
        verification_successful = True
        
        # Mark challenge as used (replay protection)
        cursor.execute("""
            UPDATE verification_challenges
            SET used = TRUE, used_at = NOW(), signature = %s
            WHERE challenge_id = %s
        """, (signed_challenge, challenge["challenge_id"]))
        
        # Update agent status to verified
        cursor.execute("""
            UPDATE observer_agents
            SET verified = TRUE, verified_at = NOW()
            WHERE agent_id = %s
            RETURNING agent_id
        """, (agent_id,))

        conn.commit()

        return {
            "verified": True,
            "agent_id": agent_id,
            "challenge_id": str(challenge["challenge_id"]),
            "verification_method": verification_method,
            "message": "Agent successfully verified using challenge-response protocol",
            "next_steps": [
                "Badge updated: GET /observer/badge/{agent_id}.svg",
                "Submit transactions: POST /observer/submit-transaction",
                "View profile: https://observerprotocol.org/agents/{agent_id}"
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.post("/observer/submit-transaction")
def submit_transaction(
    agent_id: str,
    protocol: str,
    transaction_reference: str,
    timestamp: str,
    signature: str,
    optional_metadata: Optional[str] = None
):
    """Submit a verified transaction to the Observer Protocol.
    
    Security: All transactions must be cryptographically signed.
    The signature is verified against the agent's stored public key.
    
    Signing Format:
        The agent must sign: "agent_id:transaction_reference:protocol:timestamp"
        Example: "abc123:tx_hash_456:lightning:2024-01-15T10:30:00Z"
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify agent exists and is verified; fetch agent_did for payload
        cursor.execute("""
            SELECT verified, agent_did FROM observer_agents WHERE agent_id = %s
        """, (agent_id,))

        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not result[0]:
            raise HTTPException(status_code=403, detail="Agent not verified")
        agent_did = result[1] if result[1] else None

        # Verify transaction signature cryptographically
        if not signature:
            raise HTTPException(status_code=400, detail="Transaction signature required")

        public_key_hex = get_cached_public_key(agent_id)
        if not public_key_hex:
            raise HTTPException(status_code=400, detail="Public key not found")
        
        # Build canonical message and verify signature
        message = _build_transaction_message(agent_id, transaction_reference, protocol, timestamp)
        is_valid = verify_signature(message, signature, public_key_hex)
        
        if not is_valid:
            raise HTTPException(status_code=400, detail="Transaction signature verification failed")
        
        # Determine amount_bucket from optional_metadata if provided
        amount_bucket = "unknown"
        if optional_metadata:
            try:
                import json
                metadata = json.loads(optional_metadata)
                amount = metadata.get("amount_sats", 0)
                if amount < 1000:
                    amount_bucket = "micro"
                elif amount < 10000:
                    amount_bucket = "small"
                elif amount < 100000:
                    amount_bucket = "medium"
                else:
                    amount_bucket = "large"
            except:
                pass
        
        # Generate event_id
        event_id = f"event-{agent_id[:12]}-{str(uuid.uuid4())[:8]}"
        
        # Determine event_type and direction from metadata
        event_type = "payment.executed"
        direction = "outbound"
        counterparty_id = None
        service_description = None
        preimage = None
        amount_sats = None
        
        if optional_metadata:
            try:
                import json
                metadata = json.loads(optional_metadata)
                event_type = metadata.get("event_type", "payment.executed")
                direction = metadata.get("direction", "outbound")
                counterparty_id = metadata.get("counterparty_id")
                service_description = metadata.get("service_description")
                preimage = metadata.get("preimage")
                amount_sats = metadata.get("amount_sats")  # ACTUAL AMOUNT
            except:
                pass
        
        stored_at = datetime.utcnow()
        
        # Check for duplicate event_id or transaction_hash
        cursor.execute("SELECT event_id FROM verified_events WHERE event_id = %s", (event_id,))
        if cursor.fetchone():
            conn.rollback()
            raise HTTPException(status_code=409, detail=f"Transaction already exists: {event_id}")
        
        if transaction_reference:
            cursor.execute("SELECT event_id FROM verified_events WHERE transaction_hash = %s", (transaction_reference,))
            if cursor.fetchone():
                conn.rollback()
                raise HTTPException(status_code=409, detail=f"Transaction hash already exists: {transaction_reference}")
        
        cursor.execute("""
            INSERT INTO verified_events (
                event_id, agent_id, counterparty_id, event_type, protocol,
                transaction_hash, time_window, amount_bucket, direction,
                service_description, preimage, verified, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            event_id, agent_id, counterparty_id, event_type, protocol,
            transaction_reference, timestamp[:10] if timestamp else None,
            amount_bucket, direction, service_description, preimage, True
        ))
        
        conn.commit()
        
        resp: dict = {
            "event_id": event_id,
            "verified": True,
            "stored_at": stored_at.isoformat(),
        }
        if agent_did:
            resp["agent_did"] = agent_did
        return resp
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Transaction submission failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/observer/trends")
def get_trends():
    """Get trends from verified events (no auth required for MVP)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Get protocol counts
        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM verified_events
            GROUP BY protocol
            ORDER BY count DESC
        """)
        protocol_counts = [dict(r) for r in cursor.fetchall()]
        
        # Get total events
        cursor.execute("SELECT COUNT(*) as count FROM verified_events")
        total_events = cursor.fetchone()["count"]
        
        # Get total verified agents
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents WHERE verified = TRUE")
        total_verified_agents = cursor.fetchone()["count"]
        
        # Get most active protocol
        most_active_protocol = None
        if protocol_counts:
            most_active_protocol = protocol_counts[0]["protocol"]
        
        return {
            "protocol_counts": protocol_counts,
            "total_events": total_events,
            "total_verified_agents": total_verified_agents,
            "most_active_protocol": most_active_protocol
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/observer/feed")
def get_feed(limit: int = 50):
    """Get last 50 verified events with full details (anonymized — no agent_id in response)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT 
                ve.event_id,
                ve.event_type,
                ve.protocol,
                ve.transaction_hash,
                ve.time_window,
                ve.amount_bucket,
                COALESCE(ve.amount_sats, 21000) as amount_sats,
                ve.direction,
                ve.service_description,
                ve.preimage,
                ve.counterparty_id,
                ve.verified,
                ve.created_at,
                oa.alias as agent_alias
            FROM verified_events ve
            LEFT JOIN observer_agents oa ON ve.agent_id = oa.agent_id
            ORDER BY ve.created_at DESC
            LIMIT %s
        """, (limit,))
        
        events = [dict(r) for r in cursor.fetchall()]
        
        return {
            "events": events,
            "count": len(events)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


def _generate_badge_svg(
    agent_name: str,
    agent_seq: int,
    verification_status: str,  # "registered", "pending", "verified"
    verified_at: Optional[datetime],
    tx_count: int,
    agent_id: str
) -> str:
    """Generate an Observer Protocol verification badge as SVG.
    
    Args:
        verification_status: One of "registered", "pending", "verified"
            - registered: Agent registered but no cryptographic verification yet
            - pending: Challenge issued, awaiting response
            - verified: Full challenge-response verification complete
    """

    # Colors
    BG          = "#0a0a0f"
    ORANGE      = "#F7931A"
    PANEL_BG    = "#13131e"
    TEXT_LIGHT  = "#e8e8ed"
    TEXT_DIM    = "#6b6b80"
    GREEN       = "#00c853"
    YELLOW      = "#ffb300"
    BLUE        = "#448aff"
    BORDER      = "#252535"

    display_name = agent_name or f"agent-{agent_id[:8]}"
    seq_label    = f"#{agent_seq:04d}"
    date_label   = verified_at.strftime("%b %d, %Y") if verified_at else "—"
    tx_label     = f"{tx_count} verified tx"
    
    # Status display based on verification stage
    status_config = {
        "verified": {
            "color": GREEN,
            "text": "VERIFIED",
            "description": "Cryptographically verified"
        },
        "pending": {
            "color": YELLOW,
            "text": "PENDING",
            "description": "Verification in progress"
        },
        "registered": {
            "color": BLUE,
            "text": "REGISTERED",
            "description": "Identity registered, verification pending"
        }
    }
    
    config = status_config.get(verification_status, status_config["registered"])
    status_color = config["color"]
    status_text = config["text"]
    profile_url  = f"https://observerprotocol.org/agents/{agent_id}"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="400" height="96" viewBox="0 0 400 96" role="img" aria-label="Observer Protocol Badge — {display_name}">
  <title>Observer Protocol — {display_name} {seq_label}</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="{PANEL_BG}"/>
      <stop offset="100%" stop-color="{BG}"/>
    </linearGradient>
    <clipPath id="r"><rect width="400" height="96" rx="8"/></clipPath>
  </defs>

  <!-- Background -->
  <rect width="400" height="96" rx="8" fill="url(#bg)"/>
  <rect width="400" height="96" rx="8" fill="none" stroke="{BORDER}" stroke-width="1"/>

  <!-- Left accent bar -->
  <rect width="4" height="96" rx="0" fill="{ORANGE}" clip-path="url(#r)"/>

  <!-- Orange OP circle logo -->
  <circle cx="36" cy="48" r="18" fill="{ORANGE}" opacity="0.15"/>
  <circle cx="36" cy="48" r="13" fill="none" stroke="{ORANGE}" stroke-width="2"/>
  <text x="36" y="53" font-family="monospace" font-size="11" font-weight="700"
        fill="{ORANGE}" text-anchor="middle">OP</text>

  <!-- Agent name + seq -->
  <text x="66" y="34" font-family="'IBM Plex Sans', 'Helvetica Neue', Arial, sans-serif"
        font-size="15" font-weight="700" fill="{TEXT_LIGHT}">{display_name}</text>
  <text x="66" y="52" font-family="'JetBrains Mono', 'Courier New', monospace"
        font-size="11" fill="{TEXT_DIM}">Agent {seq_label}</text>

  <!-- Status pill -->
  <rect x="66" y="60" width="82" height="18" rx="4" fill="{status_color}" opacity="0.15"/>
  <text x="107" y="73" font-family="monospace" font-size="10" font-weight="700"
        fill="{status_color}" text-anchor="middle">{status_text}</text>

  <!-- Right side stats -->
  <text x="390" y="34" font-family="monospace" font-size="10" fill="{TEXT_DIM}"
        text-anchor="end">{tx_label}</text>
  <text x="390" y="52" font-family="monospace" font-size="10" fill="{TEXT_DIM}"
        text-anchor="end">since {date_label}</text>

  <!-- Bottom label -->
  <text x="200" y="88" font-family="monospace" font-size="9" fill="{TEXT_DIM}"
        text-anchor="middle" opacity="0.7">OBSERVER PROTOCOL · observerprotocol.org</text>

  <!-- Invisible full-badge link -->
  <a href="{profile_url}">
    <rect width="400" height="96" fill="transparent"/>
  </a>
</svg>"""
    return svg


def _generate_not_found_badge_svg() -> str:
    """Badge for unknown agent IDs."""
    return """<svg xmlns="http://www.w3.org/2000/svg" width="400" height="96" viewBox="0 0 400 96">
  <rect width="400" height="96" rx="8" fill="#13131e" stroke="#252535" stroke-width="1"/>
  <rect width="4" height="96" fill="#555566"/>
  <text x="200" y="44" font-family="monospace" font-size="13" fill="#6b6b80" text-anchor="middle">OBSERVER PROTOCOL</text>
  <text x="200" y="64" font-family="monospace" font-size="11" fill="#ff5252" text-anchor="middle">Agent not found</text>
</svg>"""


@app.get("/observer/badge/{agent_id}.svg",
         responses={200: {"content": {"image/svg+xml": {}}}})
def get_agent_badge(agent_id: str):
    """
    Return a dynamic SVG verification badge for a registered Observer Protocol agent.
    Embed anywhere: <img src="https://api.agenticterminal.ai/observer/badge/AGENT_ID.svg">
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # Fetch agent record
        cursor.execute("""
            SELECT agent_id, agent_name, verified, verified_at, created_at
            FROM observer_agents
            WHERE agent_id = %s
        """, (agent_id,))
        agent = cursor.fetchone()

        if not agent:
            svg = _generate_not_found_badge_svg()
            return Response(
                content=svg,
                media_type="image/svg+xml",
                headers={"Cache-Control": "no-cache", "X-Agent-Status": "not-found"}
            )

        # Get sequence number (rank by created_at)
        cursor.execute("""
            SELECT COUNT(*) as seq FROM observer_agents
            WHERE created_at <= %s
        """, (agent["created_at"],))
        seq = cursor.fetchone()["seq"]

        # Get verified event count
        cursor.execute("""
            SELECT COUNT(*) as cnt FROM verified_events
            WHERE agent_id = %s AND verified = TRUE
        """, (agent_id,))
        tx_count = cursor.fetchone()["cnt"]

        # Determine verification status for badge display
        # MVP: All registered agents show as "registered" until crypto verification implemented
        # TODO: Add "pending" state when challenge-response flow is implemented
        if agent["verified"]:
            verification_status = "verified"
        else:
            verification_status = "registered"  # Was "unverified", now "registered" for clarity
        
        svg = _generate_badge_svg(
            agent_name         = agent["agent_name"] or agent_id[:12],
            agent_seq          = seq,
            verification_status = verification_status,
            verified_at        = agent["verified_at"],
            tx_count           = tx_count,
            agent_id           = agent_id
        )

        cache = "public, max-age=300" if agent["verified"] else "no-cache"
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={
                "Cache-Control": cache,
                "X-Agent-Id": agent_id,
                "X-Verification-Status": verification_status
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Badge generation failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.get("/observer/agent/{public_key_hash}")
def lookup_agent_by_hash(public_key_hash: str):
    """Lookup an agent by its public key hash.
    
    Returns agent details including legal_entity_id if set.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # public_key_hash column was dropped (Migration 005).
        # agent_id was always SHA256(public_key)[:32], so agent_id == public_key_hash[:32].
        cursor.execute("""
            SELECT agent_id, agent_name, alias, framework, legal_entity_id,
                   verified, verified_at, created_at, access_level
            FROM observer_agents WHERE agent_id = %s
        """, (public_key_hash[:32],))
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        cursor.execute("""
            SELECT COUNT(*) as cnt FROM verified_events
            WHERE agent_id = %s AND verified = TRUE
        """, (agent["agent_id"],))
        tx_count = cursor.fetchone()["cnt"]

        return {
            "agent_id": agent["agent_id"],
            "agent_name": agent["agent_name"],
            "alias": agent["alias"],
            "framework": agent["framework"],
            "legal_entity_id": agent["legal_entity_id"],
            "access_level": agent["access_level"],
            "verified": agent["verified"],
            "verified_at": agent["verified_at"].isoformat() if agent["verified_at"] else None,
            "first_seen": agent["created_at"].isoformat(),
            "verified_tx_count": tx_count,
            "badge_url": f"https://api.agenticterminal.ai/observer/badge/{agent['agent_id']}.svg",
            "profile_url": f"https://observerprotocol.org/agents/{agent['agent_id']}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# ============================================================
# AGENT LIST ENDPOINT (for registry page) - MUST BE BEFORE /{agent_id}
# ============================================================

@app.get("/observer/agents/list")
async def list_agents():
    """List all registered agents with basic stats (for registry page)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT 
                oa.agent_id,
                oa.agent_name,
                oa.alias,
                oa.framework,
                oa.verified,
                oa.verified_at,
                oa.created_at,
                oa.legal_entity_id,
                COALESCE(
                    (SELECT COUNT(*) FROM verified_events ve 
                     WHERE ve.agent_id = oa.agent_id AND ve.verified = TRUE), 
                    0
                ) as tx_count,
                COALESCE(
                    (SELECT COUNT(DISTINCT ve.counterparty_id) FROM verified_events ve 
                     WHERE ve.agent_id = oa.agent_id AND ve.verified = TRUE),
                    0
                ) as unique_counterparties,
                (
                    SELECT ve.protocol FROM verified_events ve 
                    WHERE ve.agent_id = oa.agent_id AND ve.verified = TRUE 
                    ORDER BY ve.created_at DESC LIMIT 1
                ) as last_rail
            FROM observer_agents oa
            ORDER BY oa.verified DESC, oa.created_at ASC
        """)
        agents = cursor.fetchall()
        
        result = []
        for agent in agents:
            result.append({
                "agent_id": agent["agent_id"],
                "agent_name": agent["agent_name"],
                "alias": agent["alias"],
                "framework": agent["framework"],
                "verified": agent["verified"],
                "verified_at": agent["verified_at"].isoformat() if agent["verified_at"] else None,
                "created_at": agent["created_at"].isoformat() if agent["created_at"] else None,
                "legal_entity_id": agent["legal_entity_id"],
                "total_transactions": agent["tx_count"],
                "unique_counterparties": agent["unique_counterparties"],
                "last_rail": agent["last_rail"] or "L402",
                "success_rate": 1.0 if agent["verified"] else 0.0
            })
        
        return {"agents": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.get("/observer/agents/{agent_id}")
def get_agent_profile(agent_id: str):
    """Public agent profile — name, verification status, event count, first seen."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT agent_id, agent_name, alias, framework, legal_entity_id,
                   verified, verified_at, created_at, access_level,
                   wallet_standard, ows_vault_name, chains
            FROM observer_agents WHERE agent_id = %s
        """, (agent_id,))
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")

        cursor.execute("""
            SELECT COUNT(*) as cnt FROM verified_events
            WHERE agent_id = %s AND verified = TRUE
        """, (agent_id,))
        tx_count = cursor.fetchone()["cnt"]

        cursor.execute("""
            SELECT COUNT(*) as seq FROM observer_agents
            WHERE created_at <= %s
        """, (agent["created_at"],))
        seq = cursor.fetchone()["seq"]

        # Build response with OWS fields
        response = {
            "agent_id": agent_id,
            "agent_name": agent["agent_name"],
            "alias": agent["alias"],
            "framework": agent["framework"],
            "legal_entity_id": agent["legal_entity_id"],
            "access_level": agent["access_level"],
            "verified": agent["verified"],
            "verified_at": agent["verified_at"].isoformat() if agent["verified_at"] else None,
            "first_seen": agent["created_at"].isoformat(),
            "sequence_number": seq,
            "verified_tx_count": tx_count,
            "badge_url": f"https://api.agenticterminal.ai/observer/badge/{agent_id}.svg",
            "profile_url": f"https://observerprotocol.org/agents/{agent_id}"
        }
        
        # Add OWS fields if present
        if agent.get("wallet_standard"):
            response["wallet_standard"] = agent["wallet_standard"]
            response["ows_badge"] = agent["wallet_standard"] == "ows"
        if agent.get("ows_vault_name"):
            response["ows_vault_name"] = agent["ows_vault_name"]
        if agent.get("chains"):
            import json
            try:
                chains = agent["chains"]
                if isinstance(chains, str):
                    chains = json.loads(chains)
                response["chains"] = chains
            except:
                pass
                
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


# ============================================================
# VAC (VERIFIED AGENT CREDENTIAL) ENDPOINTS
# ============================================================

class PartnerRegistrationRequest(BaseModel):
    """Request body for registering a partner."""
    partner_name: str
    partner_type: str  # 'corpo', 'verifier', 'counterparty', 'infrastructure'
    public_key: str
    webhook_url: Optional[str] = None
    metadata: Optional[dict] = None


class AttestationRequest(BaseModel):
    """Request body for issuing an attestation."""
    agent_id: str
    claims: dict
    credential_id: Optional[str] = None
    expires_in_days: Optional[int] = None
    attestation_signature: Optional[str] = None


class CounterpartyMetadataRequest(BaseModel):
    """Request body for adding counterparty metadata."""
    counterparty_id: str
    metadata: dict
    ipfs_cid: Optional[str] = None


@app.get("/vac/{agent_id}")
def get_vac_credential(agent_id: str, include_extensions: bool = True):
    """
    Get the active VAC (Verified Agent Credential) for an agent.
    
    Returns the latest valid VAC credential including:
    - Core fields: aggregated transaction data, volume, counterparties, rails
    - Extensions: partner attestations and counterparty metadata hashes
    - OWS fields: wallet_standard, ows_badge, ows_vault_name, chains
    
    VACs expire after 7 days and refresh automatically every 24 hours.
    """
    try:
        generator = VACGenerator()
        
        # Check if agent needs a new VAC
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            # Check if agent exists and is verified, include OWS fields
            cursor.execute("""
                SELECT agent_id, verified, wallet_standard, ows_vault_name, chains, public_key, alias
                FROM observer_agents WHERE agent_id = %s
            """, (agent_id,))
            
            agent = cursor.fetchone()
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            if not agent['verified']:
                raise HTTPException(status_code=403, detail="Agent not verified")
            
            # Check for active VAC
            cursor.execute("""
                SELECT credential_id, issued_at, expires_at
                FROM vac_credentials
                WHERE agent_id = %s AND is_revoked = FALSE
                ORDER BY issued_at DESC
                LIMIT 1
            """, (agent_id,))
            
            vac_row = cursor.fetchone()
            
            # Generate new VAC if needed
            from datetime import timezone
            if not vac_row or vac_row['expires_at'] < datetime.now(timezone.utc):
                vac = generator.generate_vac(agent_id, include_extensions=include_extensions)
            else:
                # Return existing VAC
                vac = generator.get_vac(agent_id)
            
            if not vac:
                raise HTTPException(status_code=404, detail="VAC not found")

            # vac is a W3C VP dict — annotate with agent metadata for convenience
            vac["_meta"] = {
                "agent_id": agent_id,
                "alias": agent.get("alias"),
                "public_key": agent.get("public_key"),
                "wallet_standard": agent.get("wallet_standard"),
                "ows_badge": agent.get("wallet_standard") == "ows",
                "ows_vault_name": agent.get("ows_vault_name"),
            }
            if agent.get("chains"):
                try:
                    chains = agent["chains"]
                    if isinstance(chains, str):
                        chains = json.loads(chains)
                    vac["_meta"]["chains"] = chains
                except Exception:
                    vac["_meta"]["chains"] = []

            return vac
            
        finally:
            cursor.close()
            conn.close()
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VAC retrieval failed: {str(e)}")


@app.post("/vac/{agent_id}/refresh")
async def refresh_vac_credential(agent_id: str, force: bool = False):
    """
    Manually refresh a VAC credential.
    
    Normally VACs refresh automatically every 24 hours.
    Use this endpoint to force an immediate refresh.
    """
    try:
        generator = VACGenerator()
        
        # Verify agent exists and is verified
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT verified FROM observer_agents WHERE agent_id = %s
            """, (agent_id,))
            
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="Agent not found")
            if not result[0]:
                raise HTTPException(status_code=403, detail="Agent not verified")
            
        finally:
            cursor.close()
            conn.close()
        
        # Generate new VAC — returns W3C VP dict
        vp = generator.generate_vac(agent_id)

        # Extract metadata from embedded VC for the response envelope
        vcs = vp.get("verifiableCredential", [])
        first_vc = vcs[0] if vcs else {}

        # Fire vc.issued webhook (best-effort)
        try:
            from webhook_delivery import on_vc_issued
            await on_vc_issued(
                credential_id=first_vc.get("id", ""),
                agent_did=vp.get("holder", ""),
                credential_type="AgentActivityCredential",
            )
        except Exception:
            pass

        return {
            "success": True,
            "vp_id": vp.get("id"),
            "credential_id": first_vc.get("id"),
            "issued_at": first_vc.get("issuanceDate"),
            "expires_at": first_vc.get("expirationDate"),
            "message": "VAC refreshed successfully",
            "vp": vp,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VAC refresh failed: {str(e)}")


class VPPresentRequest(BaseModel):
    """Request body for agent-signed VP submission."""
    holder_private_key_hex: str


@app.put("/agents/{agent_id}/present")
@app.post("/vac/{agent_id}/present")
async def present_vp(agent_id: str, request: VPPresentRequest):
    """
    Submit a holder-signed Verifiable Presentation.

    The agent's private key is used to sign the VP. The signed VP is stored
    and a vp.submitted webhook event is fired.
    """
    try:
        generator = VACGenerator()

        # Verify agent exists
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT verified FROM observer_agents WHERE agent_id = %s", (agent_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Agent not found")
            if not row[0]:
                raise HTTPException(status_code=403, detail="Agent not verified")
        finally:
            cursor.close()
            conn.close()

        vp = generator.generate_vac(
            agent_id,
            holder_private_key_hex=request.holder_private_key_hex,
        )

        # Fire vp.submitted webhook
        try:
            from webhook_delivery import on_vp_submitted
            await on_vp_submitted(vp_id=vp.get("id", ""), holder_did=vp.get("holder", ""))
        except Exception:
            pass  # webhook failure must not block the response

        return {
            "success": True,
            "vp_id": vp.get("id"),
            "holder": vp.get("holder"),
            "vp": vp,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VP presentation failed: {str(e)}")


@app.get("/vac/{agent_id}/history")
def get_vac_history(agent_id: str, limit: int = 10):
    """Get VAC credential history for an agent."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT 
                credential_id,
                vac_version,
                total_transactions,
                total_volume_sats,
                unique_counterparties,
                rails_used,
                issued_at,
                expires_at,
                is_revoked,
                revoked_at,
                vac_payload_hash
            FROM vac_credentials
            WHERE agent_id = %s
            ORDER BY issued_at DESC
            LIMIT %s
        """, (agent_id, limit))
        
        credentials = []
        for row in cursor.fetchall():
            cred = {
                "credential_id": row['credential_id'],
                "version": row['vac_version'],
                "core": {
                    "total_transactions": row['total_transactions'],
                    "total_volume_sats": row['total_volume_sats'],
                    "unique_counterparties": row['unique_counterparties'],
                    "rails_used": row['rails_used']
                },
                "issued_at": row['issued_at'].isoformat(),
                "expires_at": row['expires_at'].isoformat(),
                "is_revoked": row['is_revoked'],
                "payload_hash": row['vac_payload_hash']
            }
            if row['revoked_at']:
                cred["revoked_at"] = row['revoked_at'].isoformat()
            credentials.append(cred)
        
        return {
            "agent_id": agent_id,
            "credentials": credentials,
            "count": len(credentials)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VAC history retrieval failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


# ============================================================
# VP ENDPOINTS (Layer 3 — DB as cache, agent carries authoritative VP)
# ============================================================

class VPVerifyRequest(BaseModel):
    """Request body for VP verification."""
    vp: dict
    # Optional: provide holder public key directly. If omitted, the server
    # only verifies embedded VCs (VP proof verification is skipped).
    holder_public_key_hex: Optional[str] = None


class VPSubmitRequest(BaseModel):
    """Request body for agent VP submission."""
    vp: dict
    agent_id: str


class VPReconstructRequest(BaseModel):
    """Request body for VP reconstruction."""
    agent_id: str
    holder_private_key_hex: Optional[str] = None
    force_regenerate: bool = False


@app.post("/vp/verify")
def verify_vp_endpoint(request: VPVerifyRequest):
    """
    Verify a W3C Verifiable Presentation.

    Layer 3 guarantee: verification is performed entirely from the VP document
    and the OP public key (env var).  No DB lookup is required or performed.

    Checks:
      - W3C structural validity (context, types, holder DID, VC fields)
      - Ed25519Signature2020 proof on each embedded VC (signed by OP)
      - Expiration of each embedded VC
      - Ed25519Signature2020 proof on the VP itself (if holder_public_key_hex provided)
    """
    from vp_reconstructor import validate_vp_structure
    from vc_verifier import verify_vp_with_embedded_vcs, verify_vc, verify_vp

    vp = request.vp
    op_public_key = os.environ.get("OP_PUBLIC_KEY")
    if not op_public_key:
        raise HTTPException(status_code=500, detail="OP_PUBLIC_KEY not configured")

    # 1. Structural checks (no crypto, no DB)
    struct = validate_vp_structure(vp)

    # 2. Verify each embedded VC against OP's public key
    trusted_issuers_raw = os.environ.get("TRUSTED_ISSUERS", "")
    trusted_issuers = set(
        s.strip() for s in trusted_issuers_raw.split(",") if s.strip()
    )
    # OP's own DID is always a trusted issuer
    op_did = os.environ.get("OP_DID", "did:web:observerprotocol.org")
    trusted_issuers.add(op_did)

    vc_results = []
    for vc in vp.get("verifiableCredential", []):
        ok, reason = verify_vc(vc, op_public_key)
        issuer = vc.get("issuer") or ""
        if isinstance(issuer, dict):
            issuer = issuer.get("id", "")
        issuer_trusted = issuer in trusted_issuers
        vc_results.append({
            "id": vc.get("id"),
            "valid": ok,
            "error": None if ok else reason,
            "issuer_trusted": issuer_trusted,
        })

    # 3. Verify VP proof if holder public key provided
    vp_proof_result: Optional[dict] = None
    if request.holder_public_key_hex:
        vp_ok, vp_err = verify_vp(vp, request.holder_public_key_hex)
        vp_proof_result = {"valid": vp_ok, "error": None if vp_ok else vp_err}

    all_vcs_valid = all(r["valid"] for r in vc_results)
    vp_proof_valid = vp_proof_result["valid"] if vp_proof_result is not None else None

    overall_valid = struct["valid"] and all_vcs_valid
    if vp_proof_result is not None:
        overall_valid = overall_valid and vp_proof_valid

    result: dict = {
        "valid": overall_valid,
        "structure": struct,
        "vc_results": vc_results,
    }
    if vp_proof_result is not None:
        result["vp_proof"] = vp_proof_result

    return result


@app.post("/vp/submit")
async def submit_vp_endpoint(request: VPSubmitRequest):
    """
    Accept an agent-submitted Verifiable Presentation.

    The VP is verified (structure + all embedded VC signatures) before being
    stored in the DB cache.  The DB write is best-effort cache — a verification
    failure from the DB side does NOT constitute a rejection of the VP.

    A vp.submitted webhook is fired on success.
    """
    from vp_reconstructor import VPReconstructor, validate_vp_structure
    from vc_verifier import verify_vc

    vp = request.vp
    agent_id = request.agent_id

    op_public_key = os.environ.get("OP_PUBLIC_KEY")
    if not op_public_key:
        raise HTTPException(status_code=500, detail="OP_PUBLIC_KEY not configured")

    # Structural check
    struct = validate_vp_structure(vp)
    if not struct["valid"]:
        raise HTTPException(
            status_code=422,
            detail={"message": "VP structure invalid", "errors": struct["errors"]},
        )

    # Verify embedded VC signatures
    vc_errors = []
    for vc in vp.get("verifiableCredential", []):
        ok, reason = verify_vc(vc, op_public_key)
        if not ok:
            vc_errors.append({"id": vc.get("id"), "error": reason})
    if vc_errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "One or more VCs failed verification", "vc_errors": vc_errors},
        )

    # Store to DB cache (best-effort)
    store_error = None
    try:
        reconstructor = VPReconstructor()
        reconstructor.store_submitted_vp(agent_id, vp)
    except Exception as exc:
        store_error = str(exc)

    # Fire webhook (best-effort)
    try:
        from webhook_delivery import on_vp_submitted
        await on_vp_submitted(
            vp_id=vp.get("id", ""),
            holder_did=vp.get("holder", ""),
        )
    except Exception:
        pass

    response: dict = {
        "success": True,
        "vp_id": vp.get("id"),
        "holder": vp.get("holder"),
        "cached": store_error is None,
    }
    if store_error:
        response["cache_warning"] = store_error
    return response


@app.post("/vp/reconstruct")
def reconstruct_vp_endpoint(request: VPReconstructRequest):
    """
    Reconstruct the VP for an agent.

    Returns the cached VP from the DB if one exists and is valid.
    Otherwise generates a fresh VP from live transaction data (and updates
    the DB cache).

    Use force_regenerate=true to bypass the cache and always issue a new VP.
    """
    from vp_reconstructor import VPReconstructor

    # Verify agent exists
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT verified FROM observer_agents WHERE agent_id = %s",
            (request.agent_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not row[0]:
            raise HTTPException(status_code=403, detail="Agent not verified")
    finally:
        cursor.close()
        conn.close()

    reconstructor = VPReconstructor()
    vp = reconstructor.reconstruct_vp(
        agent_id=request.agent_id,
        holder_private_key_hex=request.holder_private_key_hex,
        force_regenerate=request.force_regenerate,
    )
    return {
        "agent_id": request.agent_id,
        "source": "cache" if not request.force_regenerate else "generated",
        "vp": vp,
    }


# ============================================================
# PARTNER REGISTRY ENDPOINTS
# ============================================================

@app.post("/vac/partners/register")
def register_partner(request: PartnerRegistrationRequest):
    """
    Register a new partner for issuing VAC attestations.
    
    Partners can be:
    - 'corpo': Legal entity verification
    - 'verifier': Identity or credential verification
    - 'counterparty': Counterparty metadata attestation
    - 'infrastructure': Infrastructure providers
    """
    try:
        registry = PartnerRegistry()
        result = registry.register_partner(
            partner_name=request.partner_name,
            partner_type=request.partner_type,
            public_key=request.public_key,
            webhook_url=request.webhook_url,
            metadata=request.metadata
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Partner registration failed: {str(e)}")


@app.get("/vac/partners")
def list_partners(
    partner_type: Optional[str] = None,
    is_active: Optional[bool] = None
):
    """List all registered partners with optional filtering."""
    try:
        registry = PartnerRegistry()
        partners = registry.list_partners(partner_type=partner_type, is_active=is_active)
        return {"partners": partners, "count": len(partners)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Partner listing failed: {str(e)}")


@app.get("/vac/partners/{partner_id}")
def get_partner(partner_id: str):
    """Get details for a specific partner."""
    try:
        registry = PartnerRegistry()
        partner = registry.get_partner(partner_id)
        if not partner:
            raise HTTPException(status_code=404, detail="Partner not found")
        return partner
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Partner retrieval failed: {str(e)}")


# ============================================================
# ATTESTATION ENDPOINTS
# ============================================================

@app.post("/vac/partners/{partner_id}/attest")
def issue_attestation(partner_id: str, request: AttestationRequest):
    """
    Issue a partner attestation for an agent.
    
    Attestations attach verified claims to an agent's VAC credential.
    Common uses:
    - Corpo partners attest legal_entity_id
    - Verifiers attest identity verification level
    - Counterparties attest service relationships
    """
    try:
        registry = PartnerRegistry()
        result = registry.issue_attestation(
            partner_id=partner_id,
            agent_id=request.agent_id,
            claims=request.claims,
            credential_id=request.credential_id,
            expires_in_days=request.expires_in_days,
            attestation_signature=request.attestation_signature
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attestation issuance failed: {str(e)}")


@app.get("/vac/{agent_id}/attestations")
def get_agent_attestations(
    agent_id: str,
    partner_type: Optional[str] = None
):
    """Get all partner attestations for an agent."""
    try:
        registry = PartnerRegistry()
        attestations = registry.get_attestations_for_agent(agent_id, partner_type=partner_type)
        return {
            "agent_id": agent_id,
            "attestations": attestations,
            "count": len(attestations)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attestation retrieval failed: {str(e)}")


# ============================================================
# COUNTERPARTY METADATA ENDPOINTS
# ============================================================

@app.post("/vac/{credential_id}/counterparty")
def add_counterparty_metadata(
    credential_id: str,
    request: CounterpartyMetadataRequest
):
    """
    Add counterparty metadata hash to a VAC credential.
    
    The actual metadata is hashed and optionally stored on IPFS.
    Only the hash is anchored to the VAC for privacy.
    """
    try:
        registry = PartnerRegistry()
        result = registry.add_counterparty_metadata(
            credential_id=credential_id,
            counterparty_id=request.counterparty_id,
            metadata=request.metadata,
            ipfs_cid=request.ipfs_cid
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Counterparty metadata addition failed: {str(e)}")


@app.get("/vac/{credential_id}/counterparty")
def get_counterparty_metadata(credential_id: str):
    """Get all counterparty metadata hashes for a VAC credential."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT 
                counterparty_id,
                metadata_hash,
                merkle_root,
                ipfs_cid,
                created_at
            FROM counterparty_metadata
            WHERE credential_id = %s
            ORDER BY created_at DESC
        """, (credential_id,))
        
        metadata = [{
            "counterparty_id": row['counterparty_id'],
            "metadata_hash": row['metadata_hash'],
            "merkle_root": row['merkle_root'],
            "ipfs_cid": row['ipfs_cid'],
            "created_at": row['created_at'].isoformat()
        } for row in cursor.fetchall()]
        
        return {
            "credential_id": credential_id,
            "counterparties": metadata,
            "count": len(metadata)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Counterparty metadata retrieval failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


# ============================================================
# REVOCATION REGISTRY ENDPOINTS
# ============================================================

@app.get("/vac/revocations")
def get_revocation_registry(
    agent_id: Optional[str] = None,
    limit: int = 50
):
    """
    Get the VAC revocation registry.
    
    Lists all revoked credentials with revocation reasons.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        query = """
            SELECT 
                r.revocation_id,
                r.credential_id,
                r.agent_id,
                r.revoked_at,
                r.reason,
                r.details,
                r.webhook_delivered,
                p.partner_name as revoked_by_name
            FROM vac_revocation_registry r
            LEFT JOIN partner_registry p ON p.partner_id = r.revoked_by
            WHERE 1=1
        """
        params = []
        
        if agent_id:
            query += " AND r.agent_id = %s"
            params.append(agent_id)
        
        query += " ORDER BY r.revoked_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        
        revocations = []
        for row in cursor.fetchall():
            rev = {
                "revocation_id": str(row['revocation_id']),
                "credential_id": row['credential_id'],
                "agent_id": row['agent_id'],
                "revoked_at": row['revoked_at'].isoformat(),
                "reason": row['reason'],
                "webhook_delivered": row['webhook_delivered']
            }
            if row['details']:
                rev["details"] = row['details']
            if row['revoked_by_name']:
                rev["revoked_by"] = row['revoked_by_name']
            revocations.append(rev)
        
        return {
            "revocations": revocations,
            "count": len(revocations)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revocation registry retrieval failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.post("/vac/{credential_id}/revoke")
def revoke_credential(
    credential_id: str,
    reason: str,
    details: Optional[str] = None,
    revoked_by: Optional[str] = None
):
    """
    Revoke a VAC credential.
    
    Reasons: 'compromise', 'expiry', 'violation', 'request', 'other'
    
    Revoked credentials are permanently invalidated and cannot be renewed.
    A new credential must be issued.
    """
    valid_reasons = ['compromise', 'expiry', 'violation', 'request', 'other']
    
    if reason not in valid_reasons:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reason. Must be one of: {', '.join(valid_reasons)}"
        )
    
    try:
        generator = VACGenerator()
        generator.revoke_vac(credential_id, reason, revoked_by)
        
        return {
            "success": True,
            "credential_id": credential_id,
            "reason": reason,
            "revoked_at": datetime.utcnow().isoformat(),
            "message": "Credential revoked successfully"
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Credential revocation failed: {str(e)}")


# ============================================================
# CORPO MIGRATION ENDPOINTS
# ============================================================

@app.post("/vac/corpo/register")
def register_corpo_partner_endpoint(
    legal_entity_name: str,
    public_key: str,
    webhook_url: Optional[str] = None
):
    """
    Register a Corpo legal wrapper partner.
    
    Corpo partners handle legal_entity_id attestations.
    Per VAC v0.3, legal_entity_id is moved from agent table to partner attestations.
    """
    try:
        result = register_corpo_partner(
            legal_entity_name=legal_entity_name,
            public_key=public_key,
            webhook_url=webhook_url
        )
        return {
            **result,
            "note": "Corpo partner registered. Use /vac/partners/{id}/attest to issue legal_entity_id attestations."
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Corpo registration failed: {str(e)}")


@app.post("/vac/corpo/{partner_id}/attest-entity")
def corpo_attest_legal_entity(
    partner_id: str,
    agent_id: str,
    legal_entity_id: str,
    jurisdiction: Optional[str] = None,
    compliance_status: Optional[str] = None,
    attestation_signature: Optional[str] = None
):
    """
    Issue a Corpo legal entity attestation.
    
    This is the VAC v0.3 way to attach legal_entity_id to an agent.
    The legal_entity_id is stored in partner_attestations, not the agent table.
    """
    try:
        result = issue_corpo_attestation(
            partner_id=partner_id,
            agent_id=agent_id,
            legal_entity_id=legal_entity_id,
            jurisdiction=jurisdiction,
            compliance_status=compliance_status,
            attestation_signature=attestation_signature
        )
        return {
            **result,
            "note": "Legal entity attestation issued. This replaces the legacy agent.legal_entity_id field."
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Legal entity attestation failed: {str(e)}")


@app.get("/vac/{agent_id}/legal-entity")
def get_legal_entity_attestation(agent_id: str):
    """
    Get the legal entity attestation for an agent (VAC v0.3 format).
    
    Returns legal_entity_id from partner attestations, not the legacy agent table.
    """
    try:
        registry = PartnerRegistry()
        attestations = registry.get_attestations_for_agent(agent_id, partner_type='corpo')
        
        if not attestations:
            # Fallback: check legacy field during migration period
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                cursor.execute("""
                    SELECT legal_entity_id FROM observer_agents WHERE agent_id = %s
                """, (agent_id,))
                row = cursor.fetchone()
                if row and row['legal_entity_id']:
                    return {
                        "agent_id": agent_id,
                        "legal_entity_id": row['legal_entity_id'],
                        "source": "legacy_agent_table",
                        "note": "This agent has not migrated to VAC v0.3 partner attestations yet"
                    }
            finally:
                cursor.close()
                conn.close()
            
            raise HTTPException(status_code=404, detail="No legal entity attestation found")
        
        # Return most recent corpo attestation
        latest = attestations[0]
        return {
            "agent_id": agent_id,
            "legal_entity_id": latest['claims'].get('legal_entity_id'),
            "jurisdiction": latest['claims'].get('jurisdiction'),
            "compliance_status": latest['claims'].get('compliance_status'),
            "attested_by": latest['partner_name'],
            "attested_at": latest['issued_at'],
            "source": "vac_partner_attestation",
            "format": "VAC v0.3"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Legal entity retrieval failed: {str(e)}")


# ============================================================
# ORGANIZATION REGISTRY ENDPOINTS (Phase 1: Organizational Attestation)
# ============================================================

@app.post("/observer/register-org", status_code=201)
def register_organization_endpoint(request: OrganizationRegistrationRequest):
    """
    Register a new organization in the Observer Protocol registry.
    
    Organizations are credential issuers (not agents) that can issue attestations
    that agents include in their VAC credentials.
    """
    try:
        result = org_registry.register_organization(
            name=request.name,
            domain=request.domain,
            master_public_key=request.master_public_key,
            revocation_public_key=request.revocation_public_key,
            key_type=request.key_type,
            display_name=request.display_name,
            description=request.description,
            contact_email=request.contact_email,
            metadata=request.metadata or {}
        )
        return result
    except OrganizationAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Organization registration failed: {str(e)}")


@app.get("/observer/orgs/{org_id}")
def get_organization_endpoint(org_id: str, include_keys: bool = Query(False)):
    """Get organization details by ID."""
    try:
        result = org_registry.get_organization(org_id, include_public_keys=include_keys)
        return result
    except OrganizationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organization: {str(e)}")


@app.get("/observer/orgs/by-domain/{domain}")
def get_organization_by_domain_endpoint(domain: str):
    """Get organization by domain."""
    try:
        result = org_registry.get_organization_by_domain(domain)
        return result
    except OrganizationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organization: {str(e)}")


@app.get("/observer/orgs/by-key/{key_hash}")
def get_organization_by_key_hash_endpoint(key_hash: str):
    """Get organization by public key hash (master or revocation)."""
    try:
        result = org_registry.get_organization_by_key_hash(key_hash)
        return result
    except OrganizationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organization: {str(e)}")


@app.get("/observer/orgs")
def list_organizations_endpoint(
    status: Optional[str] = Query('active'),
    verification_status: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """List organizations with optional filtering."""
    try:
        result = org_registry.list_organizations(
            status=status,
            verification_status=verification_status,
            domain_filter=domain,
            limit=limit,
            offset=offset
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list organizations: {str(e)}")


@app.post("/observer/orgs/{org_id}/revoke")
def revoke_organization_endpoint(org_id: str, request: OrganizationRevocationRequest):
    """Revoke an organization (soft delete)."""
    try:
        result = org_registry.revoke_organization(
            org_id=org_id,
            reason=request.reason,
            revocation_signature=request.revocation_signature
        )
        return result
    except OrganizationNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except OrganizationRevokedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")


# ============================================================
# END ORGANIZATION REGISTRY ENDPOINTS
# ============================================================


# ============================================================
# DID RESOLUTION ENDPOINTS (Layer 1)
# ============================================================

@app.get("/.well-known/did.json", tags=["DID"])
def get_op_did_document():
    """
    Return Observer Protocol's own DID Document.
    Required by any verifier checking OP-issued VC signatures.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT document FROM op_did_document ORDER BY updated_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="OP DID Document not initialised. Set OP_PUBLIC_KEY and restart.",
        )
    doc = row["document"]
    if isinstance(doc, str):
        import json as _json
        doc = _json.loads(doc)
    return doc


@app.get("/agents/{agent_id}/did.json", tags=["DID"])
def get_agent_did_document(agent_id: str):
    """
    Return the DID Document for an agent.
    Contains the agent's current Ed25519 public key.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT did_document, agent_did FROM observer_agents WHERE agent_id = %s",
            (agent_id,),
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    if not row["did_document"]:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{agent_id}' has no DID Document (key may be non-Ed25519)",
        )
    doc = row["did_document"]
    if isinstance(doc, str):
        import json as _json
        doc = _json.loads(doc)
    return doc


@app.get("/orgs/{org_id}/did.json", tags=["DID"])
def get_org_did_document(org_id: str):
    """
    Return the DID Document for an organization.
    Contains the org's current public key.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT did_document, org_did FROM organizations WHERE org_id = %s",
            (org_id,),
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Organization '{org_id}' not found")
    if not row["did_document"]:
        raise HTTPException(
            status_code=404,
            detail=f"Organization '{org_id}' has no DID Document",
        )
    doc = row["did_document"]
    if isinstance(doc, str):
        import json as _json
        doc = _json.loads(doc)
    return doc


class KeyRotationRequest(BaseModel):
    """Request body for agent key rotation."""
    new_public_key: str

    class Config:
        extra = "forbid"


@app.put("/agents/{agent_id}/keys", tags=["DID"])
def rotate_agent_key(agent_id: str, request: KeyRotationRequest):
    """
    Rotate an agent's key.

    Builds a new DID Document from the new public key and stores it.
    The DID string itself never changes — only the verificationMethod is updated.
    """
    if not request.new_public_key or len(request.new_public_key) < 32:
        raise HTTPException(
            status_code=400,
            detail="new_public_key must be at least 32 characters",
        )

    try:
        new_did_document = build_agent_did_document(agent_id, request.new_public_key)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Could not build DID Document from new_public_key: {e}",
        )

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT agent_id, agent_did FROM observer_agents WHERE agent_id = %s",
            (agent_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

        cursor.execute(
            """
            UPDATE observer_agents
            SET public_key = %s,
                did_document = %s,
                did_updated_at = NOW()
            WHERE agent_id = %s
            """,
            (
                request.new_public_key,
                json.dumps(new_did_document),
                agent_id,
            ),
        )
        conn.commit()

        # Refresh in-memory key cache
        persist_public_key(agent_id, request.new_public_key, verified=False)

        return {
            "agent_id": agent_id,
            "agent_did": row["agent_did"],
            "did_document": new_did_document,
            "message": "Key rotation successful. DID Document updated. DID string unchanged.",
        }
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


# ============================================================
# END DID RESOLUTION ENDPOINTS
# ============================================================


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ── Alias routes for frontend compatibility ──────────────────────────────────

@app.get("/observer/transactions")
def get_transactions(limit: int = 50, agent_id: str = None):
    """Alias for /observer/feed with optional agent_id filter."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        if agent_id:
            cursor.execute("""
                SELECT ve.event_id, ve.event_type, ve.protocol, ve.transaction_hash,
                       ve.time_window, ve.amount_bucket,
                       COALESCE(ve.amount_sats, 21000) as amount_sats,
                       ve.direction, ve.service_description, ve.preimage,
                       ve.counterparty_id, ve.verified, ve.created_at,
                       oa.alias as agent_alias
                FROM verified_events ve
                LEFT JOIN observer_agents oa ON ve.agent_id = oa.agent_id
                WHERE ve.agent_id = %s
                ORDER BY ve.created_at DESC LIMIT %s
            """, (agent_id, limit))
        else:
            cursor.execute("""
                SELECT ve.event_id, ve.event_type, ve.protocol, ve.transaction_hash,
                       ve.time_window, ve.amount_bucket,
                       COALESCE(ve.amount_sats, 21000) as amount_sats,
                       ve.direction, ve.service_description, ve.preimage,
                       ve.counterparty_id, ve.verified, ve.created_at,
                       oa.alias as agent_alias
                FROM verified_events ve
                LEFT JOIN observer_agents oa ON ve.agent_id = oa.agent_id
                ORDER BY ve.created_at DESC LIMIT %s
            """, (limit,))
        events = [dict(r) for r in cursor.fetchall()]
        for e in events:
            if e.get("created_at"):
                e["created_at"] = e["created_at"].isoformat()
        return {"transactions": events, "events": events, "total": len(events)}
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()


@app.get("/observer/stats")
def get_observer_stats(agent_id: str = None):
    """Aggregated stats for the registry dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents")
        agents_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM verified_events")
        tx_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM vac_credentials WHERE expires_at IS NULL OR expires_at > NOW()")
        vac_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(DISTINCT protocol) as count FROM verified_events")
        rails_count = cursor.fetchone()["count"]

        return {
            "registered_agents": agents_count,
            "verified_transactions": tx_count,
            "vacs_issued": vac_count,
            "active_rails": rails_count,
            "total_agents": agents_count,
            "total_transactions": tx_count,
            "total_vacs": vac_count
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()
