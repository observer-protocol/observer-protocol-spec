#!/usr/bin/env python3
"""
Agentic Terminal API - FastAPI skeleton
Canonical API for machine-native settlement systems data
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
from typing import Optional, List
from datetime import datetime, timedelta
import os
import hashlib
import secrets
import uuid
import base64
import sys
sys.path.insert(0, '/home/futurebit/.openclaw/workspace/observer-protocol')
from crypto_verification import verify_signature_simple, cache_public_key, get_cached_public_key

# Flag for crypto availability - cryptography library is confirmed available
ECDSA_AVAILABLE = True


def verify_ecdsa_signature(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify an ECDSA signature (SECP256k1) against a message and public key.
    
    Args:
        message: The original message that was signed (bytes)
        signature_hex: The signature in hex format (64 bytes raw r||s, or DER)
        public_key_hex: The public key in hex format (33 bytes compressed or 65 bytes uncompressed)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Decode signature
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Decode public key
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # Load the public key
        # Try uncompressed first (65 bytes starting with 04)
        if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            # Uncompressed format: 04 || x || y (32 bytes each)
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(public_key_bytes[1:33], 'big'),
                y=int.from_bytes(public_key_bytes[33:65], 'big'),
                curve=ec.SECP256K1()
            )
        elif len(public_key_bytes) == 33:
            # Compressed format: 02/03 || x (32 bytes)
            # Note: cryptography library may need uncompressed, so we'd need to decompress
            # For now, we'll try but this might need additional handling
            return False  # Compressed key support requires decompression
        else:
            return False  # Invalid public key format
        
        public_key = public_numbers.public_key()
        
        # Parse signature
        if len(sig_bytes) == 64:
            # Raw format: r || s
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
            
            # Convert to DER format for cryptography library
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            signature_der = encode_dss_signature(r, s)
        elif len(sig_bytes) >= 68 and len(sig_bytes) <= 72:
            # Already DER format
            signature_der = sig_bytes
        else:
            return False  # Invalid signature format
        
        # Verify the signature
        public_key.verify(
            signature_der,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return True
        
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False


DB_URL = "postgresql://agentic_terminal:at_secure_2026@localhost/agentic_terminal_db"

app = FastAPI(
    title="Agentic Terminal API",
    description="Canonical structured database for machine-native settlement systems",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://observerprotocol.org",
        "https://www.observerprotocol.org",
        "https://agenticterminal.ai",
        "https://www.agenticterminal.ai",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def get_db_connection():
    """Get database connection."""
    return psycopg2.connect(DB_URL)

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
    alias: Optional[str] = None
):
    """Register a new agent with the Observer Protocol."""
    # Generate agent_id as SHA256 hash of public_key
    agent_id = hashlib.sha256(public_key.encode()).hexdigest()[:32]
    public_key_hash = hashlib.sha256(public_key.encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO observer_agents (agent_id, public_key_hash, agent_name, alias, framework, verified, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (agent_id) DO UPDATE SET
                agent_name = EXCLUDED.agent_name,
                alias = EXCLUDED.alias,
                framework = EXCLUDED.framework
            RETURNING agent_id
        """, (agent_id, public_key_hash, agent_name, alias or agent_name, framework, False))
        
        conn.commit()

        # Cache the public key for verification (temporary until DB schema updated)
        cache_public_key(agent_id, public_key)
        
        return {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "verification_status": "registered",
            "message": "Registration successful. Agent identity recorded in Observer Protocol registry.",
            "note": "Public key cached for challenge-response verification",
            "next_steps": [
                "1. Generate challenge: POST /observer/challenge?agent_id=<id>",
                "2. Sign and verify: POST /observer/verify-agent",
                "3. Badge available at: GET /observer/badge/{agent_id}.svg"
            ],
            "badge_url": f"https://api.agenticterminal.ai/observer/badge/{agent_id}.svg",
            "profile_url": f"https://observerprotocol.org/agents/{agent_id}"
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
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
            SELECT agent_id, public_key_hash FROM observer_agents 
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
            SELECT agent_id, public_key_hash, verified 
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
        
        # Get the cached public key
        public_key_hex = get_cached_public_key(agent_id)
        
        if not public_key_hex:
            # Try to get from agent record if stored there
            # For now, we need the public key to verify
            raise HTTPException(
                status_code=400, 
                detail="Public key not found. Please re-register with the full public key."
            )
        
        # Verify the signature cryptographically
        nonce_bytes = challenge["nonce"].encode('utf-8')
        is_valid = verify_signature_simple(nonce_bytes, signed_challenge, public_key_hex)
        
        if not is_valid:
            raise HTTPException(
                status_code=400, 
                detail="Signature verification failed. The signature does not match the public key."
            )
        
        verification_successful = True
        verification_method = "challenge_response_v2_real"
        
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
    """Submit a verified transaction to the Observer Protocol."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify agent exists and is verified
        cursor.execute("""
            SELECT verified FROM observer_agents WHERE agent_id = %s
        """, (agent_id,))
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Agent not found")
        if not result[0]:
            raise HTTPException(status_code=403, detail="Agent not verified")
        
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
        cursor.execute("SELECT COUNT(*) FROM verified_events")
        count = cursor.fetchone()[0]
        event_id = f"event-{agent_id[:12]}-{count + 1:04d}"
        
        # Determine event_type and direction from metadata
        event_type = "payment.executed"
        direction = "outbound"
        counterparty_id = None
        service_description = None
        
        if optional_metadata:
            try:
                import json
                metadata = json.loads(optional_metadata)
                event_type = metadata.get("event_type", "payment.executed")
                direction = metadata.get("direction", "outbound")
                counterparty_id = metadata.get("counterparty_id")
                service_description = metadata.get("service_description")
            except:
                pass
        
        stored_at = datetime.utcnow()
        
        cursor.execute("""
            INSERT INTO verified_events (
                event_id, agent_id, counterparty_id, event_type, protocol,
                transaction_hash, time_window, amount_bucket, direction,
                service_description, verified, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            event_id, agent_id, counterparty_id, event_type, protocol,
            transaction_reference, timestamp[:10] if timestamp else None,
            amount_bucket, direction, service_description, True
        ))
        
        conn.commit()
        
        return {
            "event_id": event_id,
            "verified": True,
            "stored_at": stored_at.isoformat()
        }
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
    """Get last 50 verified events (anonymized — no agent_id in response)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT event_type, protocol, time_window, amount_bucket, verified, created_at
            FROM verified_events
            ORDER BY created_at DESC
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


@app.get("/observer/agents/{agent_id}")
def get_agent_profile(agent_id: str):
    """Public agent profile — name, verification status, event count, first seen."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT agent_id, agent_name, alias, framework,
                   verified, verified_at, created_at, access_level
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

        return {
            "agent_id": agent_id,
            "agent_name": agent["agent_name"],
            "alias": agent["alias"],
            "framework": agent["framework"],
            "access_level": agent["access_level"],
            "verified": agent["verified"],
            "verified_at": agent["verified_at"].isoformat() if agent["verified_at"] else None,
            "first_seen": agent["created_at"].isoformat(),
            "sequence_number": seq,
            "verified_tx_count": tx_count,
            "badge_url": f"https://api.agenticterminal.ai/observer/badge/{agent_id}.svg",
            "profile_url": f"https://observerprotocol.org/agents/{agent_id}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
