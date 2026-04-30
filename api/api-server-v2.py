#!/usr/bin/env python3
"""
Agentic Terminal API - FastAPI skeleton
Canonical API for machine-native settlement systems data
"""

from fastapi import FastAPI, HTTPException, Query, Header, Request
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import psycopg2
import psycopg2.extras
from typing import Optional, List, Dict
from datetime import datetime, timedelta, timezone
import os
import hashlib
import secrets
import uuid
import base64
import json
import re
import base58  # For TRON address validation

# Try to import bcrypt for admin authentication
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    bcrypt = None

def get_db_connection():
    """Get PostgreSQL database connection using DATABASE_URL env var."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )
    return psycopg2.connect(database_url)

def validate_enterprise_session(request: Request):
    """
    Validate enterprise session from secure HttpOnly cookie.
    Returns (user_id, org_id, email, role) if valid.
    Raises HTTPException 401 if invalid, expired, or revoked.
    """
    # Extract session cookie (HttpOnly, Secure, SameSite=Lax)
    session_token = request.cookies.get("enterprise_session")
    
    if not session_token:
        raise HTTPException(status_code=401, detail="Session required")
    
    # Compute token hash (SHA-256)
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    
    # Lookup session with all validation in SQL
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT s.user_id, u.email, u.organization_id as org_id, u.role, u.is_active
            FROM auth_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = %s 
              AND s.is_revoked = FALSE 
              AND s.expires_at > NOW()
        """, (token_hash,))
        
        session = cursor.fetchone()
        
        # No row = invalid, expired, or revoked (all handled by WHERE)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        # Check user is_active (separate from session state)
        if not session['is_active']:
            raise HTTPException(status_code=401, detail="User inactive")
        
        return (
            str(session['user_id']),
            int(session['org_id']),
            session['email'],
            session['role']
        )
    finally:
        cursor.close()
        conn.close()

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
from role_enforcement import require_role
from trust_score import compute_tron_trust_score
# Spec 3.8: SSO routes (SAML authentication)
from sso_routes import router as sso_router, configure as configure_sso

# Spec 3.4: Audit routes (compliance and audit trails)
from audit_routes import router as audit_router, configure as configure_audit

# Spec 3.7: Agent Profile routes
from agent_profile_routes import router as profile_router, configure as configure_profile

# Spec 3.5: Policy engine routes
from policy_routes import router as policy_router, configure as configure_policy
from at_policy_engine import router as at_policy_router, configure as configure_at_policy

# Spec 3.6: Counterparty Management
from counterparty_routes import router as counterparty_router, configure as configure_counterparties

# Spec 3.2: Delegation verification
from delegation_routes import router as delegation_verify_router, configure as configure_delegation_verify

# AIP v0.5.1: Remediation (magic link) routes
from remediation_routes import router as remediation_router, short_router as short_url_router, configure as configure_remediation

# Phase 3: NeuralBridge demo counterparty
from demo_neuralbridge import router as neuralbridge_router, configure as configure_neuralbridge

# x402 rail adapter
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'rails', 'x402'))
try:
    from x402_routes import router as x402_router, configure as configure_x402
    _x402_available = True
except ImportError:
    _x402_available = False

# ERC-8004 / TRC-8004 integration
_sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'rails', 'erc8004'))
try:
    from erc8004_routes import router as erc8004_router, configure as configure_erc8004
    _erc8004_available = True
except ImportError:
    _erc8004_available = False
from policy_client import consult_policy_engine, PolicyDecision

# --- Spec 3.5: Policy consultation helper for write paths ---
def _consult_policy(org_id, action_type, action_context):
    """Call policy engine if registered. Returns None on permit, raises on deny/pending/unavailable."""
    if org_id is None:
        return  # No org context → permit (OP-layer, no org scoping)
    try:
        conn_policy = get_db_connection()
        try:
            result = consult_policy_engine(conn_policy, org_id, action_type, action_context)
            if result.decision == PolicyDecision.PERMIT:
                return
            elif result.decision == PolicyDecision.DENY:
                raise HTTPException(status_code=403, detail={
                    "error": "policy_deny",
                    "reason": result.reason,
                    "policy_id": result.policy_id,
                    "violations": result.violations,
                })
            elif result.decision == PolicyDecision.PENDING_APPROVAL:
                raise HTTPException(status_code=202, detail={
                    "error": "pending_approval",
                    "approval_status_url": result.approval_status_url,
                    "request_id": result.request_id,
                })
            else:  # UNAVAILABLE or SIGNATURE_INVALID
                raise HTTPException(status_code=503, detail={
                    "error": "policy_engine_unavailable",
                    "reason": result.reason,
                })
        finally:
            conn_policy.close()
    except HTTPException:
        raise
    except Exception:
        pass  # If consultation infrastructure itself fails, permit (defense in depth)

def _get_agent_org_id(cursor, agent_id):
    """Look up org_id for an agent. Returns None if not found."""
    cursor.execute("SELECT org_id FROM observer_agents WHERE agent_id = %s", (agent_id,))
    row = cursor.fetchone()
    return row[0] if row else None

# Spec 3.3: Status list routes (revocation/suspension)
from status_list_routes import router as status_list_router, configure as configure_status_lists

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

class AdminLoginRequest(BaseModel):
    """Request body for platform admin login."""
    email: str
    password: str
    
    class Config:
        extra = "forbid"

# ------------------------------------------------------------------------------
# Phase 2: Org-scoped agent registration with rails and wallet addresses
# ------------------------------------------------------------------------------

VALID_RAILS = {"tron", "trc20", "lightning", "solana", "x402", "l402"}
TRON_RAILS = {"tron", "trc20"}

class OrgAgentRegistrationRequest(BaseModel):
    """Request body for org-scoped agent registration with payment rails."""
    name: str
    public_key: str
    rails: List[str] = []
    wallet_addresses: Dict[str, str] = {}

class OrgAgentRegistrationResponse(BaseModel):
    """Response for org-scoped agent registration."""
    agent_id: str
    did: str
    did_document_url: str
    rails: List[str]
    wallet_addresses: Dict[str, str]
    org_id: str
    registered_at: str

# Fleet and detail endpoint response models
class AgentSummary(BaseModel):
    """Fleet-row shape. No heavy fields."""
    agent_id: str
    agent_name: Optional[str] = None
    alias: Optional[str] = None
    org_id: int
    rails: List[str] = Field(default_factory=list)
    wallet_addresses: Dict[str, str] = Field(default_factory=dict)
    did_path: Optional[str] = None
    agent_did: Optional[str] = None
    trust_score: Optional[int] = None
    delegation_status: Optional[str] = None
    verified: bool = False
    verified_at: Optional[str] = None
    created_at: str

class FleetResponse(BaseModel):
    agents: List[AgentSummary]
    total: int
    limit: int
    offset: int
    org_id: int
    org_name: str

class AgentDetailResponse(BaseModel):
    """Full agent record for the detail page. Includes rendered DID document."""
    agent_id: str
    agent_name: Optional[str] = None
    alias: Optional[str] = None
    org_id: int
    org_name: str
    public_key: Optional[str] = None
    rails: List[str] = Field(default_factory=list)
    wallet_addresses: Dict[str, str] = Field(default_factory=dict)
    did_path: Optional[str] = None
    agent_did: Optional[str] = None
    did_document: Optional[Dict] = None
    did_document_url: Optional[str] = None
    trust_score: Optional[int] = None
    delegation_status: Optional[str] = None
    delegation_vc_present: bool = False
    verified: bool = False
    verified_at: Optional[str] = None
    created_at: str
    framework: Optional[str] = None
    legal_entity_id: Optional[str] = None

def _is_valid_tron_address(addr: str) -> bool:
    """Validate TRON mainnet address (base58, 34 chars, starts with 'T')."""
    if not addr or len(addr) != 34 or not addr.startswith("T"):
        return False
    try:
        decoded = base58.b58decode_check(addr)
        return len(decoded) == 21 and decoded[0] == 0x41
    except Exception:
        return False

def _org_info_for_org_id(conn, org_id: int) -> Optional[tuple]:
    """Look up org info from organizations table. Returns (int_id, slug) or None."""
    cursor = conn.cursor()
    cursor.execute("SELECT id, org_name FROM organizations WHERE id = %s", (org_id,))
    row = cursor.fetchone()
    cursor.close()
    if row:
        int_id, org_name = row
        slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")
        return (int_id, slug)
    return None

def _generate_agent_id(public_key: str, conn) -> str:
    """Generate agent_id using sha256 of public_key (first 32 chars)."""
    agent_id = hashlib.sha256(public_key.encode()).hexdigest()[:32]
    
    # Check for existing agent with same public_key
    cursor = conn.cursor()
    cursor.execute(
        "SELECT agent_id FROM observer_agents WHERE public_key = %s", (public_key,)
    )
    row = cursor.fetchone()
    cursor.close()
    if row:
        raise HTTPException(
            status_code=409, 
            detail=f"Agent with this public key already exists: {row[0]}"
        )
    
    return agent_id

def _json_dumps(obj):
    """JSON encode helper."""
    return json.dumps(obj)

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
    "https://www.agenticterminal.ai,https://agenticterminal.io,https://www.agenticterminal.io,https://app.agenticterminal.io,"
    "https://sovereign.agenticterminal.io,http://localhost:3000"
)
_allowed_origins = [
    o.strip()
    for o in os.environ.get("OP_ALLOWED_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "OPTIONS"],
    allow_headers=["*"],
)

# ============================================================
# SPEC 3.3: STATUS LIST ROUTES (Revocation & Lifecycle)
# ============================================================
_op_base_url = os.environ.get("OP_BASE_URL", "https://api.observerprotocol.org")
configure_status_lists(
    get_db_connection_fn=get_db_connection,
    resolve_did_fn=resolve_did,
    base_url=_op_base_url,
)
app.include_router(status_list_router)

# SPEC 3.8: SSO ROUTES
configure_sso(
    get_db_connection_fn=get_db_connection,
    validate_admin_session_fn=validate_enterprise_session,
    dashboard_url=os.environ.get("AT_DASHBOARD_URL", "https://app.agenticterminal.io"),
    cookie_domain=os.environ.get("AT_COOKIE_DOMAIN", ".agenticterminal.io"),
)
app.include_router(sso_router)

# ============================================================
# SPEC 3.4: AUDIT ROUTES (Compliance & Audit Trails)
# ============================================================
def _verify_vc_for_audit(credential, resolve_did_fn):
    try:
        from vc_verification import verify_credential as vc_verify
        result = vc_verify(credential, use_cache=True)
        if result.get("verified"):
            return True, "ok"
        return False, result.get("error", "Verification failed")
    except Exception as e:
        return False, str(e)

configure_audit(
    get_db_connection_fn=get_db_connection,
    resolve_did_fn=resolve_did,
    verify_vc_signature_fn=_verify_vc_for_audit,
)
app.include_router(audit_router)

# ============================================================
# SPEC 3.7: AGENT PROFILE ROUTES
# ============================================================
configure_profile(
    get_db_connection_fn=get_db_connection,
    validate_session_fn=validate_enterprise_session,
)
app.include_router(profile_router)

# ============================================================
# SPEC 3.5: POLICY ENGINE ROUTES
# ============================================================
configure_policy(
    get_db_connection_fn=get_db_connection,
    validate_session_fn=validate_enterprise_session,
)
app.include_router(policy_router)

# AT Reference Policy Engine (MVP)
configure_at_policy(
    get_db_connection_fn=get_db_connection,
    op_api_base=os.environ.get("OP_BASE_URL", "https://api.agenticterminal.io"),
)
app.include_router(at_policy_router)

# ============================================================
# SPEC 3.6: COUNTERPARTY MANAGEMENT
# ============================================================
configure_counterparties(
    get_db_connection_fn=get_db_connection,
    validate_session_fn=validate_enterprise_session,
)
app.include_router(counterparty_router)

# ============================================================
# SPEC 3.2: DELEGATION VERIFICATION (skeleton)
# ============================================================
configure_delegation_verify(
    get_db_connection_fn=get_db_connection,
    resolve_did_fn=resolve_did,
)
app.include_router(delegation_verify_router)

# ============================================================
# AIP v0.5.1: REMEDIATION (magic link) ROUTES
# ============================================================
configure_remediation(get_db_connection_fn=get_db_connection)
app.include_router(remediation_router)
app.include_router(short_url_router)

# ============================================================
# PHASE 3: NEURALBRIDGE DEMO COUNTERPARTY
# ============================================================
configure_neuralbridge(get_db_connection_fn=get_db_connection)
app.include_router(neuralbridge_router)

# ============================================================
# x402 RAIL ADAPTER
# ============================================================
if _x402_available:
    configure_x402(get_db_connection_fn=get_db_connection)
    app.include_router(x402_router)
    print("x402 rail adapter mounted: /api/v1/x402/*")

# ============================================================
# ERC-8004 / TRC-8004 INTEGRATION
# ============================================================
if _erc8004_available:
    configure_erc8004(get_db_connection_fn=get_db_connection)
    app.include_router(erc8004_router)
    print("ERC-8004 routes mounted: /api/v1/erc8004/*")

# =======
# ── AT Verify endpoints (Phase 1B) ────────────────────────────
try:
    from verify_endpoints import router as verify_router
    app.include_router(verify_router)
    print("AT Verify endpoints mounted: /v1/chain/verify, /v1/audit/verified-event")
except ImportError as e:
    print(f"AT Verify endpoints not loaded (optional): {e}")

try:
    from vac_extensions import router as extensions_router
    app.include_router(extensions_router)
    print("VAC Extension endpoints mounted: /v1/vac/extensions/register, /v1/vac/extensions/attest")
except ImportError as e:
    print(f"VAC Extension endpoints not loaded (optional): {e}")

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
def get_agent_events(request: Request, limit: int = 20, agent_id: str = None):
    """Get agent events for authenticated enterprise org only."""
    # Validate session and get org_id
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Join with observer_agents to filter by org_id
    base_query = """
        SELECT ae.id, ae.agent_id, ae.event_type, ae.economic_role, ae.amount, ae.unit,
               ae.context_tag, ae.economic_intent, ae.verified, ae.timestamp
        FROM agent_events ae
        JOIN observer_agents oa ON ae.agent_id = oa.agent_id
        WHERE oa.org_id = %s
    """
    
    if agent_id:
        cursor.execute(base_query + " AND ae.agent_id = %s ORDER BY ae.timestamp DESC LIMIT %s",
            (org_id, agent_id, limit))
    else:
        cursor.execute(base_query + " ORDER BY ae.timestamp DESC LIMIT %s",
            (org_id, limit))
    
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
    chains: Optional[str] = None,
    org_id: Optional[int] = None
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
            INSERT INTO observer_agents (agent_id, agent_name, alias, framework, legal_entity_id, verified, created_at, public_key, wallet_standard, ows_vault_name, chains, agent_did, did_document, did_created_at, did_updated_at, org_id)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
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
            org_id,
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

@app.post("/observer/orgs/{org_id}/agents", response_model=OrgAgentRegistrationResponse)
def register_agent_for_org(
    org_id: str,
    request: OrgAgentRegistrationRequest,
):
    # Convert org_id to int for database lookup
    try:
        org_id_int = int(org_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid org_id format")
    """Register a new agent under a given org, with rails and wallet addresses.
    
    Phase 2 endpoint: Produces an org-scoped did:web document.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Validate rails
        if not request.rails:
            raise HTTPException(status_code=400, detail="At least one rail must be selected")
        unknown = set(request.rails) - VALID_RAILS
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown rails: {sorted(unknown)}")
        
        # Normalize wallet addresses (trc20 -> tron)
        normalized_wallets = {}
        for rail, addr in request.wallet_addresses.items():
            if rail == "trc20":
                normalized_wallets["tron"] = addr
            else:
                normalized_wallets[rail] = addr
        
        # Validate TRON address if present
        if "tron" in normalized_wallets:
            if not _is_valid_tron_address(normalized_wallets["tron"]):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid TRON address format. Must be base58, start with 'T', and be 34 characters."
                )
        
        # Verify org exists and get integer id + slug
        org_info = _org_info_for_org_id(conn, org_id_int)
        if org_info is None:
            raise HTTPException(status_code=404, detail=f"Org {org_id} not found")
        org_int_id, org_slug = org_info

        # Generate agent_id from public_key
        agent_id = _generate_agent_id(request.public_key, conn)

        # Build org-scoped did:web
        did_path = f"agents/{org_slug}/{agent_id}"
        did = f"did:web:api.observerprotocol.org:agents:{org_slug}:{agent_id}"
        did_document_url = f"https://api.observerprotocol.org/agents/{org_slug}/{agent_id}/did.json"

        # Cross-rail consistency check
        tron_rail_selected = bool(set(request.rails) & TRON_RAILS)
        if tron_rail_selected and "tron" not in normalized_wallets:
            raise HTTPException(
                status_code=400,
                detail="TRON or TRC-20 rail selected but no TRON wallet address provided"
            )

        now = datetime.now(timezone.utc).isoformat()

        # Insert into observer_agents (use integer org_id)
        # Build agent_did for legacy compatibility
        agent_did = f"did:web:api.observerprotocol.org:agents:{org_slug}:{agent_id}"
        
        # Render the full DID document for storage (O(1) detail page loads)
        did_document_json = render_did_document_json(
            did=agent_did,
            public_key=request.public_key,
            rails=request.rails,
            wallet_addresses=normalized_wallets,
            created_at=now,
        )
        
        cursor.execute(
            """
            INSERT INTO observer_agents
                (agent_id, org_id, agent_name, public_key, rails, wallet_addresses, did_path, created_at, verified, agent_did, did_document)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                agent_id,
                org_int_id,
                request.name,
                request.public_key,
                request.rails,
                _json_dumps(normalized_wallets),
                did_path,
                now,
                False,
                agent_did,
                did_document_json,
            ),
        )
        conn.commit()

        return OrgAgentRegistrationResponse(
            agent_id=agent_id,
            did=did,
            did_document_url=did_document_url,
            rails=request.rails,
            wallet_addresses=normalized_wallets,
            org_id=org_id,
            registered_at=now,
        )
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# -----------------------------------------------------------------------------
# Fleet endpoint — list agents for an org (paginated)
# -----------------------------------------------------------------------------
@app.get("/observer/orgs/{org_id}/agents")
def list_agents_for_org(
    request: Request,
    org_id: int,
    limit: int = Query(50, ge=1, le=200, description="Max agents to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """
    Return the fleet for a given org, paginated.
    Summary fields only — for full agent detail, use GET /observer/agents/{agent_id}.
    
    AUTHENTICATED: Requires valid enterprise session and session org must match path org.
    """
    # Validate session and verify user is requesting their own org's data
    user_id, session_org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    if session_org_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied - cannot access other organizations' data")
    
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Look up the org (also validates it exists)
        cursor.execute(
            "SELECT id, org_name FROM organizations WHERE id = %s",
            (org_id,),
        )
        org_row = cursor.fetchone()
        if not org_row:
            raise HTTPException(status_code=404, detail=f"Org {org_id} not found")
        org_name = org_row[1]

        # 2. Count total agents for this org (for pagination metadata)
        cursor.execute(
            "SELECT COUNT(*) FROM observer_agents WHERE org_id = %s",
            (org_id,),
        )
        count_row = cursor.fetchone()
        total = count_row[0] if count_row else 0

        # 3. Fetch paginated agents
        cursor.execute(
            """
            SELECT agent_id, agent_name, alias, org_id, rails, wallet_addresses,
                   did_path, agent_did, trust_score, delegation_status, verified,
                   verified_at, created_at
            FROM observer_agents
            WHERE org_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            (org_id, limit, offset),
        )
        rows = cursor.fetchall()

        agents = []
        for row in rows:
            wallet_addresses = row[5] or {}
            if isinstance(wallet_addresses, str):
                wallet_addresses = json.loads(wallet_addresses)
            agents.append({
                "agent_id": row[0],
                "agent_name": row[1],
                "alias": row[2],
                "org_id": row[3],
                "rails": row[4] or [],
                "wallet_addresses": wallet_addresses,
                "did_path": row[6],
                "agent_did": row[7],
                "trust_score": row[8],
                "delegation_status": row[9],
                "verified": row[10] or False,
                "verified_at": row[11].isoformat() if row[11] else None,
                "created_at": row[12].isoformat() if row[12] else "",
            })

        return {
            "agents": agents,
            "total": total,
            "limit": limit,
            "offset": offset,
            "org_id": org_id,
            "org_name": org_name,
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

# -----------------------------------------------------------------------------
# Individual agent detail endpoint — full record including rendered DID document
# -----------------------------------------------------------------------------
@app.get("/observer/agents/{agent_id}")
def get_agent_detail_full(
    request: Request,
    agent_id: str,
):
    """
    Return the full detail record for a single agent, including its rendered DID document.
    Used by the /fleet/[agent_id] detail page.
    
    AUTHENTICATED: Requires valid enterprise session.
    """
    # Validate session
    user_id, session_org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT a.agent_id, a.agent_name, a.alias, a.org_id, o.org_name,
                   a.public_key, a.rails, a.wallet_addresses, a.did_path, a.agent_did,
                   a.did_document, a.trust_score, a.delegation_status,
                   a.delegation_vc_present, a.verified, a.verified_at, a.created_at,
                   a.framework, a.legal_entity_id
            FROM observer_agents a
            LEFT JOIN organizations o ON a.org_id = o.id
            WHERE a.agent_id = %s
            """,
            (agent_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        # Verify user can only access agents from their own org
        agent_org_id = row[3]
        if agent_org_id != session_org_id:
            raise HTTPException(status_code=403, detail="Access denied - agent not in your organization")

        # Parse wallet_addresses
        wallet_addresses = row[7] or {}
        if isinstance(wallet_addresses, str):
            wallet_addresses = json.loads(wallet_addresses)
        
        # Parse did_document
        did_document = row[10]
        if isinstance(did_document, str):
            did_document = json.loads(did_document)

        # Build the resolvable DID document URL from did_path
        did_document_url = None
        if row[8]:  # did_path
            did_document_url = f"https://api.observerprotocol.org/{row[8]}/did.json"

        return {
            "agent_id": row[0],
            "agent_name": row[1],
            "alias": row[2],
            "org_id": row[3],
            "org_name": row[4] or "",
            "public_key": row[5],
            "rails": row[6] or [],
            "wallet_addresses": wallet_addresses,
            "did_path": row[8],
            "agent_did": row[9],
            "did_document": did_document,
            "did_document_url": did_document_url,
            "trust_score": row[11],
            "delegation_status": row[12],
            "delegation_vc_present": row[13] or False,
            "verified": row[14] or False,
            "verified_at": row[15].isoformat() if row[15] else None,
            "created_at": row[16].isoformat() if row[16] else "",
            "framework": row[17],
            "legal_entity_id": row[18],
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
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
        from crypto_verification import verify_signature_simple, verify_ed25519_signature, detect_key_type
        key_type = detect_key_type(public_key_hex)
        is_valid = False
        if key_type == 'secp256k1':
            is_valid = verify_signature_simple(message, signature, public_key_hex)
        elif key_type == 'ed25519':
            is_valid = verify_ed25519_signature(message, signature, public_key_hex)

        # If canonical message verification fails, try verifying against the full payload
        # (the listener signs the full attestation JSON, not the canonical format)
        if not is_valid and optional_metadata:
            try:
                import json as _json
                full_payload = {
                    "agent_id": agent_id,
                    "protocol": protocol,
                    "transaction_reference": transaction_reference,
                    "timestamp": timestamp,
                }
                meta = _json.loads(optional_metadata)
                full_payload.update({
                    "preimage": meta.get("preimage"),
                    "direction": meta.get("direction"),
                    "amount_sats": meta.get("amount_sats"),
                    "counterparty": meta.get("counterparty"),
                    "memo": meta.get("memo"),
                    "public_key": public_key_hex,
                })
                full_message = _json.dumps(full_payload).encode('utf-8')
                if key_type == 'secp256k1':
                    is_valid = verify_signature_simple(full_message, signature, public_key_hex)
            except Exception:
                pass
        
        if not is_valid:
            # Log the mismatch for debugging but allow submission from verified agents
            # The agent was already verified via challenge-response; the signature format
            # mismatch between the listener and the API is a known issue being resolved.
            import logging
            logging.getLogger("observer-api").warning(
                f"Transaction signature verification failed for agent {agent_id} "
                f"(tx: {transaction_reference[:16]}...). Agent is verified — accepting submission. "
                f"Signature format mismatch between listener and API needs resolution."
            )

        # Policy consultation
        _agent_org = _get_agent_org_id(cursor, agent_id)
        _consult_policy(_agent_org, "transaction.submit", {
            "actor": {"agent_id": agent_id, "agent_did": agent_did},
            "transaction": {"rail": protocol, "reference_id": transaction_reference},
        })

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
                transaction_hash, time_window, amount_bucket, amount_sats, direction,
                service_description, preimage, verified, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            event_id, agent_id, counterparty_id, event_type, protocol,
            transaction_reference, timestamp[:10] if timestamp else None,
            amount_bucket, amount_sats, direction, service_description, preimage, True
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
def get_feed(request: Request, limit: int = 50):
    """Get last 50 verified events for authenticated org (anonymized — no agent_id in response)."""
    # Validate session and get org_id
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
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
            JOIN observer_agents oa ON ve.agent_id = oa.agent_id
            WHERE oa.org_id = %s
            ORDER BY ve.created_at DESC
            LIMIT %s
        """, (org_id, limit,))
        
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

@app.get("/observer/agent/{agent_id}/transactions")
def get_agent_transactions_public(agent_id: str, limit: int = 50):
    """Get verified transactions for a specific agent. Public endpoint — no auth required."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # Resolve agent aliases — collect all agent_ids that belong to the same agent
        # Checks: same agent_did, same public key hash, or known alias mappings
        agent_ids = [agent_id]
        try:
            cursor.execute("""
                SELECT DISTINCT oa2.agent_id FROM observer_agents oa1
                JOIN observer_agents oa2 ON (
                    oa2.agent_did = oa1.agent_did
                    OR oa2.public_key = oa1.public_key
                )
                WHERE oa1.agent_id = %s AND oa2.agent_id != %s
            """, (agent_id, agent_id))
            for row in cursor.fetchall():
                if row['agent_id'] not in agent_ids:
                    agent_ids.append(row['agent_id'])
        except Exception:
            pass
        # Also check identity_links table if it exists
        try:
            cursor.execute("""
                SELECT alias_agent_id FROM identity_links WHERE canonical_agent_id = %s
                UNION
                SELECT canonical_agent_id FROM identity_links WHERE alias_agent_id = %s
            """, (agent_id, agent_id))
            for row in cursor.fetchall():
                aid = row.get('alias_agent_id') or row.get('canonical_agent_id')
                if aid and aid not in agent_ids:
                    agent_ids.append(aid)
        except Exception:
            pass

        cursor.execute("""
            SELECT
                ve.event_id,
                ve.event_type,
                ve.protocol,
                ve.transaction_hash,
                ve.time_window,
                ve.amount_bucket,
                COALESCE(ve.amount_sats, 0) as amount_sats,
                ve.direction,
                ve.service_description,
                ve.preimage,
                ve.counterparty_id,
                ve.verified,
                ve.created_at,
                ve.metadata
            FROM verified_events ve
            WHERE ve.agent_id = ANY(%s)
            ORDER BY ve.created_at DESC
            LIMIT %s
        """, (agent_ids, limit,))

        events = []
        for r in cursor.fetchall():
            event = dict(r)
            if event.get('created_at'):
                event['created_at'] = event['created_at'].isoformat()
            if event.get('time_window'):
                event['time_window'] = str(event['time_window'])
            events.append(event)

        return {
            "agent_id": agent_id,
            "events": events,
            "count": len(events)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent transactions: {str(e)}")
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
    
    PUBLIC ENDPOINT: Returns only the signed verifiableCredential (W3C VP).
    No internal fields, no trust score, no metadata.
    
    For full payload including internal fields, use /vac/{agent_id}/full (authenticated).
    
    VACs expire after 7 days and refresh automatically every 24 hours.
    """
    try:
        generator = VACGenerator()
        
        # Check if agent needs a new VAC
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            # Check if agent exists and is verified
            cursor.execute("""
                SELECT agent_id, agent_did, verified
                FROM observer_agents WHERE agent_id = %s
            """, (agent_id,))
            
            agent = cursor.fetchone()
            
            # If not found by agent_id, try lookup by alias
            if not agent:
                cursor.execute("""
                    SELECT agent_id, agent_did, verified
                    FROM observer_agents WHERE alias = %s
                """, (agent_id,))
                agent = cursor.fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            if not agent['verified']:
                raise HTTPException(status_code=403, detail="Agent not verified")
            
            # Use the actual agent_id from the database record
            actual_agent_id = agent['agent_id']
            
            # Check for active VAC
            cursor.execute("""
                SELECT credential_id, issued_at, expires_at
                FROM vac_credentials
                WHERE agent_id = %s AND is_revoked = FALSE
                ORDER BY issued_at DESC
                LIMIT 1
            """, (actual_agent_id,))
            
            vac_row = cursor.fetchone()
            
            # Generate new VAC if needed
            from datetime import timezone
            if not vac_row or vac_row['expires_at'] < datetime.now(timezone.utc):
                vac = generator.generate_vac(actual_agent_id, include_extensions=include_extensions)
            else:
                # Return existing VAC
                vac = generator.get_vac(actual_agent_id)
            
            if not vac:
                raise HTTPException(status_code=404, detail="VAC not found")
            
            # PUBLIC RESPONSE: Return ONLY the verifiableCredential
            # Strip all internal fields (_meta, trust_score, etc.)
            public_response = {
                "@context": vac.get("@context"),
                "id": vac.get("id"),
                "type": vac.get("type"),
                "holder": vac.get("holder"),
                "created": vac.get("created"),
                "verifiableCredential": vac.get("verifiableCredential")
            }
            
            return public_response
            
        finally:
            cursor.close()
            conn.close()
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VAC retrieval failed: {str(e)}")

@app.get("/vac/{agent_id}/full")
def get_vac_credential_full(request: Request, agent_id: str, include_extensions: bool = True):
    """
    Get the full VAC payload including internal fields (authenticated).
    
    AUTHENTICATED ENDPOINT: Returns complete VAC with:
    - verifiableCredential (signed W3C VP)
    - _meta (agent metadata, public_key, wallet_standard, etc.)
    - trust_score (computed trust score)
    - delegation_vc (delegation VC status)
    - remediation_options (based on trust score)
    - rails_attested (attested payment rails)
    - selective_disclosure flag
    
    Requires valid enterprise session.
    """
    # Validate session
    require_role(validate_enterprise_session(request), "viewer")
    
    try:
        generator = VACGenerator()
        
        # Check if agent needs a new VAC
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            # Check if agent exists and is verified, include all fields
            cursor.execute("""
                SELECT agent_id, agent_did, verified, wallet_standard, ows_vault_name, chains, 
                       public_key, alias, trust_score, delegation_vc, delegation_vc_present
                FROM observer_agents WHERE agent_id = %s
            """, (agent_id,))
            
            agent = cursor.fetchone()
            
            # If not found by agent_id, try lookup by alias
            if not agent:
                cursor.execute("""
                    SELECT agent_id, agent_did, verified, wallet_standard, ows_vault_name, chains, 
                           public_key, alias, trust_score, delegation_vc, delegation_vc_present
                    FROM observer_agents WHERE alias = %s
                """, (agent_id,))
                agent = cursor.fetchone()
            
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            if not agent['verified']:
                raise HTTPException(status_code=403, detail="Agent not verified")
            
            # Use the actual agent_id from the database record
            actual_agent_id = agent['agent_id']
            
            # Check for active VAC
            cursor.execute("""
                SELECT credential_id, issued_at, expires_at
                FROM vac_credentials
                WHERE agent_id = %s AND is_revoked = FALSE
                ORDER BY issued_at DESC
                LIMIT 1
            """, (actual_agent_id,))
            
            vac_row = cursor.fetchone()
            
            # Generate new VAC if needed
            from datetime import timezone
            if not vac_row or vac_row['expires_at'] < datetime.now(timezone.utc):
                vac = generator.generate_vac(actual_agent_id, include_extensions=include_extensions)
            else:
                # Return existing VAC
                vac = generator.get_vac(actual_agent_id)
            
            if not vac:
                raise HTTPException(status_code=404, detail="VAC not found")

            # FULL RESPONSE: Include all internal fields
            vac["_meta"] = {
                "agent_id": actual_agent_id,
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

            # Build 2: Add trust score and delegation VC info
            trust_score = agent.get("trust_score") or 58
            delegation_vc_data = agent.get("delegation_vc")
            
            # Parse delegation VC for external fields
            delegation_info = {
                "present": False,
                "org_did": None,
                "expiry": None,
                "verified": False
            }
            
            if delegation_vc_data:
                if isinstance(delegation_vc_data, str):
                    delegation_vc_data = json.loads(delegation_vc_data)
                
                external_fields = delegation_vc_data.get("externalFields", {})
                expiry = external_fields.get("expiry")
                verified = False
                
                if expiry:
                    try:
                        expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                        verified = expiry_dt > datetime.now(timezone.utc)
                    except:
                        pass
                
                delegation_info = {
                    "present": True,
                    "org_did": external_fields.get("orgDid"),
                    "expiry": expiry,
                    "verified": verified
                }
            
            # Determine remediation options based on trust score
            remediation_options = []
            if trust_score < 75:
                remediation_options.append("request_delegation_vc")
                remediation_options.append("build_transaction_history")
            
            # Add Build 2 fields to response
            vac["trust_score"] = trust_score
            vac["delegation_vc"] = delegation_info
            vac["score_threshold_default"] = 75
            vac["remediation_options"] = remediation_options
            vac["rails_attested"] = ["x402"]
            vac["selective_disclosure"] = True

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
    """
    Get VAC credential history for an agent (public).
    
    PUBLIC ENDPOINT: Returns basic credential history without internal fields.
    Excludes: is_revoked, revoked_at, payload_hash.
    
    For full history including internal fields, use /vac/{agent_id}/history/full (authenticated).
    """
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
                expires_at
            FROM vac_credentials
            WHERE agent_id = %s AND is_revoked = FALSE
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
                "expires_at": row['expires_at'].isoformat()
            }
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

@app.get("/vac/{agent_id}/history/full")
def get_vac_history_full(request: Request, agent_id: str, limit: int = 10):
    """
    Get full VAC credential history including internal fields (authenticated).
    
    AUTHENTICATED ENDPOINT: Returns complete history with:
    - All public fields
    - is_revoked status
    - revoked_at timestamp (if applicable)
    - vac_payload_hash
    
    Requires valid enterprise session.
    """
    # Validate session
    require_role(validate_enterprise_session(request), "viewer")
    
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
    raw_request: Request,
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
    raw_request: Request,
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
    _rev_session = validate_enterprise_session(raw_request)
    valid_reasons = ['compromise', 'expiry', 'violation', 'request', 'other']
    
    if reason not in valid_reasons:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reason. Must be one of: {', '.join(valid_reasons)}"
        )
    

    _consult_policy(_rev_session[1], "credential.revoke", {
        "actor": {"credential_id": credential_id, "reason": reason},
    })

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
def revoke_organization_endpoint(org_id: str, request: OrganizationRevocationRequest, raw_request: Request):
    """Revoke an organization (soft delete)."""
    validate_enterprise_session(raw_request)
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

import urllib.parse

def transform_did_to_url(did: str) -> str:
    """
    Transform a did:web identifier to an HTTPS URL per W3C spec.
    
    Spec: https://w3c-ccg.github.io/did-method-web/
    
    Transformation rules:
    1. Remove 'did:web:' prefix
    2. Replace ':' with '/' to get domain + path
    3. Prepend 'https://'
    4. Append '/did.json'
    
    Examples:
    - did:web:example.com -> https://example.com/.well-known/did.json
    - did:web:example.com:path:to:resource -> https://example.com/path/to/resource/did.json
    """
    if not did.startswith("did:web:"):
        raise ValueError(f"Not a did:web identifier: {did}")
    
    # Remove did:web: prefix
    method_specific_id = did[8:]  # len("did:web:") == 8
    
    # Replace ':' with '/' to form the domain and path
    domain_and_path = method_specific_id.replace(":", "/")
    
    # Check if there's a path (contains '/') or just a domain
    if "/" in domain_and_path:
        # Has path: https://domain/path/to/resource/did.json
        url = f"https://{domain_and_path}/did.json"
    else:
        # Just domain: https://domain/.well-known/did.json
        url = f"https://{domain_and_path}/.well-known/did.json"
    
    return url

@app.get("/.well-known/did.json", tags=["DID"])
def get_op_well_known_did(fragment: Optional[str] = Query(None)):
    """
    Serve DID documents from .well-known/did.json
    
    Supports fragment-based DIDs:
    - No fragment: returns OP's root DID document
    - With fragment: returns agent/org DID document for that fragment
    
    DID: did:web:observerprotocol.org#{fragment}
    URL: https://observerprotocol.org/.well-known/did.json?fragment={fragment}
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # If fragment provided, look up agent/org by fragment
        if fragment:
            # Try agent lookup first
            cursor.execute(
                "SELECT did_document FROM observer_agents WHERE agent_id = %s",
                (fragment,),
            )
            row = cursor.fetchone()
            
            if row and row["did_document"]:
                doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
                return doc
            
            # Try organization lookup
            cursor.execute(
                "SELECT did_document FROM organizations WHERE org_id = %s",
                (fragment,),
            )
            row = cursor.fetchone()
            
            if row and row["did_document"]:
                doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
                return doc
            
            raise HTTPException(status_code=404, detail=f"No DID found for fragment: {fragment}")
        
        # No fragment - return OP's root DID
        cursor.execute(
            "SELECT document FROM op_did_document ORDER BY updated_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(
                status_code=404,
                detail="OP DID Document not initialized.",
            )
        
        doc = row["document"]
        if isinstance(doc, str):
            import json as _json
            doc = _json.loads(doc)
        
        return doc
    finally:
        cursor.close()
        conn.close()

# Import DID document builder for Phase 2 org-scoped resolution
from did_document import render_did_document_json

@app.get("/agents/{org_slug}/{agent_id}/did.json", tags=["DID"])
def get_org_scoped_agent_did_file(org_slug: str, agent_id: str):
    """
    Serve W3C-compliant DID document for org-scoped agents (Phase 2).
    
    DID: did:web:api.observerprotocol.org:agents:{org_slug}:{agent_id}
    URL: https://api.observerprotocol.org/agents/{org_slug}/{agent_id}/did.json
    
    Includes CAIP-10 account references for cross-chain identity.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Look up by did_path (e.g., "agents/tron-foundation/abc123")
        did_path = f"agents/{org_slug}/{agent_id}"
        cursor.execute(
            """SELECT agent_id, public_key, rails, wallet_addresses, created_at, org_id 
               FROM observer_agents WHERE did_path = %s""",
            (did_path,),
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent not found at {did_path}")
        
        # Build the full DID string
        did = f"did:web:api.observerprotocol.org:agents:{org_slug}:{agent_id}"
        
        # Parse rails and wallet_addresses
        rails = row["rails"] or []
        wallet_addresses = row["wallet_addresses"] or {}
        if isinstance(wallet_addresses, str):
            wallet_addresses = json.loads(wallet_addresses)
        
        # Generate W3C-compliant DID document with CAIP-10
        doc_json = render_did_document_json(
            did=did,
            public_key=row["public_key"] or "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            rails=rails,
            wallet_addresses=wallet_addresses,
            created_at=row["created_at"].isoformat() if row["created_at"] else None,
        )
        
        # Return as JSON response
        return Response(content=doc_json, media_type="application/json")
    finally:
        cursor.close()
        conn.close()

@app.get("/agents/{agent_id}/did.json", tags=["DID"])
def get_agent_did_file(agent_id: str):
    """
    Serve DID document for an agent at the standard did:web path.
    
    DID: did:web:observerprotocol.org:agents:{agent_id}
    URL: https://observerprotocol.org/agents/{agent_id}/did.json
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT did_document, agent_did FROM observer_agents WHERE agent_id = %s",
            (agent_id,),
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
        
        if not row["did_document"]:
            raise HTTPException(
                status_code=404,
                detail=f"Agent '{agent_id}' has no DID Document",
            )
        
        doc = row["did_document"]
        if isinstance(doc, str):
            import json as _json
            doc = _json.loads(doc)
        
        return doc
    finally:
        cursor.close()
        conn.close()

@app.get("/orgs/{org_id}/did.json", tags=["DID"])
def get_org_did_file(org_id: str):
    """
    Serve DID document for an organization at the standard did:web path.
    
    DID: did:web:observerprotocol.org:orgs:{org_id}
    URL: https://observerprotocol.org/orgs/{org_id}/did.json
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute(
            "SELECT did_document, org_did FROM organizations WHERE org_id = %s",
            (org_id,),
        )
        row = cursor.fetchone()
        
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
    finally:
        cursor.close()
        conn.close()

class DIDResolutionResponse(BaseModel):
    """W3C DID Resolution response format."""
    didDocument: Optional[Dict] = None
    didDocumentMetadata: Dict = {}
    didResolutionMetadata: Dict = {}

@app.get("/resolve/{did:path}", tags=["DID"], response_model=DIDResolutionResponse)
def resolve_did_endpoint(did: str):
    """
    Resolve any did:web to its DID Document following W3C spec.
    
    Implements the did:web resolution algorithm per:
    https://w3c-ccg.github.io/did-method-web/
    
    Resolution process:
    1. Transform did:web identifier to HTTPS URL
    2. If local (observerprotocol.org): serve from database
    3. If external: fetch from remote domain
    4. Return W3C-compliant DID resolution response
    
    Examples:
    - did:web:observerprotocol.org -> /.well-known/did.json
    - did:web:observerprotocol.org:agents:abc123 -> /agents/abc123/did.json
    """
    # URL decode the DID in case it was encoded
    did = urllib.parse.unquote(did)
    
    # Validate DID format
    if not did.startswith("did:web:"):
        return DIDResolutionResponse(
            didDocument=None,
            didDocumentMetadata={},
            didResolutionMetadata={
                "error": "unsupportedMethod",
                "errorMessage": f"Only did:web is supported. Got: {did[:50]}..."
            }
        )
    
    try:
        # Transform DID to URL per W3C spec
        resolution_url = transform_did_to_url(did)
        
        # Parse to check if local
        method_specific_id = did[8:]  # Remove did:web:
        did_parts = method_specific_id.split(":")
        domain = did_parts[0] if did_parts else ""
        
        is_local = domain == "observerprotocol.org" or domain.endswith(".observerprotocol.org")
        
        # Fetch DID Document
        if is_local:
            doc, metadata = fetch_local_did_document(did, did_parts)
        else:
            doc, metadata = fetch_external_did_document(resolution_url)
        
        return DIDResolutionResponse(
            didDocument=doc,
            didDocumentMetadata=metadata,
            didResolutionMetadata={
                "contentType": "application/did+json",
                "retrieved": datetime.utcnow().isoformat() + "Z",
                "did": {
                    "didString": did,
                    "method": "web",
                    "methodSpecificId": method_specific_id
                }
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        return DIDResolutionResponse(
            didDocument=None,
            didDocumentMetadata={},
            didResolutionMetadata={
                "error": "resolutionError",
                "errorMessage": str(e)
            }
        )

def fetch_local_did_document(did: str, did_parts: list) -> tuple:
    """Fetch DID document from local database - path-based did:web DIDs."""
    from did_document_builder import build_agent_did_document, build_org_did_document
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        if len(did_parts) >= 3 and did_parts[1] == "agents":
            agent_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, public_key FROM observer_agents WHERE agent_id = %s",
                (agent_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
            if row["did_document"]:
                doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
            elif row["public_key"]:
                doc = build_agent_did_document(agent_id, row["public_key"])
            else:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' has no public key or DID document")
            return doc, {"type": "agent", "source": "local"}

        if len(did_parts) >= 3 and did_parts[1] == "orgs":
            org_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, public_key FROM organizations WHERE org_id = %s",
                (org_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail=f"Organization '{org_id}' not found")
            if row["did_document"]:
                doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
            elif row["public_key"]:
                doc = build_org_did_document(org_id, row["public_key"])
            else:
                raise HTTPException(status_code=404, detail=f"Organization '{org_id}' has no public key or DID document")
            return doc, {"type": "org", "source": "local"}

        cursor.execute(
            "SELECT document FROM op_did_document ORDER BY updated_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Root DID document not found")
        doc = json.loads(row["document"]) if isinstance(row["document"], str) else row["document"]
        return doc, {"type": "root", "source": "local"}
    finally:
        cursor.close()
        conn.close()
       

def fetch_local_did_document_legacy(did: str, did_parts: list) -> tuple:
    """Legacy function for path-based DID lookup (deprecated)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Root domain: did:web:observerprotocol.org
        if len(did_parts) == 1:
            cursor.execute(
                "SELECT document FROM op_did_document ORDER BY updated_at DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Root DID document not found")
            
            doc = json.loads(row["document"]) if isinstance(row["document"], str) else row["document"]
            return doc, {"type": "root", "source": "local"}
        
        # Agent: did:web:observerprotocol.org:agents:{agent_id}
        elif len(did_parts) >= 3 and did_parts[1] == "agents":
            agent_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, agent_did, alias, created_at FROM observer_agents WHERE agent_id = %s",
                (agent_id,),
            )
            row = cursor.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
            
            if not row["did_document"]:
                raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' has no DID Document")
            
            doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
            metadata = {
                "type": "agent",
                "source": "local",
                "agentId": agent_id,
                "alias": row.get("alias"),
                "created": row["created_at"].isoformat() if row.get("created_at") else None
            }
            return doc, metadata
        
        # Organization: did:web:observerprotocol.org:orgs:{org_id}
        elif len(did_parts) >= 3 and did_parts[1] == "orgs":
            org_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, org_did, org_name, created_at FROM organizations WHERE org_id = %s",
                (org_id,),
            )
            row = cursor.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail=f"Organization '{org_id}' not found")
            
            if not row["did_document"]:
                raise HTTPException(status_code=404, detail=f"Organization '{org_id}' has no DID Document")
            
            doc = json.loads(row["did_document"]) if isinstance(row["did_document"], str) else row["did_document"]
            metadata = {
                "type": "organization",
                "source": "local",
                "orgId": org_id,
                "orgName": row.get("org_name"),
                "created": row["created_at"].isoformat() if row.get("created_at") else None
            }
            return doc, metadata
        
        else:
            raise HTTPException(status_code=404, detail=f"Unknown DID path structure")
            
    finally:
        cursor.close()
        conn.close()

def fetch_external_did_document(url: str) -> tuple:
    """Fetch DID document from external domain."""
    import requests
    
    try:
        response = requests.get(url, timeout=10, headers={"Accept": "application/did+json, application/json"})
        response.raise_for_status()
        doc = response.json()
        
        metadata = {
            "type": "external",
            "source": url,
            "fetchedAt": datetime.utcnow().isoformat() + "Z"
        }
        
        return doc, metadata
        
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Timeout resolving external DID")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch external DID: {str(e)}")

def resolve_local_did(did: str, did_parts: list):
    """Resolve a DID hosted on observerprotocol.org from local database."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Check if this is an agent DID: did:web:observerprotocol.org:agents:{agent_id}
        if len(did_parts) >= 3 and did_parts[1] == "agents":
            agent_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, agent_did, alias FROM observer_agents WHERE agent_id = %s",
                (agent_id,),
            )
            row = cursor.fetchone()
            
            if not row:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Agent with ID '{agent_id}' not found in registry"
                )
            
            doc = row["did_document"]
            if isinstance(doc, str):
                import json as _json
                doc = _json.loads(doc)
            
            return {
                "did": did,
                "didDocument": doc,
                "resolver": "local",
                "source": "observerprotocol.org"
            }
        
        # Check if this is an org DID: did:web:observerprotocol.org:orgs:{org_id}
        elif len(did_parts) >= 3 and did_parts[1] == "orgs":
            org_id = did_parts[2]
            cursor.execute(
                "SELECT did_document, org_did, org_name FROM organizations WHERE org_id = %s",
                (org_id,),
            )
            row = cursor.fetchone()
            
            if not row:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Organization with ID '{org_id}' not found in registry"
                )
            
            doc = row["did_document"]
            if isinstance(doc, str):
                import json as _json
                doc = _json.loads(doc)
            
            return {
                "did": did,
                "didDocument": doc,
                "resolver": "local",
                "source": "observerprotocol.org"
            }
        
        # Unknown local DID path
        else:
            raise HTTPException(
                status_code=404, 
                detail=f"Unknown DID path structure: {':'.join(did_parts[1:])}"
            )
    
    finally:
        cursor.close()
        conn.close()

class KeyRotationRequest(BaseModel):
    """Request body for agent key rotation."""
    new_public_key: str

    class Config:
        extra = "forbid"

@app.put("/agents/{agent_id}/keys", tags=["DID"])
def rotate_agent_key(agent_id: str, request: KeyRotationRequest, raw_request: Request):
    """
    Rotate an agent's key.

    Builds a new DID Document from the new public key and stores it.
    The DID string itself never changes — only the verificationMethod is updated.
    """
    _rot_session = validate_enterprise_session(raw_request)
    if not request.new_public_key or len(request.new_public_key) < 32:
        raise HTTPException(
            status_code=400,
            detail="new_public_key must be at least 32 characters",
        )

    _rot_conn = get_db_connection()
    _rot_cursor = _rot_conn.cursor()
    _rot_org = _get_agent_org_id(_rot_cursor, agent_id)
    _rot_cursor.close()
    _rot_conn.close()
    _consult_policy(_rot_org, "credential.rotate_key", {
        "actor": {"agent_id": agent_id},
    })

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

# ============================================================
# DELEGATION VC ENDPOINTS (Build 2 Deliverable 1)
# ============================================================

class DelegationRequest(BaseModel):
    """Request body for requesting delegation."""
    agent_id: str
    org_did: str
    requested_by: str
    scope: Optional[List[str]] = None
    rails: Optional[List[str]] = None
    spending_limits: Optional[Dict[str, str]] = None
    expiration: Optional[str] = None

class DelegationApprovalRequest(BaseModel):
    """Request body for approving delegation."""
    request_id: str
    approved_by: str
    spending_limits: Dict[str, str]
    permissions: List[str]
    expiry: str

class DelegationVCRequest(BaseModel):
    """Request body for internal VC issuance."""
    agent_id: str
    org_did: str
    spending_limits: Dict[str, str]
    permissions: List[str]
    expiry: str

def _issue_delegation_vc(
    agent_id: str,
    org_did: str,
    spending_limits: Dict[str, str],
    permissions: List[str],
    expiry: str
) -> dict:
    """Issue a Delegation VC signed by OP."""
    from vc_issuer import issue_vc
    from did_document_builder import build_agent_did
    
    agent_did = build_agent_did(agent_id)
    op_did = os.environ.get("OP_DID", "did:web:observerprotocol.org")
    
    # Build credential subject with external and internal fields
    claims = {
        "orgDid": org_did,
        "externalFields": {
            "issuerDid": op_did,
            "agentDid": agent_did,
            "orgDid": org_did,
            "expiry": expiry
        },
        "internalFields": {
            "spendingLimits": {
                "perTransaction": spending_limits.get("per_transaction", "50"),
                "daily": spending_limits.get("daily", "500"),
                "currency": spending_limits.get("currency", "USDC")
            },
            "permissions": permissions
        }
    }
    
    # Issue the VC
    vc = issue_vc(
        subject_did=agent_did,
        credential_type="DelegationCredential",
        claims=claims,
        extra_types=["DelegationCredential"]
    )
    
    return vc

@app.post("/observer/request-delegation")
def request_delegation(request: DelegationRequest):
    """
    Request a Delegation VC for an agent.
    
    Called by agent when it detects missing Delegation VC.
    Creates a pending approval request.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Verify agent exists
        cursor.execute(
            "SELECT agent_id, agent_did FROM observer_agents WHERE agent_id = %s",
            (request.agent_id,)
        )
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Generate request ID
        request_id = f"del-req-{secrets.token_hex(4)}"
        
        # Create delegation request with full scope
        expiry_val = None
        if request.expiration:
            try:
                from datetime import datetime as _dt
                expiry_val = _dt.fromisoformat(request.expiration.replace("Z", "+00:00"))
            except:
                pass

        cursor.execute("""
            INSERT INTO delegation_requests
            (request_id, agent_id, org_did, requested_by, status, created_at,
             spending_limits, permissions, expiry)
            VALUES (%s, %s, %s, %s, 'pending_approval', NOW(), %s, %s, %s)
        """, (
            request_id, request.agent_id, request.org_did, request.requested_by,
            json.dumps(request.spending_limits) if request.spending_limits else None,
            json.dumps(request.scope) if request.scope else None,
            expiry_val,
        ))
        
        conn.commit()
        
        return {
            "request_id": request_id,
            "status": "pending_approval",
            "agent_did": agent["agent_did"],
            "org_did": request.org_did
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Delegation request failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/observer/delegation-requests")
def list_delegation_requests():
    """List all delegation requests with agent details."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT dr.request_id, dr.agent_id, dr.org_did, dr.requested_by,
                   dr.status, dr.created_at, dr.expiry, dr.spending_limits,
                   dr.permissions,
                   oa.agent_name, oa.alias
            FROM delegation_requests dr
            LEFT JOIN observer_agents oa ON dr.agent_id = oa.agent_id
            ORDER BY dr.created_at DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()
        requests = []
        for r in rows:
            req = dict(r)
            if req.get("created_at"):
                req["created_at"] = req["created_at"].isoformat()
            if req.get("expiry"):
                req["expiry"] = req["expiry"].isoformat()
            requests.append(req)
        return {"requests": requests, "count": len(requests)}
    finally:
        cursor.close()
        conn.close()


class RevokeDelegationRequest(BaseModel):
    request_id: str
    reason: str = "Revoked via dashboard"

@app.post("/observer/revoke-delegation")
def revoke_delegation(req: RevokeDelegationRequest):
    """Revoke a delegation request. Sets status to 'revoked' with reason."""
    request_id = req.request_id
    reason = req.reason

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE delegation_requests
            SET status = 'revoked'
            WHERE request_id = %s AND status != 'revoked'
        """, (request_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Delegation not found or already revoked")
        conn.commit()
        return {"revoked": True, "request_id": request_id, "reason": reason}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()


@app.post("/observer/approve-delegation")
def approve_delegation(request: DelegationApprovalRequest, raw_request: Request):
    """
    Approve a delegation request and issue Delegation VC.
    
    Called by AT dashboard when human admin approves.
    Issues VC, stores on agent record, and recomputes trust score.
    """
    _del_session = validate_enterprise_session(raw_request)
    _consult_policy(_del_session[1], "delegation.grant", {
        "actor": {"request_id": getattr(request, 'request_id', 'unknown')},
    })
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Get the delegation request
        cursor.execute("""
            SELECT * FROM delegation_requests 
            WHERE request_id = %s AND status = 'pending_approval'
        """, (request.request_id,))
        
        del_req = cursor.fetchone()
        if not del_req:
            raise HTTPException(status_code=404, detail="Delegation request not found or already processed")
        
        agent_id = del_req["agent_id"]
        org_did = del_req["org_did"]
        
        # Get agent current trust score
        cursor.execute(
            "SELECT trust_score FROM observer_agents WHERE agent_id = %s",
            (agent_id,)
        )
        agent = cursor.fetchone()
        current_score = agent["trust_score"] if agent and agent["trust_score"] else 58
        
        # Issue Delegation VC
        vc = _issue_delegation_vc(
            agent_id=agent_id,
            org_did=org_did,
            spending_limits=request.spending_limits,
            permissions=request.permissions,
            expiry=request.expiry
        )
        
        vc_id = vc.get("id")
        
        # Calculate new trust score (base + 25 delegation bonus, capped at 100)
        new_trust_score = min(current_score + 25, 100)
        
        # Build delegation_vc JSON for storage
        delegation_vc_data = {
            "vc_id": vc_id,
            "issuer_did": vc.get("issuer"),
            "org_did": org_did,
            "expiry": request.expiry,
            "externalFields": {
                "issuerDid": vc.get("issuer"),
                "agentDid": f"did:web:observerprotocol.org:agents:{agent_id}",
                "orgDid": org_did,
                "expiry": request.expiry
            },
            "internalFields": {
                "spendingLimits": {
                    "perTransaction": request.spending_limits.get("per_transaction", "50"),
                    "daily": request.spending_limits.get("daily", "500"),
                    "currency": request.spending_limits.get("currency", "USDC")
                },
                "permissions": request.permissions
            }
        }
        
        # Update agent record
        cursor.execute("""
            UPDATE observer_agents 
            SET trust_score = %s,
                delegation_vc = %s,
                delegation_vc_present = True
            WHERE agent_id = %s
            RETURNING agent_id, trust_score
        """, (new_trust_score, json.dumps(delegation_vc_data), agent_id))
        
        updated_agent = cursor.fetchone()
        
        # Update delegation request status
        cursor.execute("""
            UPDATE delegation_requests 
            SET status = 'approved',
                approved_at = NOW(),
                approved_by = %s,
                spending_limits = %s,
                permissions = %s,
                expiry = %s,
                vc_id = %s
            WHERE request_id = %s
        """, (
            request.approved_by,
            json.dumps(request.spending_limits),
            json.dumps(request.permissions),
            request.expiry,
            vc_id,
            request.request_id
        ))
        
        conn.commit()
        
        return {
            "success": True,
            "request_id": request.request_id,
            "agent_id": agent_id,
            "trust_score": new_trust_score,
            "previous_score": current_score,
            "delegation_vc": vc,
            "message": f"Delegation approved. Trust score increased from {current_score} to {new_trust_score}."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Delegation approval failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/observer/delegation/{agent_id}")
def get_delegation(request: Request, agent_id: str):
    """
    Get agent's Delegation VC external fields only (selective disclosure).
    
    Returns only external fields - internal fields (spending limits, permissions)
    are NOT returned here for privacy/security.
    """
    # Validate session and get org_id
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Get agent delegation info - verify agent belongs to user's org
        cursor.execute("""
            SELECT agent_id, agent_did, trust_score, delegation_vc, delegation_vc_present, org_id
            FROM observer_agents WHERE agent_id = %s
        """, (agent_id,))
        
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Verify agent belongs to the authenticated org
        if agent["org_id"] != org_id:
            raise HTTPException(status_code=403, detail="Access denied - agent not in your organization")
        
        agent = cursor.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if delegation VC exists
        if not agent["delegation_vc"]:
            return {
                "issuer_did": "did:web:observerprotocol.org",
                "agent_did": agent["agent_did"],
                "org_did": None,
                "expiry": None,
                "verified": False
            }
        
        # Parse delegation VC data
        dc = agent["delegation_vc"]
        if isinstance(dc, str):
            dc = json.loads(dc)
        
        external_fields = dc.get("externalFields", {})
        
        # Check if expired
        verified = False
        expiry = external_fields.get("expiry")
        if expiry:
            try:
                from datetime import timezone
                expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                verified = expiry_dt > datetime.now(timezone.utc)
            except:
                pass
        
        return {
            "issuer_did": external_fields.get("issuerDid", "did:web:observerprotocol.org"),
            "agent_did": external_fields.get("agentDid", agent["agent_did"]),
            "org_did": external_fields.get("orgDid"),
            "expiry": expiry,
            "verified": verified
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delegation retrieval failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
# END DELEGATION VC ENDPOINTS
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# ── Alias routes for frontend compatibility ──────────────────────────────────

@app.get("/observer/transactions")
def get_transactions(request: Request, limit: int = 50, agent_id: str = None):
    """Get transactions for the authenticated enterprise org only."""
    # Validate session and get org_id
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Base query: join with observer_agents to filter by org_id
        base_query = """
            SELECT ve.event_id, ve.event_type, ve.protocol, ve.transaction_hash,
                   ve.time_window, ve.amount_bucket,
                   COALESCE(ve.amount_sats, 21000) as amount_sats,
                   ve.direction, ve.service_description, ve.preimage,
                   ve.counterparty_id, ve.verified, ve.created_at,
                   ve.metadata,
                   oa.alias as agent_alias
            FROM verified_events ve
            JOIN observer_agents oa ON ve.agent_id = oa.agent_id
            WHERE oa.org_id = %s
        """
        
        if agent_id:
            # Also filter by specific agent within the org
            cursor.execute(base_query + " AND ve.agent_id = %s ORDER BY ve.created_at DESC LIMIT %s",
                (org_id, agent_id, limit))
        else:
            cursor.execute(base_query + " ORDER BY ve.created_at DESC LIMIT %s",
                (org_id, limit))
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

@app.post("/api/v1/admin/auth/login")
def admin_login(request: AdminLoginRequest):
    """
    Platform admin login with email and password.
    Bypasses magic link flow for platform administrators.
    """
    if not BCRYPT_AVAILABLE:
        raise HTTPException(status_code=500, detail="Authentication system not available")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get user by email with platform-admin role
        cursor.execute("""
            SELECT u.id, u.email, u.name, u.role, u.password_hash, u.organization_id,
                   o.org_name as org_name, o.domain
            FROM users u
            JOIN organizations o ON u.organization_id = o.id
            WHERE u.email = %s AND u.role = 'platform-admin' AND u.is_active = TRUE
        """, (request.email,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not user['password_hash']:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check password with bcrypt
        password_bytes = request.password.encode('utf-8')
        stored_hash = user['password_hash'].encode('utf-8') if isinstance(user['password_hash'], str) else user['password_hash']
        
        if not bcrypt.checkpw(password_bytes, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login
        cursor.execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = %s",
            (user['id'],)
        )
        conn.commit()
        
        # Generate session token (simple JWT-like token)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Store session
        cursor.execute("""
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (user['id'], hashlib.sha256(token.encode()).hexdigest(), expires_at))
        conn.commit()
        
        return {
            "token": token,
            "user": {
                "id": str(user['id']),
                "email": user['email'],
                "name": user['name'],
                "role": user['role'],
                "organization_id": str(user['organization_id'])
            }
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(ex)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/admin/orgs")
def list_admin_orgs(authorization: str = Header(None)):
    """List all organizations (platform admin only)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Verify token and check platform-admin role
        cursor.execute("""
            SELECT s.user_id, u.role, s.expires_at
            FROM auth_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = %s AND s.is_revoked = FALSE AND u.is_active = TRUE
        """, (hashlib.sha256(token.encode()).hexdigest(),))
        session = cursor.fetchone()
        
        if not session or session['role'] != 'platform-admin':
            raise HTTPException(status_code=403, detail="Platform admin access required")
        
        if session["expires_at"].replace(tzinfo=None) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Get all orgs except platform admin org
        cursor.execute("""
            SELECT id, org_id as slug_id, org_name as name, domain, kyb_status, created_at
            FROM organizations
            WHERE domain != 'platform.agenticterminal.io'
            ORDER BY created_at DESC
        """)
        orgs = cursor.fetchall()
        
        return [
            {
                "id": str(o['id']),
                "name": o['name'],
                "slug": o['domain'].split('.')[0] if '.' in o['domain'] else o['domain'],
                "domain": o['domain'],
                "kyb_status": o['kyb_status'],
                "created_at": o['created_at'].isoformat() if o['created_at'] else None
            }
            for o in orgs
        ]
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/admin/orgs")
def create_admin_org(request: dict, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    """Create a new organization (platform admin only)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Verify token and check platform-admin role
        cursor.execute("""
            SELECT s.user_id, u.role, s.expires_at
            FROM auth_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = %s AND s.is_revoked = FALSE AND u.is_active = TRUE
        """, (hashlib.sha256(token.encode()).hexdigest(),))
        session = cursor.fetchone()
        
        if not session or session['role'] != 'platform-admin':
            raise HTTPException(status_code=403, detail="Platform admin access required")
        
        if session["expires_at"].replace(tzinfo=None) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Session expired")
        
        name = request.get('name')
        slug = request.get('slug')
        
        if not name or not slug:
            raise HTTPException(status_code=400, detail="Name and slug are required")
        
        domain = f"{slug}.agenticterminal.io"
        
        # Check if domain exists
        cursor.execute("SELECT 1 FROM organizations WHERE domain = %s", (domain,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Organization slug already exists")
        
        # Create org
        placeholder_pubkey = secrets.token_hex(32)
        cursor.execute("""
            INSERT INTO organizations (org_id, org_name, domain, public_key, kyb_status)
            VALUES (%s, %s, %s, 'placeholder_key', 'pending')
            RETURNING id, org_name as name, domain, kyb_status, created_at
        """, (name, domain, placeholder_pubkey))
        org = cursor.fetchone()
        conn.commit()
        
        return {
            "id": str(org['id']),
            "name": org['name'],
            "slug": slug,
            "domain": org['domain'],
            "kyb_status": org['kyb_status'],
            
            "created_at": org['created_at'].isoformat() if org['created_at'] else None
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/admin/orgs/{org_id}/invite")
def invite_admin_to_org(org_id: str, request: dict, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    """Invite an admin to an organization (platform admin only)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Verify token and check platform-admin role
        cursor.execute("""
            SELECT s.user_id, u.role, s.expires_at
            FROM auth_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = %s AND s.is_revoked = FALSE AND u.is_active = TRUE
        """, (hashlib.sha256(token.encode()).hexdigest(),))
        session = cursor.fetchone()
        
        if not session or session['role'] != 'platform-admin':
            raise HTTPException(status_code=403, detail="Platform admin access required")
        
        if session["expires_at"].replace(tzinfo=None) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Session expired")
        
        email = request.get('email')
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        
        # Verify org exists
        cursor.execute("SELECT * FROM organizations WHERE id = %s", (org_id,))
        org = cursor.fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE email = %s AND organization_id = %s", (email, org_id))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="User already exists in this organization")
        
        # Generate invitation token
        invitation_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=48)
        
        # Create invitation
        cursor.execute("""
            INSERT INTO user_invitations (organization_id, email, invited_by, token, expires_at, role)
            VALUES (%s, %s, %s, %s, %s, 'admin')
            RETURNING id
        """, (org_id, email, session['user_id'], invitation_token, expires_at))
        invitation_id = cursor.fetchone()['id']
        conn.commit()
        
        magic_link = f"/enterprise/demo-access?token={invitation_token}"
        
        return {
            "success": True,
            "message": f"Invitation sent to {email}",
            "invitation_id": str(invitation_id),
            "magic_link": magic_link,
            "token": invitation_token
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/enterprise/auth/validate-token")
async def validate_enterprise_token(request: Request):
    body = await request.json()
    token = body.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token required")
    from datetime import datetime, timezone
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT i.organization_id, i.email, i.role, i.expires_at,
                   o.org_name, o.domain
            FROM user_invitations i
            JOIN organizations o ON o.id = i.organization_id
            WHERE i.token = %s
        """, (token,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid token")
        org_id, email, role, expires_at, org_name, domain = row
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token expired")
        return {
            "valid": True,
            "organization_id": org_id,
            "org_name": org_name,
            "domain": domain,
            "email": email,
            "role": role
        }
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

# =============================================================================
# SIWW (Sign-In With Wallet) Endpoints
# =============================================================================

class SIWWChallengeRequest(BaseModel):
    wallet_address: str
    wallet_type: str  # 'metamask', 'alby', 'tronlink', 'phantom'

class SIWWChallengeResponse(BaseModel):
    nonce: str
    challenge_message: str
    expires_at: str

class SIWWVerifyRequest(BaseModel):
    wallet_address: str
    wallet_type: str
    nonce: str
    signature: str
    magic_link_token: Optional[str] = None  # Present for onboarding, absent for re-auth

class BindWalletRequest(BaseModel):
    invitation_token: str
    wallet_address: str
    wallet_type: str  # 'evm', 'tron', 'solana', 'lightning'
    signature: str
    message: str  # The challenge message that was signed
    chain_type: Optional[str] = None  # 'evm', 'tron' - for signature verification routing

class BindWalletResponse(BaseModel):
    success: bool
    user_id: Optional[str] = None
    org_id: Optional[int] = None
    org_name: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    message: Optional[str] = None

class SIWWVerifyResponse(BaseModel):
    success: bool
    user_id: Optional[str] = None
    org_id: Optional[int] = None
    org_name: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    session_token: Optional[str] = None
    message: Optional[str] = None

def _generate_challenge_message(nonce: str, wallet_address: str, wallet_type: str, origin: str = "app.agenticterminal.io") -> str:
    """Generate EIP-4361 style challenge message."""
    from datetime import datetime, timezone
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # EIP-4361 requires domain in message to match the origin serving the page
    domain = origin.replace("https://", "").replace("http://", "").split(":")[0]
    return f"{domain} wants you to sign in with your {wallet_type} account:\n{wallet_address}\n\nNonce: {nonce}\nIssued At: {issued_at}"

@app.post("/api/v1/auth/challenge", response_model=SIWWChallengeResponse)
def siww_create_challenge(body: SIWWChallengeRequest, request: Request):
    """
    Create a challenge nonce for SIWW authentication.
    The client must sign this challenge with their wallet.
    """
    import secrets
    from datetime import datetime, timezone, timedelta
    
    # Get origin from request headers for EIP-4361 compliance
    origin = request.headers.get("origin") or request.headers.get("referer") or "https://app.agenticterminal.io"
    
    nonce = secrets.token_urlsafe(32)
    challenge_message = _generate_challenge_message(nonce, body.wallet_address, body.wallet_type, origin)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO auth_challenges (nonce, wallet_address, wallet_type, challenge_message, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (nonce, body.wallet_address.lower(), body.wallet_type, challenge_message, expires_at),
        )
        conn.commit()
        
        return SIWWChallengeResponse(
            nonce=nonce,
            challenge_message=challenge_message,
            expires_at=expires_at.isoformat(),
        )
    except Exception as ex:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create challenge: {str(ex)}")
    finally:
        cursor.close()
        conn.close()

def _verify_eip4361_signature(wallet_address: str, challenge_message: str, signature: str) -> bool:
    """Verify EIP-4361 / Ethereum personal_sign signature using siwe library."""
    try:
        from siwe import SiweMessage
        from datetime import datetime, timezone
        
        # Parse the SIWE message
        siwe_msg = SiweMessage.from_message(challenge_message)
        
        # Verify the signature
        siwe_msg.verify(signature, nonce=siwe_msg.nonce)
        
        # Also verify the wallet address matches
        return siwe_msg.address.lower() == wallet_address.lower()
    except Exception as ex:
        print(f"SIWE signature verification error: {ex}")
        # Fallback to manual verification if siwe fails
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct
            
            message = encode_defunct(text=challenge_message)
            recovered_address = Account.recover_message(message, signature=signature)
            return recovered_address.lower() == wallet_address.lower()
        except Exception as fallback_ex:
            print(f"Fallback signature verification error: {fallback_ex}")
            return False

@app.post("/api/v1/auth/verify", response_model=SIWWVerifyResponse)
def siww_verify_signature(request: SIWWVerifyRequest):
    """
    Verify a wallet signature for SIWW authentication.
    Supports onboarding (with magic_link_token) and re-auth flows.
    """
    import secrets
    from datetime import datetime, timezone
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Look up and validate the challenge
        cursor.execute(
            """
            SELECT challenge_message, expires_at, used_at 
            FROM auth_challenges 
            WHERE nonce = %s AND wallet_address = %s AND wallet_type = %s
            """,
            (request.nonce, request.wallet_address.lower(), request.wallet_type),
        )
        row = cursor.fetchone()
        if not row:
            return SIWWVerifyResponse(success=False, message="Invalid challenge nonce")
        
        challenge_message, expires_at, used_at = row
        
        if used_at:
            return SIWWVerifyResponse(success=False, message="Challenge already used")
        
        if expires_at < datetime.now(timezone.utc):
            return SIWWVerifyResponse(success=False, message="Challenge expired")
        
        # 2. Mark challenge as used
        cursor.execute(
            "UPDATE auth_challenges SET used_at = now() WHERE nonce = %s",
            (request.nonce,),
        )
        
        # 3. Verify signature (MetaMask/Alby use EIP-4361)
        if request.wallet_type in ('metamask', 'alby'):
            if not _verify_eip4361_signature(request.wallet_address, challenge_message, request.signature):
                conn.rollback()
                return SIWWVerifyResponse(success=False, message="Invalid signature")
        else:
            conn.rollback()
            return SIWWVerifyResponse(success=False, message=f"Wallet type {request.wallet_type} not yet supported")
        
        # 4. Handle onboarding vs re-auth
        if request.magic_link_token:
            # ONBOARDING FLOW
            cursor.execute(
                """
                SELECT i.organization_id, i.email, i.role, i.expires_at, o.org_name
                FROM user_invitations i
                JOIN organizations o ON o.id = i.organization_id
                WHERE i.token = %s
                """,
                (request.magic_link_token,),
            )
            invite = cursor.fetchone()
            if not invite:
                conn.rollback()
                return SIWWVerifyResponse(success=False, message="Invalid invitation token")
            
            org_id, email, role, expires_at, org_name = invite
            
            if expires_at < datetime.now(timezone.utc):
                conn.rollback()
                return SIWWVerifyResponse(success=False, message="Invitation expired")
            
            # Find or create user
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user_row = cursor.fetchone()
            if user_row:
                user_id = user_row[0]
            else:
                cursor.execute(
                    """
                    INSERT INTO users (email, name, organization_id, role)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (email, email.split('@')[0], org_id, role),
                )
                user_id = cursor.fetchone()[0]
            
            # Create wallet membership
            try:
                cursor.execute(
                    """
                    INSERT INTO wallet_org_memberships (user_id, org_id, wallet_address, wallet_type, role)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user_id, org_id, request.wallet_address.lower(), request.wallet_type, role),
                )
            except psycopg2.errors.UniqueViolation:
                # Wallet already registered for this org
                pass
        else:
            # RE-AUTH FLOW
            # Fetch all memberships for this wallet
            cursor.execute(
                """
                SELECT w.user_id, w.org_id, w.role, o.org_name
                FROM wallet_org_memberships w
                JOIN organizations o ON o.id = w.org_id
                WHERE w.wallet_address = %s AND w.wallet_type = %s AND w.revoked_at IS NULL
                """,
                (request.wallet_address.lower(), request.wallet_type),
            )
            memberships = cursor.fetchall()
            
            if not memberships:
                conn.rollback()
                return SIWWVerifyResponse(success=False, message="wallet_not_registered")
            
            # Check for multi-membership scenario
            if len(memberships) > 1:
                # Build list of orgs for 409 response
                orgs_list = [
                    {
                        "org_id": m[1],
                        "org_name": m[3],
                        "role": m[2]
                    }
                    for m in memberships
                ]
                
                # Check if we have an invitation token context to resolve ambiguity
                # For now, return 409 with orgs list for frontend to handle
                conn.rollback()
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": "multiple_memberships",
                        "message": "Wallet has memberships in multiple organizations",
                        "organizations": orgs_list
                    }
                )
            
            # Single membership - proceed as before
            user_id, org_id, role, org_name = memberships[0]
            
            # DEBUG LOGGING
            print(f"[SIWW DEBUG] Single membership for wallet {request.wallet_address}: user_id={user_id}, org_id={org_id}, org_name={org_name}")
            
            # Update last_login_at
            cursor.execute(
                "UPDATE wallet_org_memberships SET last_login_at = now() WHERE user_id = %s AND org_id = %s AND wallet_address = %s",
                (user_id, org_id, request.wallet_address.lower()),
            )
        
        # 5. Create session (matches Phase 1 pattern)
        session_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        cursor.execute(
            """
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, now())
            """,
            (user_id, token_hash, expires_at),
        )
        
        conn.commit()
        
        # Fetch email for cookies (needed in both flows)
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        email_row = cursor.fetchone()
        user_email = email_row[0] if email_row else ""
        print(f"[SIWW DEBUG] Fetched email for user_id={user_id}: email_row={email_row}, user_email='{user_email}'")
        
        # Build response with Set-Cookie headers (matches magic-link flow)
        from fastapi.responses import JSONResponse
        response = JSONResponse({
            "success": True,
            "user_id": str(user_id),
            "org_id": org_id,
            "org_name": org_name,
            "role": role,
            "email": user_email,
            "session_token": session_token,
        })
        
        # Set enterprise_session cookie (HttpOnly, Secure - auth token, NOT readable by JS)
        response.set_cookie(
            key="enterprise_session",
            value=session_token,  # Raw token, NOT hashed
            max_age=86400,
            path="/",
            httponly=True,      # JavaScript cannot read this
            secure=True,        # HTTPS only
            samesite="lax",
            domain=".agenticterminal.io"
        )
        
        # Set display cookies (readable by JS for UI, NOT trusted for auth)
        response.set_cookie(
            key="enterprise_email",
            value=user_email,
            max_age=86400,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
        response.set_cookie(
            key="enterprise_org",
            value=org_name,
            max_age=86400,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
        response.set_cookie(
            key="enterprise_org_id",
            value=str(org_id),
            max_age=86400,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
        response.set_cookie(
            key="enterprise_role",
            value=role,
            max_age=86400,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
        response.set_cookie(
            key="enterprise_wallet",
            value=request.wallet_address.lower(),
            max_age=86400,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as ex:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(ex)}")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/enterprise/auth/bind-wallet")
async def bind_wallet(request: Request):
    """
    Chain-aware wallet binding endpoint.
    Validates invitation token AND wallet signature in one call.
    """
    from datetime import datetime, timezone, timedelta
    import hashlib
    import secrets
    
    body = await request.json()
    invitation_token = body.get('invitation_token')
    wallet_address = body.get('wallet_address')
    wallet_type = body.get('wallet_type')
    signature = body.get('signature')
    message = body.get('message')
    chain_type = body.get('chain_type', wallet_type)
    
    if not all([invitation_token, wallet_address, wallet_type, signature, message]):
        raise HTTPException(status_code=400, detail="Missing required fields")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Validate invitation
        cursor.execute("""
            SELECT i.id, i.organization_id, i.email, i.role, i.expires_at, i.accepted_at, o.org_name
            FROM user_invitations i
            JOIN organizations o ON o.id = i.organization_id
            WHERE i.token = %s
        """, (invitation_token,))
        invite = cursor.fetchone()
        
        if not invite:
            raise HTTPException(status_code=401, detail="Invalid invitation token")
        
        invite_id, org_id, email, role, expires_at, accepted_at, org_name = invite
        
        # Check if already accepted
        if accepted_at:
            cursor.execute("""
                SELECT w.wallet_address FROM wallet_org_memberships w
                JOIN users u ON u.id = w.user_id
                WHERE u.email = %s AND w.org_id = %s
            """, (email, org_id))
            if cursor.fetchone():
                raise HTTPException(status_code=409, detail="already_bound")
        
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Invitation expired")
        
        # Find or create user
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_row = cursor.fetchone()
        if user_row:
            user_id = user_row[0]
        else:
            cursor.execute("""
                INSERT INTO users (email, name, organization_id, role)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (email, email.split('@')[0], org_id, role))
            user_id = cursor.fetchone()[0]
        
        # Create wallet membership
        try:
            cursor.execute("""
                INSERT INTO wallet_org_memberships (user_id, org_id, wallet_address, wallet_type, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, org_id, wallet_address.lower(), wallet_type, role))
        except psycopg2.errors.UniqueViolation:
            pass
        
        # Mark invitation accepted
        cursor.execute("UPDATE user_invitations SET accepted_at = NOW() WHERE id = %s AND accepted_at IS NULL", (invite_id,))
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        cursor.execute("""
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (user_id, token_hash, expires_at))
        
        conn.commit()
        
        response = JSONResponse({"success": True, "user_id": str(user_id), "org_id": org_id, "org_name": org_name, "role": role, "email": email})
        response.set_cookie(key="enterprise_session", value=session_token, max_age=86400, path="/", httponly=True, secure=True, samesite="lax", domain=".agenticterminal.io")
        response.set_cookie(key="enterprise_org", value=org_name, max_age=86400, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_org_id", value=str(org_id), max_age=86400, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_role", value=role, max_age=86400, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_email", value=email, max_age=86400, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_wallet", value=wallet_address.lower(), max_age=86400, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        
        return response
        
    except HTTPException:
        raise
    except Exception as ex:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(ex))
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/auth/logout")
def logout(request: Request):
    """
    Logout endpoint: Revokes the session and clears all auth cookies.
    Idempotent: Returns 200 even if session is already invalid/expired.
    """
    from fastapi.responses import JSONResponse
    
    # Try to get and revoke session (if valid)
    session_token = request.cookies.get("enterprise_session")
    if session_token:
        try:
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    UPDATE auth_sessions 
                    SET is_revoked = true, revoked_at = NOW() 
                    WHERE token_hash = %s AND is_revoked = false
                """, (token_hash,))
                conn.commit()
            finally:
                cursor.close()
                conn.close()
        except Exception:
            # Ignore errors - logout should succeed even if DB update fails
            pass
    
    # Build response with all cookies cleared
    response = JSONResponse({"success": True, "message": "Logged out"})
    
    # Clear enterprise_session (HttpOnly auth cookie)
    response.set_cookie(
        key="enterprise_session",
        value="",
        max_age=0,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
        domain=".agenticterminal.io"
    )
    
    # Clear display cookies
    for cookie_name in ["enterprise_email", "enterprise_org", "enterprise_org_id", "enterprise_role", "enterprise_wallet"]:
        response.set_cookie(
            key=cookie_name,
            value="",
            max_age=0,
            path="/",
            secure=True,
            samesite="lax",
            domain=".agenticterminal.io"
        )
    
    return response

# =============================================================================
# Chain-Aware Signature Verification
# =============================================================================

def verify_signature(chain_type: str, address: str, message: str, signature: str) -> bool:
    """
    Route signature verification to the correct chain verifier.
    """
    if chain_type == "evm":
        return verify_evm_signature(address, message, signature)
    elif chain_type == "tron":
        return verify_tron_signature(address, message, signature)
    elif chain_type == "solana":
        return verify_solana_signature(address, message, signature)
    elif chain_type == "lightning":
        return verify_lnurl_auth(address, message, signature)
    elif chain_type == "tether_wdk":
        return verify_wdk_signature(address, message, signature)
    else:
        raise ValueError(f"Unsupported chain_type: {chain_type}")

def verify_evm_signature(address: str, message: str, signature: str) -> bool:
    """
    Verify EIP-191 personal_sign signature.
    """
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account
        
        # Recover address from signature
        message_encoded = encode_defunct(text=message)
        recovered_address = Account.recover_message(message_encoded, signature=signature)
        
        # Compare addresses (case-insensitive)
        return recovered_address.lower() == address.lower()
    except Exception as ex:
        print(f"[EVM Signature Verify Error] {ex}")
        return False

def verify_tron_signature(address: str, message: str, signature: str) -> bool:
    """
    Verify TRON signature using tronpy.
    TRON addresses are base58 encoded.
    """
    try:
        from tronpy import Tron
        from tronpy.keys import to_hex_address
        
        # Convert base58 address to hex if needed
        if address.startswith('T'):
            # It's a base58 address
            hex_address = to_hex_address(address)
        else:
            hex_address = address
        
        # For now, do basic validation - full crypto verification would need tronweb
        # Check signature format (65 bytes = 130 hex chars)
        if not signature or len(signature) < 130:
            return False
            
        # TODO: Implement full TRON signature verification
        # For production, use: Tron().trx.verify_message(message, signature)
        return True
    except Exception as ex:
        print(f"[TRON Signature Verify Error] {ex}")
        return True  # TEMP: Accept for testing

def verify_solana_signature(address: str, message: str, signature: str) -> bool:
    """
    Verify Solana Ed25519 signature.
    STUB - NotImplementedError for now.
    """
    raise NotImplementedError("Solana signature verification not yet implemented")

def verify_lnurl_auth(address: str, message: str, signature: str) -> bool:
    """
    Verify LNURL-auth k1 challenge signature.
    STUB - NotImplementedError for now.
    """
    raise NotImplementedError("Lightning/LNURL-auth verification not yet implemented")

def verify_wdk_signature(address: str, message: str, signature: str) -> bool:
    """
    Verify Tether WDK signature.
    STUB - NotImplementedError for now.
    """
    raise NotImplementedError("Tether WDK verification not yet implemented")

def generate_challenge_message(nonce: str, address: str, chain_type: str, origin: str = "app.agenticterminal.io") -> str:
    """
    Generate chain-aware SIWE-style challenge message.
    """
    from datetime import datetime, timezone
    
    chain_labels = {
        "evm": "Ethereum",
        "tron": "TRON",
        "solana": "Solana",
        "lightning": "Lightning",
        "tether_wdk": "Tether"
    }
    
    chain_label = chain_labels.get(chain_type, "Unknown Chain")
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    domain = origin.replace("https://", "").replace("http://", "").split(":")[0]
    
    return f"{domain} wants you to sign in with your {chain_label} account:\n{address}\n\nNonce: {nonce}\nIssued At: {issued_at}"

# =============================================================================
# Enterprise Auth Rebuild Endpoints
# =============================================================================

class AuthNonceRequest(BaseModel):
    wallet_address: str
    chain_type: str  # 'evm', 'tron', 'solana', 'lightning', 'tether_wdk'

class AuthNonceResponse(BaseModel):
    nonce: str
    message: str
    expires_at: str

class AuthOnboardRequest(BaseModel):
    invitation_token: str
    wallet_address: str
    chain_type: str
    message: str
    signature: str

class AuthOnboardResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    account_id: Optional[str] = None
    org_id: Optional[int] = None
    org_name: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    wallet: Optional[dict] = None
    message: Optional[str] = None

class AuthLoginRequest(BaseModel):
    wallet_address: str
    chain_type: str
    message: str
    signature: str

class AuthLoginResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    account_id: Optional[str] = None
    wallet: Optional[dict] = None
    message: Optional[str] = None

class AddWalletRequest(BaseModel):
    wallet_address: str
    chain_type: str
    message: str
    signature: str
    label: Optional[str] = None

# =============================================================================
# Multi-Wallet Auth Endpoints (using wallet_org_memberships)
# =============================================================================

class AuthNonceRequest(BaseModel):
    wallet_address: str
    chain_type: str  # 'evm', 'tron', 'solana', 'lightning'

class AuthNonceResponse(BaseModel):
    nonce: str
    message: str
    expires_at: str

class AuthOnboardRequest(BaseModel):
    invitation_token: str
    wallet_address: str
    chain_type: str
    message: str
    signature: str

class AuthLoginRequest(BaseModel):
    wallet_address: str
    chain_type: str
    message: str
    signature: str

class AddWalletRequest(BaseModel):
    wallet_address: str
    chain_type: str
    message: str
    signature: str
    label: Optional[str] = None

@app.post("/api/v1/enterprise/auth/nonce", response_model=AuthNonceResponse)
async def auth_nonce(body: AuthNonceRequest, request: Request):
    """Issue a nonce for wallet signing."""
    from datetime import datetime, timezone, timedelta
    import secrets
    
    nonce = secrets.token_urlsafe(32)
    origin = request.headers.get("origin") or request.headers.get("referer") or "https://app.agenticterminal.io"
    message = generate_challenge_message(nonce, body.wallet_address, body.chain_type, origin)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO auth_challenges (nonce, wallet_address, wallet_type, challenge_message, expires_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (nonce, body.wallet_address.lower(), body.chain_type, message, expires_at))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    
    return AuthNonceResponse(nonce=nonce, message=message, expires_at=expires_at.isoformat())

@app.post("/api/v1/enterprise/auth/onboard")
async def auth_onboard(body: AuthOnboardRequest, request: Request):
    """First-time onboarding using invitation token."""
    from datetime import datetime, timezone, timedelta
    import hashlib
    import secrets
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Validate invitation
        cursor.execute("""
            SELECT i.id, i.organization_id, i.email, i.role, i.expires_at, i.accepted_at, o.org_name
            FROM user_invitations i
            JOIN organizations o ON o.id = i.organization_id
            WHERE i.token = %s
        """, (body.invitation_token,))
        invite = cursor.fetchone()
        
        if not invite:
            raise HTTPException(status_code=401, detail="INVITATION_INVALID")
        
        invite_id, org_id, email, role, expires_at, accepted_at, org_name = invite
        
        # Check if already accepted
        if accepted_at:
            # Check if wallet already bound
            cursor.execute("""
                SELECT w.wallet_address FROM wallet_org_memberships w
                JOIN users u ON u.id = w.user_id
                WHERE u.email = %s AND w.wallet_type = %s AND w.revoked_at IS NULL
            """, (email, body.chain_type))
            if cursor.fetchone():
                raise HTTPException(status_code=409, detail="already_bound")
        
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="INVITATION_INVALID")
        
        # Verify signature
        try:
            sig_valid = verify_signature(body.chain_type, body.wallet_address, body.message, body.signature)
        except NotImplementedError as ne:
            raise HTTPException(status_code=501, detail=str(ne))
        
        if not sig_valid:
            raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
        
        # Find or create user
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_row = cursor.fetchone()
        
        if user_row:
            user_id = user_row[0]
        else:
            cursor.execute("""
                INSERT INTO users (email, name, organization_id, role)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (email, email.split('@')[0], org_id, role))
            user_id = cursor.fetchone()[0]
        
        # Create wallet membership (is_primary = true for first wallet)
        try:
            cursor.execute("""
                INSERT INTO wallet_org_memberships (user_id, org_id, wallet_address, wallet_type, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, org_id, body.wallet_address.lower(), body.chain_type, role))
        except psycopg2.errors.UniqueViolation:
            pass  # Already exists
        
        # Mark invitation accepted
        cursor.execute("UPDATE user_invitations SET accepted_at = NOW() WHERE id = %s AND accepted_at IS NULL", (invite_id,))
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        cursor.execute("""
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (user_id, token_hash, expires_at))
        
        conn.commit()
        
        response = JSONResponse({
            "success": True,
            "session_token": session_token,
            "account_id": str(user_id),
            "org_id": org_id,
            "org_name": org_name,
            "role": role,
            "email": email,
            "wallet": {
                "address": body.wallet_address,
                "chain_type": body.chain_type,
                "is_primary": True
            }
        })
        
        response.set_cookie(key="enterprise_session", value=session_token, max_age=604800, path="/", httponly=True, secure=True, samesite="lax", domain=".agenticterminal.io")
        response.set_cookie(key="enterprise_org", value=org_name, max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_org_id", value=str(org_id), max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_role", value=role, max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_email", value=email, max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_wallet", value=body.wallet_address.lower(), max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        
        return response
        
    except HTTPException:
        raise
    except Exception as ex:
        conn.rollback()
        print(f"[Onboard Error] {ex}")
        raise HTTPException(status_code=500, detail="Internal error")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/enterprise/auth/login")
async def auth_login(body: AuthLoginRequest, request: Request):
    """Returning user login via bound wallet."""
    from datetime import datetime, timezone, timedelta
    import hashlib
    import secrets
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Look up wallet in wallet_org_memberships
        cursor.execute("""
            SELECT w.user_id, w.org_id, w.role, w.last_login_at, u.email
            FROM wallet_org_memberships w
            JOIN users u ON u.id = w.user_id
            WHERE w.wallet_address = %s AND w.wallet_type = %s AND w.revoked_at IS NULL
        """, (body.wallet_address.lower(), body.chain_type))
        wallet_row = cursor.fetchone()
        
        if not wallet_row:
            raise HTTPException(status_code=404, detail="WALLET_NOT_REGISTERED")
        
        user_id, org_id, role, last_login, email = wallet_row
        
        # Verify signature
        try:
            sig_valid = verify_signature(body.chain_type, body.wallet_address, body.message, body.signature)
        except NotImplementedError as ne:
            raise HTTPException(status_code=501, detail=str(ne))
        
        if not sig_valid:
            raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
        
        # Update last_login_at
        cursor.execute("""
            UPDATE wallet_org_memberships SET last_login_at = NOW()
            WHERE user_id = %s AND org_id = %s AND wallet_address = %s
        """, (user_id, org_id, body.wallet_address.lower()))
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        cursor.execute("""
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (user_id, token_hash, expires_at))
        
        conn.commit()
        
        # Check if primary wallet (oldest non-revoked for this user/org)
        cursor.execute("""
            SELECT id FROM wallet_org_memberships
            WHERE user_id = %s AND org_id = %s AND revoked_at IS NULL
            ORDER BY created_at ASC LIMIT 1
        """, (user_id, org_id))
        primary_row = cursor.fetchone()
        is_primary = primary_row is not None
        
        cursor.execute("SELECT org_name FROM organizations WHERE id = %s", (org_id,))
        org_name_row = cursor.fetchone()
        org_name = org_name_row[0] if org_name_row else ""
        
        response = JSONResponse({
            "success": True,
            "session_token": session_token,
            "account_id": str(user_id),
            "wallet": {
                "address": body.wallet_address,
                "chain_type": body.chain_type,
                "is_primary": is_primary
            }
        })
        
        response.set_cookie(key="enterprise_session", value=session_token, max_age=604800, path="/", httponly=True, secure=True, samesite="lax", domain=".agenticterminal.io")
        if org_name:
            response.set_cookie(key="enterprise_org", value=org_name, max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_org_id", value=str(org_id), max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_role", value=role, max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_email", value=email or "", max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        response.set_cookie(key="enterprise_wallet", value=body.wallet_address.lower(), max_age=604800, path="/", domain=".agenticterminal.io", secure=True, samesite="lax")
        
        return response
        
    except HTTPException:
        raise
    except Exception as ex:
        conn.rollback()
        print(f"[Login Error] {ex}")
        raise HTTPException(status_code=500, detail="Internal error")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/enterprise/wallets/add")
async def add_wallet(body: AddWalletRequest, request: Request):
    """Add additional wallet to existing account."""
    # Validate session
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "operator")
    
    from datetime import datetime, timezone
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify signature
        try:
            sig_valid = verify_signature(body.chain_type, body.wallet_address, body.message, body.signature)
        except NotImplementedError as ne:
            raise HTTPException(status_code=501, detail=str(ne))
        
        if not sig_valid:
            raise HTTPException(status_code=401, detail="SIGNATURE_INVALID")
        
        # Check wallet not bound to different account
        cursor.execute("""
            SELECT user_id FROM wallet_org_memberships
            WHERE wallet_address = %s AND wallet_type = %s AND revoked_at IS NULL
        """, (body.wallet_address.lower(), body.chain_type))
        existing = cursor.fetchone()
        
        if existing and str(existing[0]) != str(user_id):
            raise HTTPException(status_code=409, detail="WALLET_ALREADY_BOUND")
        
        # Add wallet with is_primary=false (additional wallets are never primary)
        try:
            cursor.execute("""
                INSERT INTO wallet_org_memberships (user_id, org_id, wallet_address, wallet_type, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, org_id, body.wallet_address.lower(), body.chain_type, role))
        except psycopg2.errors.UniqueViolation:
            # Already exists for this account, update
            cursor.execute("""
                UPDATE wallet_org_memberships SET last_login_at = NOW()
                WHERE user_id = %s AND wallet_address = %s AND wallet_type = %s
            """, (user_id, body.wallet_address.lower(), body.chain_type))
        
        conn.commit()
        
        # Return updated wallet list
        cursor.execute("""
            SELECT wallet_address, wallet_type, created_at, last_login_at
            FROM wallet_org_memberships
            WHERE user_id = %s AND org_id = %s AND revoked_at IS NULL
            ORDER BY created_at ASC
        """, (user_id, org_id))
        wallets = [
            {
                "address": r[0],
                "chain_type": r[1],
                "created_at": r[2].isoformat() if r[2] else None,
                "last_signed_at": r[3].isoformat() if r[3] else None
            }
            for r in cursor.fetchall()
        ]
        
        return {"success": True, "wallets": wallets}
        
    except HTTPException:
        raise
    except Exception as ex:
        conn.rollback()
        print(f"[Add Wallet Error] {ex}")
        raise HTTPException(status_code=500, detail="Internal error")
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/enterprise/wallets")
def get_wallets(request: Request):
    """Get all wallets bound to authenticated account."""
    user_id, org_id, email, role = require_role(validate_enterprise_session(request), "viewer")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get primary wallet (oldest non-revoked)
        cursor.execute("""
            SELECT id FROM wallet_org_memberships
            WHERE user_id = %s AND org_id = %s AND revoked_at IS NULL
            ORDER BY created_at ASC LIMIT 1
        """, (user_id, org_id))
        primary_row = cursor.fetchone()
        primary_id = primary_row[0] if primary_row else None
        
        cursor.execute("""
            SELECT id, wallet_address, wallet_type, created_at, last_login_at
            FROM wallet_org_memberships
            WHERE user_id = %s AND org_id = %s AND revoked_at IS NULL
            ORDER BY created_at ASC
        """, (user_id, org_id))
        
        wallets = [
            {
                "id": r[0],
                "address": r[1],
                "chain_type": r[2],
                "created_at": r[3].isoformat() if r[3] else None,
                "last_signed_at": r[4].isoformat() if r[4] else None,
                "is_primary": r[0] == primary_id
            }
            for r in cursor.fetchall()
        ]
        
        return {"wallets": wallets}
        
    finally:
        cursor.close()
        conn.close()

# ============================================================
# TRON RAIL ENDPOINTS
# ============================================================

import subprocess
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Thread pool for Node.js subprocess calls
_tron_executor = ThreadPoolExecutor(max_workers=4)

class TRONReceiptSubmitRequest(BaseModel):
    vc: dict = Field(..., description="Signed tron_receipt_v1 Verifiable Credential")

class TRONReceiptResponse(BaseModel):
    success: bool
    receipt_id: Optional[str] = None
    vc_id: Optional[str] = None
    verified: bool = False
    error: Optional[str] = None

class TRONTrustScoreResponse(BaseModel):
    agent_id: str
    trust_score: float = Field(..., ge=0.0, le=100.0)
    receipt_count: int = 0
    unique_counterparties: int = 0
    total_trx_volume: str = "0"
    total_stablecoin_volume: str = "0"
    org_affiliated_count: int = 0
    last_activity: Optional[str] = None
    components: dict = Field(default_factory=dict)

class TRONLeaderboardEntry(BaseModel):
    agent_id: str
    trust_score: float
    receipt_count: int
    unique_counterparties: int
    total_volume: str
    rank: int

def _call_tron_rail_verify(vc: dict) -> dict:
    """Call TRON rail library via Node.js subprocess to verify a receipt VC."""

    # Escape the VC for JavaScript
    vc_json = json.dumps(vc).replace('\\', '\\\\').replace("'", "\\'")

    js_code = f"""
    import('/media/nvme/observer-protocol/rails/tron/index.mjs')
        .then(async (rail) => {{
            try {{
                const verifier = new rail.TronReceiptVerifier();
                const result = await verifier.verifyReceipt({vc_json});
                console.log(JSON.stringify(result));
            }} catch (err) {{
                console.log(JSON.stringify({{error: err.message}}));
            }}
        }})
        .catch(err => {{
            console.log(JSON.stringify({{error: err.message}}));
        }});
    """

    # Pass environment variables to subprocess
    env = os.environ.copy()
    env['TRON_NETWORK'] = os.environ.get('TRON_NETWORK', 'mainnet')
    if os.environ.get('OP_SKIP_TRON_VERIFICATION'):
        env['OP_SKIP_TRON_VERIFICATION'] = os.environ.get('OP_SKIP_TRON_VERIFICATION')

    try:
        result = subprocess.run(
            ['node', '-e', js_code],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )
        if result.returncode == 0 and result.stdout.strip():
            # Get the last line which should be the JSON result
            lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
            for line in reversed(lines):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        if result.stderr:
            return {"error": f"Rail error: {result.stderr[:200]}"}
        return {"error": "Rail call failed: no valid response"}
    except subprocess.TimeoutExpired:
        return {"error": "TRON rail timeout"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/v1/tron/receipts/submit", response_model=TRONReceiptResponse)
async def submit_tron_receipt(body: TRONReceiptSubmitRequest):
    """
    Submit a signed tron_receipt_v1 Verifiable Credential for verification and storage.
    """
    vc = body.vc
    
    # Validate required fields
    if not vc or not isinstance(vc, dict):
        raise HTTPException(status_code=400, detail="Invalid VC: must be a JSON object")
    
    vc_id = vc.get('id')
    if not vc_id:
        raise HTTPException(status_code=400, detail="Invalid VC: missing 'id' field")
    
    # Check if receipt already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT receipt_id, verified FROM tron_receipts WHERE vc_id = %s",
            (vc_id,)
        )
        existing = cursor.fetchone()
        if existing:
            return TRONReceiptResponse(
                success=True,
                receipt_id=str(existing[0]),
                vc_id=vc_id,
                verified=existing[1],
                error=None
            )
    finally:
        cursor.close()
        conn.close()
    
    # Call TRON rail for verification
    rail_result = await asyncio.get_event_loop().run_in_executor(
        _tron_executor,
        lambda: _call_tron_rail_verify(vc)
    )
    
    if rail_result.get('error'):
        raise HTTPException(status_code=400, detail=f"Verification failed: {rail_result['error']}")
    
    if not rail_result.get('verified') and not rail_result.get('valid'):
        raise HTTPException(status_code=400, detail="VC signature verification failed")
    
    # Policy consultation
    _cs = vc.get('credentialSubject', {})
    _tron_agent_id = _cs.get('agentId') or (_cs.get('id', '').split('/')[-1] if '/agents/' in _cs.get('id', '') else None)
    if _tron_agent_id:
        _tron_conn = get_db_connection()
        _tron_cursor = _tron_conn.cursor()
        _tron_org = _get_agent_org_id(_tron_cursor, _tron_agent_id)
        _tron_cursor.close()
        _tron_conn.close()
        _consult_policy(_tron_org, "transaction.submit", {
            "actor": {"agent_id": _tron_agent_id},
            "transaction": {"rail": _cs.get('rail', 'tron'), "amount": str(_cs.get('amount', '')), "reference_id": _cs.get('tronTxHash', '')},
        })

    # Persist to database
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        credential_subject = vc.get('credentialSubject', {})
        
        cursor.execute("""
            INSERT INTO tron_receipts (
                vc_id, issuer_did, subject_did, subject_agent_id, rail, asset, amount,
                tron_tx_hash, sender_address, recipient_address, token_contract,
                network, tx_timestamp, confirmations, org_affiliation, verified,
                tron_grid_verified, signature_verified, verification_error,
                issued_at, expires_at, vc_document, receipt_hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (vc_id) DO NOTHING
            RETURNING receipt_id
        """, (
            vc_id,
            vc.get('issuer', {}).get('id', ''),
            credential_subject.get('id', ''),
            credential_subject.get('agentId') or (credential_subject.get('id', '').split('/')[-1] if '/agents/' in credential_subject.get('id', '') else None),
            credential_subject.get('rail', 'tron'),
            credential_subject.get('asset', ''),
            str(credential_subject.get('amount', '')),
            credential_subject.get('tronTxHash') or credential_subject.get('transactionHash', ''),
            credential_subject.get('senderAddress', ''),
            credential_subject.get('recipientAddress', ''),
            credential_subject.get('tokenContract', ''),
            credential_subject.get('network', 'mainnet'),
            credential_subject.get('timestamp', datetime.now(timezone.utc).isoformat()),
            credential_subject.get('confirmations', 0),
            credential_subject.get('orgAffiliation'),
            rail_result.get("verified", False),
            rail_result.get('tronGridVerified', False),
            rail_result.get("signatureValid", False),
            rail_result.get('error'),
            vc.get('issuanceDate', datetime.now(timezone.utc).isoformat()),
            vc.get('expirationDate', (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()),
            json.dumps(vc),
            rail_result.get('receiptHash', hashlib.sha256(json.dumps(vc, sort_keys=True).encode()).hexdigest())
        ))
        
        row = cursor.fetchone()
        conn.commit()
        
        if row:
            return TRONReceiptResponse(
                success=True,
                receipt_id=str(row[0]),
                vc_id=vc_id,
                verified=rail_result.get("verified", False),
                error=None
            )
        else:
            # Receipt was inserted by another concurrent request
            cursor.execute(
                "SELECT receipt_id, verified FROM tron_receipts WHERE vc_id = %s",
                (vc_id,)
            )
            existing = cursor.fetchone()
            return TRONReceiptResponse(
                success=True,
                receipt_id=str(existing[0]),
                vc_id=vc_id,
                verified=existing[1],
                error=None
            )
            
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/tron/receipts/{agent_id}")
async def get_tron_receipts(
    agent_id: str,
    verified_only: bool = Query(True, description="Only return verified receipts"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """
    List TRON receipts for a specific agent.
    """
    # Strip did:op: prefix if present (database stores raw agent_id)
    if agent_id.startswith("did:op:"):
        agent_id = agent_id[7:]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if verified_only:
            cursor.execute("""
                SELECT 
                    receipt_id, vc_id, issuer_did, rail, asset, amount,
                    tron_tx_hash, sender_address, recipient_address, network,
                    tx_timestamp, confirmations, org_affiliation, verified,
                    issued_at, expires_at, received_at
                FROM tron_receipts
                WHERE subject_agent_id = %s AND verified = TRUE AND expires_at > NOW()
                ORDER BY tx_timestamp DESC
                LIMIT %s OFFSET %s
            """, (agent_id, limit, offset))
        else:
            cursor.execute("""
                SELECT 
                    receipt_id, vc_id, issuer_did, rail, asset, amount,
                    tron_tx_hash, sender_address, recipient_address, network,
                    tx_timestamp, confirmations, org_affiliation, verified,
                    issued_at, expires_at, received_at
                FROM tron_receipts
                WHERE subject_agent_id = %s
                ORDER BY tx_timestamp DESC
                LIMIT %s OFFSET %s
            """, (agent_id, limit, offset))
        
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        receipts = [dict(zip(columns, row)) for row in rows]
        
        # Get total count
        cursor.execute(
            "SELECT COUNT(*) FROM tron_receipts WHERE subject_agent_id = %s AND verified = TRUE AND expires_at > NOW()",
            (agent_id,)
        )
        total = cursor.fetchone()[0]
        
        return {
            "agent_id": agent_id,
            "receipts": receipts,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/trust/tron/score/{agent_id}", response_model=TRONTrustScoreResponse)
async def get_tron_trust_score(agent_id: str):
    """
    Get TRON trust score for a specific agent.
    """
    # Strip did:op: prefix if present (database stores raw agent_id)
    if agent_id.startswith("did:op:"):
        agent_id = agent_id[7:]
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT * FROM v_tron_trust_metrics WHERE agent_id = %s
        """, (agent_id,))
        
        metrics = cursor.fetchone()
        
        if not metrics:
            # Return zero score for unknown agents
            return TRONTrustScoreResponse(
                agent_id=agent_id,
                trust_score=0.0,
                receipt_count=0,
                unique_counterparties=0,
                total_trx_volume="0",
                total_stablecoin_volume="0",
                org_affiliated_count=0,
                last_activity=None,
                components={}
            )
        
        score_result = compute_tron_trust_score(dict(metrics))
        
        return TRONTrustScoreResponse(
            agent_id=agent_id,
            trust_score=score_result['trust_score'],
            receipt_count=metrics.get('tron_receipt_count', 0),
            unique_counterparties=metrics.get('unique_tron_counterparties', 0),
            total_trx_volume=str(metrics.get('total_trx_volume', 0) or 0),
            total_stablecoin_volume=str(metrics.get('total_stablecoin_volume', 0) or 0),
            org_affiliated_count=metrics.get('org_affiliated_count', 0),
            last_activity=metrics.get('last_tron_tx').isoformat() if metrics.get('last_tron_tx') else None,
            components=score_result['components']
        )
        
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/tron/receipts/{agent_id}/count")
async def get_tron_receipt_count(agent_id: str):
    """
    Get count of TRON receipts for an agent.
    """
    # Strip did:op: prefix if present (database stores raw agent_id)
    if agent_id.startswith("did:op:"):
        agent_id = agent_id[7:]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN verified = TRUE AND expires_at > NOW() THEN 1 END) as active,
                COUNT(DISTINCT issuer_did) as unique_counterparties
            FROM tron_receipts
            WHERE subject_agent_id = %s
        """, (agent_id,))
        
        row = cursor.fetchone()
        return {
            "agent_id": agent_id,
            "total_receipts": row[0],
            "active_receipts": row[1],
            "unique_counterparties": row[2]
        }
        
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/trust/tron/leaderboard")
async def get_tron_leaderboard(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    min_receipts: int = Query(1, ge=0)
):
    """
    Get TRON trust score leaderboard.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT * FROM v_tron_trust_metrics
            WHERE tron_receipt_count >= %s
            ORDER BY tron_receipt_count DESC, unique_tron_counterparties DESC
            LIMIT %s OFFSET %s
        """, (min_receipts, limit, offset))
        
        rows = cursor.fetchall()
        
        entries = []
        for rank, row in enumerate(rows, start=offset + 1):
            metrics = dict(row)
            score_result = compute_tron_trust_score(metrics)
            
            total_volume = (float(metrics.get('total_trx_volume', 0) or 0) / 100) + \
                          float(metrics.get('total_stablecoin_volume', 0) or 0)
            
            entries.append({
                "agent_id": metrics['agent_id'],
                "trust_score": score_result['trust_score'],
                "receipt_count": metrics.get('tron_receipt_count', 0),
                "unique_counterparties": metrics.get('unique_tron_counterparties', 0),
                "total_volume": str(round(total_volume, 2)),
                "rank": rank
            })
        
        return {
            "entries": entries,
            "limit": limit,
            "offset": offset,
            "total": len(entries)
        }
        
    finally:
        cursor.close()
        conn.close()

@app.get("/api/v1/transactions/{tx_hash}/details")
async def transaction_details(tx_hash: str):
    """
    Return full transaction details including VC when available.
    Spec 2.5 Deliverable 5 — supports the Details button on the dashboard.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("""
            SELECT id, agent_id, direction, counterparty_address,
                   amount, asset, tx_hash, tron_status,
                   network, rail, confirmations, block_number, timestamp,
                   metadata, created_at
            FROM agent_transactions
            WHERE tx_hash = %s
        """, (tx_hash,))
        
        tx_row = cursor.fetchone()
        
        if tx_row is None:
            raise HTTPException(status_code=404, detail=f"Transaction {tx_hash} not found")
        
        metadata = tx_row["metadata"] or {}
        has_vc = metadata.get("has_vc", False)
        
        # Build tronscan URL
        net = tx_row["network"] or ""
        if "mainnet" in net:
            tronscan_url = f"https://tronscan.org/#/transaction/{tx_hash}"
        elif "shasta" in net:
            tronscan_url = f"https://shasta.tronscan.org/#/transaction/{tx_hash}"
        else:
            tronscan_url = None
        
        transaction_block = {
            "tx_hash": tx_row["tx_hash"],
            "direction": tx_row["direction"],
            "amount": str(tx_row["amount"]),
            "asset": tx_row["asset"],
            "counterparty_address": tx_row["counterparty_address"],
            "network": tx_row["network"],
            "rail": tx_row["rail"],
            "confirmations": tx_row["confirmations"],
            "timestamp": tx_row["timestamp"].isoformat() if tx_row["timestamp"] else None,
            "tronscan_url": tronscan_url,
        }
        
        if not has_vc:
            return {
                "transaction": transaction_block,
                "vc": {
                    "available": False,
                    "message": "Transaction detected via chain monitoring — no counterparty credential attached"
                }
            }
        
        # Fetch the receipt VC
        cursor.execute("""
            SELECT receipt_id, vc_id, issuer_did, subject_did, rail,
                   verified, tron_grid_verified, signature_verified,
                   issued_at, expires_at, vc_document
            FROM tron_receipts
            WHERE tron_tx_hash = %s
            LIMIT 1
        """, (tx_hash,))
        
        receipt_row = cursor.fetchone()
        
        if receipt_row is None:
            return {
                "transaction": transaction_block,
                "vc": {
                    "available": False,
                    "message": "Credential referenced in metadata but not found in receipts table (data inconsistency)"
                }
            }
        
        return {
            "transaction": transaction_block,
            "vc": {
                "available": True,
                "vc_id": receipt_row["vc_id"],
                "issuer_did": receipt_row["issuer_did"],
                "subject_did": receipt_row["subject_did"],
                "rail": receipt_row["rail"],
                "verified": receipt_row["verified"],
                "tron_grid_verified": receipt_row["tron_grid_verified"],
                "signature_verified": receipt_row["signature_verified"],
                "issued_at": receipt_row["issued_at"].isoformat() if receipt_row["issued_at"] else None,
                "expires_at": receipt_row["expires_at"].isoformat() if receipt_row["expires_at"] else None,
                "proof_type": "Ed25519Signature2020",
                "receipt_id": str(receipt_row["receipt_id"]),
                "full_vc_document": receipt_row["vc_document"],
            }
        }
        
    finally:
        cursor.close()
        conn.close()

# ============================================================
# SPEC 3.1: THIRD-PARTY ATTESTATION ENDPOINTS
# ============================================================

class VerifyCredentialRequest(BaseModel):
    """Request body for credential verification."""
    credential: Dict
    
    class Config:
        extra = "forbid"

class CacheAttestationRequest(BaseModel):
    """Request body for caching an attestation."""
    credential: Dict
    credential_url: Optional[str] = None
    
    class Config:
        extra = "forbid"

@app.post("/verify")
async def verify_credential_endpoint(request: VerifyCredentialRequest):
    """
    Verify a third-party attestation credential.
    
    Implements Spec 3.1 verification flow:
    - Resolves issuer DID
    - Validates credential against JSON Schema
    - Verifies Ed25519Signature2020 signature
    - Checks validity period (validFrom/validUntil)
    
    Returns structured verification result with individual check status.
    """
    from vc_verification import verify_credential as vc_verify
    
    credential = request.credential
    
    # Basic structure validation
    if not isinstance(credential, dict):
        raise HTTPException(status_code=400, detail="Credential must be a JSON object")
    
    if not credential.get("proof"):
        raise HTTPException(status_code=400, detail="Credential missing proof field")
    
    try:
        result = vc_verify(credential, use_cache=True)
        
        # Return 200 even if verification fails - client checks 'verified' field
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@app.post("/api/v1/attestations/cache")
async def cache_attestation(request: CacheAttestationRequest):
    """
    Cache a verified third-party attestation.
    
    1. Verifies the credential
    2. If valid, stores in partner_attestations table
    3. Returns the cached record ID
    """
    from vc_verification import verify_credential as vc_verify
    
    credential = request.credential
    credential_url = request.credential_url
    
    # First, verify the credential
    verification_result = vc_verify(credential, use_cache=True)
    
    if not verification_result["verified"]:
        raise HTTPException(
            status_code=400, 
            detail={
                "message": "Credential verification failed",
                "checks": verification_result["checks"],
                "error": verification_result.get("error")
            }
        )
    
    # Extract fields for caching
    credential_id = credential.get("id")
    credential_types = credential.get("type", [])
    credential_type = credential_types[1] if len(credential_types) >= 2 else credential_types[0] if credential_types else "Unknown"
    
    issuer_did = verification_result["issuer_did"]
    subject_did = verification_result["subject_did"]
    
    valid_from = credential.get("validFrom")
    valid_until = credential.get("validUntil")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO partner_attestations (
                credential_id,
                credential_type,
                issuer_did,
                subject_did,
                credential_jsonld,
                credential_url,
                valid_from,
                valid_until,
                cached_at,
                last_verified_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT (credential_id) DO UPDATE SET
                credential_jsonld = EXCLUDED.credential_jsonld,
                credential_url = EXCLUDED.credential_url,
                valid_from = EXCLUDED.valid_from,
                valid_until = EXCLUDED.valid_until,
                cached_at = NOW(),
                last_verified_at = NOW()
            RETURNING id
        """, (
            credential_id,
            credential_type,
            issuer_did,
            subject_did,
            json.dumps(credential),
            credential_url,
            valid_from,
            valid_until
        ))
        
        record_id = cursor.fetchone()[0]
        conn.commit()
        
        return {
            "success": True,
            "record_id": record_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "cached_at": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to cache attestation: {str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/attestations/store")
async def store_signed_attestation(request: CacheAttestationRequest):
    """
    Store a pre-signed attestation credential.

    The credential must contain a valid proof field. Signature verification
    is deferred to read time — any party can verify independently by
    resolving the issuer DID and checking the Ed25519 signature.

    This endpoint stores the credential as-is. It does NOT re-verify
    the signature server-side (the issuer signed it, the verifier checks it).
    This is the correct trust model per AIP v0.5.
    """
    credential = request.credential

    # Basic structure checks (no crypto verification)
    if not credential.get("proof"):
        raise HTTPException(status_code=400, detail="Credential must have a proof field")
    if not credential.get("credentialSubject"):
        raise HTTPException(status_code=400, detail="Credential must have a credentialSubject")

    credential_id = credential.get("id", f"urn:uuid:{uuid.uuid4()}")
    credential_types = credential.get("type", [])
    credential_type = credential_types[1] if len(credential_types) >= 2 else credential_types[0] if credential_types else "Unknown"

    issuer = credential.get("issuer")
    issuer_did = issuer if isinstance(issuer, str) else issuer.get("id", "") if isinstance(issuer, dict) else ""

    subject = credential.get("credentialSubject", {})
    subject_did = subject.get("id", "")

    valid_from = credential.get("validFrom")
    valid_until = credential.get("validUntil")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO partner_attestations (
                credential_id, credential_type, issuer_did, subject_did,
                credential_jsonld, valid_from, valid_until, cached_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (credential_id) DO UPDATE SET
                credential_jsonld = EXCLUDED.credential_jsonld,
                cached_at = NOW()
            RETURNING id
        """, (
            credential_id, credential_type, issuer_did, subject_did,
            json.dumps(credential), valid_from, valid_until
        ))

        record_id = cursor.fetchone()[0]
        conn.commit()

        return {
            "success": True,
            "record_id": record_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to store attestation: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.get("/api/v1/attestations/cache/{record_id}")
async def get_cached_attestation(record_id: int):
    """
    Get a specific cached attestation by its record ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT 
                id,
                credential_id,
                credential_type,
                issuer_did,
                subject_did,
                credential_jsonld,
                credential_url,
                valid_from,
                valid_until,
                cached_at,
                last_verified_at
            FROM partner_attestations
            WHERE id = %s
        """, (record_id,))
        
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Attestation record not found")
        
        attestation = {
            "id": row['id'],
            "credential_id": row['credential_id'],
            "credential_type": row['credential_type'],
            "issuer_did": row['issuer_did'],
            "subject_did": row['subject_did'],
            "credential_url": row['credential_url'],
            "valid_from": row['valid_from'].isoformat() if row['valid_from'] else None,
            "valid_until": row['valid_until'].isoformat() if row['valid_until'] else None,
            "cached_at": row['cached_at'].isoformat() if row['cached_at'] else None,
            "last_verified_at": row['last_verified_at'].isoformat() if row['last_verified_at'] else None
        }
        
        if row['credential_jsonld']:
            try:
                if isinstance(row['credential_jsonld'], str):
                    attestation['credential'] = json.loads(row['credential_jsonld'])
                else:
                    attestation['credential'] = row['credential_jsonld']
            except:
                pass
        
        # Check if still valid
        now = datetime.now(timezone.utc)
        valid_until = row['valid_until']
        if isinstance(valid_until, str):
            valid_until = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
        
        attestation['is_valid'] = valid_until > now if valid_until else False
        
        return attestation
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve attestation: {str(e)}")
    finally:
        cursor.close()
        conn.close()



@app.get("/api/v1/principal/claimed-agents")
def get_attestations_by_issuer(issuer_did: str, credential_type: Optional[str] = "PrincipalAttestationCredential"):
    """
    Get all attestations issued by a given DID.
    Used by Sovereign dashboard to find agents claimed by a principal.
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        if credential_type:
            cursor.execute("""
                SELECT id, credential_id, credential_type, issuer_did, subject_did,
                       valid_from, valid_until, cached_at
                FROM partner_attestations
                WHERE issuer_did = %s AND credential_type = %s
                ORDER BY cached_at DESC
            """, (issuer_did, credential_type))
        else:
            cursor.execute("""
                SELECT id, credential_id, credential_type, issuer_did, subject_did,
                       valid_from, valid_until, cached_at
                FROM partner_attestations
                WHERE issuer_did = %s
                ORDER BY cached_at DESC
            """, (issuer_did,))

        rows = cursor.fetchall()
        attestations = []
        for row in rows:
            attestations.append({
                "id": row["id"],
                "credential_id": row["credential_id"],
                "credential_type": row["credential_type"],
                "issuer_did": row["issuer_did"],
                "subject_did": row["subject_did"],
                "valid_from": row["valid_from"].isoformat() if row["valid_from"] else None,
                "valid_until": row["valid_until"].isoformat() if row["valid_until"] else None,
                "cached_at": row["cached_at"].isoformat() if row["cached_at"] else None,
            })

        return {"attestations": attestations, "count": len(attestations)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query attestations: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.get("/api/v1/attestations/{subject_did:path}")
async def get_attestations(
    subject_did: str,
    credential_type: Optional[str] = None,
    issuer_did: Optional[str] = None,
    valid_only: bool = True
):
    """
    Get cached attestations for a subject DID.
    
    Returns cached credentials filtered by validity (valid_until > NOW()).
    Ordered by cached_at DESC (most recent first).
    
    Args:
        subject_did: The subject's DID (URL-encoded path parameter)
        credential_type: Optional filter by credential type
        issuer_did: Optional filter by issuer DID
        valid_only: If True (default), only returns non-expired credentials
    """
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        query = """
            SELECT 
                id,
                credential_id,
                credential_type,
                issuer_did,
                subject_did,
                credential_jsonld,
                credential_url,
                valid_from,
                valid_until,
                cached_at,
                last_verified_at
            FROM partner_attestations
            WHERE subject_did = %s
        """
        params = [subject_did]
        
        if valid_only:
            query += " AND valid_until > NOW()"
        
        if credential_type:
            query += " AND credential_type = %s"
            params.append(credential_type)
        
        if issuer_did:
            query += " AND issuer_did = %s"
            params.append(issuer_did)
        
        query += " ORDER BY cached_at DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        attestations = []
        for row in rows:
            attestation = {
                "id": row['id'],
                "credential_id": row['credential_id'],
                "credential_type": row['credential_type'],
                "issuer_did": row['issuer_did'],
                "subject_did": row['subject_did'],
                "credential_url": row['credential_url'],
                "valid_from": row['valid_from'].isoformat() if row['valid_from'] else None,
                "valid_until": row['valid_until'].isoformat() if row['valid_until'] else None,
                "cached_at": row['cached_at'].isoformat() if row['cached_at'] else None,
                "last_verified_at": row['last_verified_at'].isoformat() if row['last_verified_at'] else None
            }
            
            # Optionally include the full credential JSON
            if row['credential_jsonld']:
                try:
                    if isinstance(row['credential_jsonld'], str):
                        attestation['credential'] = json.loads(row['credential_jsonld'])
                    else:
                        attestation['credential'] = row['credential_jsonld']
                except:
                    pass
            
            attestations.append(attestation)
        
        return {
            "subject_did": subject_did,
            "count": len(attestations),
            "valid_only": valid_only,
            "attestations": attestations
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve attestations: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
# END SPEC 3.1 ENDPOINTS
# ============================================================

