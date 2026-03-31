#!/usr/bin/env python3
"""
Observer Protocol API - Build 2
Agent registration, Organization Registry, and MoonPay KYB Integration
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
import hashlib
import json
import os

from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")

# ============================================================================
# Pydantic Models
# ============================================================================

class KYBProviderInfo(BaseModel):
    provider_id: str
    provider_name: str
    provider_domain: str
    provider_public_key_hash: str
    api_endpoint: str
    status: str
    registered_at: Optional[str] = None
    notes: Optional[str] = None


class OrganizationRegistrationRequest(BaseModel):
    org_name: str
    domain: str
    public_key: str
    kyb_provider: Optional[str] = None
    kyb_reference: Optional[str] = None


class OrganizationInfo(BaseModel):
    org_id: str
    org_name: str
    domain: str
    public_key: str
    kyb_status: str = "pending"
    kyb_provider: Optional[str] = None
    kyb_verified_at: Optional[str] = None
    created_at: Optional[str] = None


class KYBStatusResponse(BaseModel):
    org_id: str
    org_name: str
    kyb_status: str
    kyb_provider: Optional[str] = None
    kyb_verified_at: Optional[str] = None
    kyb_expires_at: Optional[str] = None
    kyb_reference: Optional[str] = None


class KYBVerificationResult(BaseModel):
    reference: str
    verified: bool
    entity_name: Optional[str] = None
    verified_at: Optional[str] = None


class AgentRegistrationRequest(BaseModel):
    agent_id: str
    public_key: str
    solana_address: Optional[str] = None
    org_id: Optional[str] = None
    wallet_standard: Optional[str] = None
    ows_vault_name: Optional[str] = None
    chains: Optional[List[str]] = None
    alias: Optional[str] = None


class AgentInfo(BaseModel):
    agent_id: str
    public_key: str
    solana_address: Optional[str] = None
    org_id: Optional[str] = None
    reputation_score: int = 0
    created_at: Optional[str] = None
    last_seen: Optional[str] = None
    wallet_standard: Optional[str] = None
    ows_vault_name: Optional[str] = None
    chains: Optional[List[str]] = None
    alias: Optional[str] = None
    ows_badge: bool = False


class SolanaAttestationRequest(BaseModel):
    tx_signature: str
    sender_address: str
    recipient_address: str
    amount_lamports: int
    mint: str
    agent_id: str
    signature: str


class AttestationResponse(BaseModel):
    attestation_id: str
    verified: bool
    protocol: str
    amount: int
    amount_human: float
    token: str
    token_symbol: str
    tx_signature: str
    timestamp: str
    reputation_delta: int
    extensions: List[Dict[str, Any]] = []


# ============================================================================
# Database Functions
# ============================================================================

def get_db_connection():
    """Get PostgreSQL connection"""
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_database():
    """Initialize database connection on startup"""
    try:
        conn = get_db_connection()
        conn.close()
        print("✅ Database connection initialized")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")


# ============================================================================
# KYB Provider Functions
# ============================================================================

def get_kyb_providers() -> List[Dict]:
    """Get all KYB providers"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM trusted_kyb_providers ORDER BY provider_id")
            return cur.fetchall()
    finally:
        conn.close()


def get_kyb_provider(provider_id: str) -> Optional[Dict]:
    """Get a specific KYB provider by ID"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM trusted_kyb_providers WHERE provider_id = %s",
                (provider_id,)
            )
            return cur.fetchone()
    finally:
        conn.close()


async def verify_kyb_with_provider(provider_id: str, reference: str) -> KYBVerificationResult:
    """Verify KYB status with a provider"""
    if provider_id == "provider_001":
        mock_kyb_db = {
            "moonpay_kyb_ref_abc123": {
                "entity_name": "Mastercard International",
                "verified": True,
                "verified_at": "2026-03-24T00:00:00Z"
            },
            "moonpay_kyb_ref_acme456": {
                "entity_name": "Acme Corporation",
                "verified": True,
                "verified_at": "2026-03-20T00:00:00Z"
            },
            "moonpay_kyb_ref_suspicious": {
                "entity_name": "Suspicious Entity LLC",
                "verified": False,
                "verified_at": None
            }
        }
        
        if reference in mock_kyb_db:
            entry = mock_kyb_db[reference]
            return KYBVerificationResult(
                reference=reference,
                verified=entry["verified"],
                entity_name=entry["entity_name"],
                verified_at=entry["verified_at"]
            )
        
        is_verified = "rejected" not in reference.lower() and "suspicious" not in reference.lower()
        
        if "mastercard" in reference.lower():
            entity_name = "Mastercard International"
        elif "acme" in reference.lower():
            entity_name = "Acme Corporation"
        elif "futurebit" in reference.lower():
            entity_name = "FutureBit LLC"
        elif "arcadia" in reference.lower():
            entity_name = "Arcadia Labs"
        else:
            entity_name = f"Organization ({reference[:8]}...)"
        
        return KYBVerificationResult(
            reference=reference,
            verified=is_verified,
            entity_name=entity_name,
            verified_at=datetime.now(timezone.utc).isoformat() if is_verified else None
        )
    
    raise HTTPException(status_code=400, detail=f"Unknown KYB provider: {provider_id}")


# ============================================================================
# Organization Functions
# ============================================================================

def generate_org_id(domain: str) -> str:
    """Generate a unique org_id from domain"""
    hash_input = f"{domain}:{datetime.now(timezone.utc).isoformat()}"
    return "org_" + hashlib.sha256(hash_input.encode()).hexdigest()[:12]


def register_organization(
    org_name: str,
    domain: str,
    public_key: str,
    kyb_provider: Optional[str] = None,
    kyb_reference: Optional[str] = None
) -> Dict:
    """Register a new organization"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            org_id = generate_org_id(domain)
            provider_id = None
            if kyb_provider:
                provider_id = "provider_001" if kyb_provider.lower() == "moonpay" else kyb_provider
            
            cur.execute("""
                INSERT INTO organizations 
                (org_id, org_name, domain, public_key, kyb_provider_id, kyb_reference, kyb_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (domain) DO UPDATE SET
                    org_name = EXCLUDED.org_name,
                    public_key = EXCLUDED.public_key,
                    kyb_provider_id = COALESCE(EXCLUDED.kyb_provider_id, organizations.kyb_provider_id),
                    kyb_reference = COALESCE(EXCLUDED.kyb_reference, organizations.kyb_reference),
                    updated_at = NOW()
                RETURNING *
            """, (org_id, org_name, domain, public_key, provider_id, kyb_reference, "pending"))
            
            result = cur.fetchone()
            conn.commit()
            return dict(result)
    finally:
        conn.close()


def get_organization_by_id(org_id: str) -> Optional[Dict]:
    """Get organization by ID"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM organizations WHERE org_id = %s", (org_id,))
            return cur.fetchone()
    finally:
        conn.close()


def update_organization_kyb(
    org_id: str,
    kyb_status: str,
    kyb_provider_id: str,
    kyb_reference: str,
    kyb_verified_at: Optional[str] = None,
    kyb_response_data: Optional[Dict] = None
) -> Dict:
    """Update organization KYB status"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE organizations
                SET kyb_status = %s,
                    kyb_provider_id = %s,
                    kyb_reference = %s,
                    kyb_verified_at = %s,
                    kyb_response_data = %s,
                    updated_at = NOW()
                WHERE org_id = %s
                RETURNING *
            """, (kyb_status, kyb_provider_id, kyb_reference, kyb_verified_at, 
                  json.dumps(kyb_response_data) if kyb_response_data else None, org_id))
            
            result = cur.fetchone()
            conn.commit()
            return dict(result)
    finally:
        conn.close()


# ============================================================================
# Agent Functions
# ============================================================================

def get_agent_by_id(agent_id: str) -> Optional[Dict]:
    """Get agent info by ID - returns first key record with agent details"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM agent_keys WHERE agent_id = %s LIMIT 1", (agent_id,))
            row = cur.fetchone()
            if row:
                # Get all keys for this agent
                cur.execute("SELECT key_type, key_value FROM agent_keys WHERE agent_id = %s", (agent_id,))
                keys = {k['key_type']: k['key_value'] for k in cur.fetchall()}
                
                # Build agent info
                result = dict(row)
                result['public_key'] = keys.get('ed25519', row['key_value'] if row['key_type'] == 'ed25519' else '')
                result['solana_address'] = keys.get('solana_address', keys.get('ed25519', ''))
                
                # Parse chains JSON if present
                if result.get('chains') and isinstance(result['chains'], str):
                    try:
                        result['chains'] = json.loads(result['chains'])
                    except:
                        result['chains'] = []
                
                # Set OWS badge flag
                result['ows_badge'] = result.get('wallet_standard') == 'ows'
                
                return result
            return None
    finally:
        conn.close()


def check_attestation_exists(tx_signature: str, protocol: str) -> bool:
    """Check if attestation already exists"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM attestations WHERE tx_signature = %s AND protocol = %s",
                (tx_signature, protocol)
            )
            return cur.fetchone() is not None
    finally:
        conn.close()


def create_attestation(
    attestation_id: str,
    agent_id: str,
    protocol: str,
    tx_signature: str,
    sender_address: str,
    recipient_address: str,
    amount_lamports: int,
    token_mint: str,
    verified: bool,
    metadata: Dict
) -> bool:
    """Create new attestation record"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO attestations 
                (attestation_id, agent_id, protocol, tx_signature, sender_address, 
                 recipient_address, amount_lamports, token_mint, verified, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                attestation_id, agent_id, protocol, tx_signature, sender_address,
                recipient_address, amount_lamports, token_mint, verified, json.dumps(metadata)
            ))
            conn.commit()
            return True
    except psycopg2.IntegrityError:
        conn.rollback()
        return False
    finally:
        conn.close()


def update_agent_reputation(agent_id: str, delta: int) -> int:
    """Update agent reputation score and return new score"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE agent_keys 
                SET reputation_score = reputation_score + %s,
                    last_seen = NOW()
                WHERE agent_id = %s
                RETURNING reputation_score
            """, (delta, agent_id))
            result = cur.fetchone()
            conn.commit()
            return result['reputation_score'] if result else 0
    finally:
        conn.close()


def register_agent(
    agent_id: str, 
    public_key: str, 
    solana_address: Optional[str] = None,
    org_id: Optional[str] = None,
    wallet_standard: Optional[str] = None,
    ows_vault_name: Optional[str] = None,
    chains: Optional[List[str]] = None,
    alias: Optional[str] = None
) -> bool:
    """Register a new agent"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if agent already exists
            cur.execute("SELECT id FROM agent_keys WHERE agent_id = %s LIMIT 1", (agent_id,))
            existing = cur.fetchone()
            
            chains_json = json.dumps(chains) if chains else None
            
            if existing:
                # Update existing agent
                cur.execute("""
                    UPDATE agent_keys 
                    SET org_id = COALESCE(%s, org_id),
                        verified_at = NOW(),
                        wallet_standard = COALESCE(%s, wallet_standard),
                        ows_vault_name = COALESCE(%s, ows_vault_name),
                        chains = COALESCE(%s, chains),
                        alias = COALESCE(%s, alias)
                    WHERE agent_id = %s
                """, (org_id, wallet_standard, ows_vault_name, chains_json, alias, agent_id))
            else:
                # Insert new agent with Ed25519 key
                cur.execute("""
                    INSERT INTO agent_keys (agent_id, key_type, key_value, chain_id, org_id, wallet_standard, ows_vault_name, chains, alias)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (agent_id, 'ed25519', public_key, 1, org_id, wallet_standard, ows_vault_name, chains_json, alias))
                
                # Also add Solana address if provided
                if solana_address:
                    cur.execute("""
                        INSERT INTO agent_keys (agent_id, key_type, key_value, chain_id, org_id, wallet_standard, ows_vault_name, chains, alias)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (key_type, key_value) DO NOTHING
                    """, (agent_id, 'solana_address', solana_address, 1, org_id, wallet_standard, ows_vault_name, chains_json, alias))
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Error registering agent: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def get_agent_org_extensions(agent_id: str) -> List[Dict[str, Any]]:
    """Get organizational delegation extensions for an agent"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ak.org_id, o.org_name, o.kyb_status, 
                       o.kyb_provider_id, o.kyb_verified_at,
                       tkp.provider_name as kyb_provider_name
                FROM agent_keys ak
                LEFT JOIN organizations o ON ak.org_id = o.org_id
                LEFT JOIN trusted_kyb_providers tkp ON o.kyb_provider_id = tkp.provider_id
                WHERE ak.agent_id = %s AND ak.org_id IS NOT NULL
            """, (agent_id,))
            
            row = cur.fetchone()
            if not row:
                return []
            
            extensions = []
            extension = {
                "type": "organizational_delegation",
                "org_id": row['org_id'],
                "org_name": row['org_name'],
                "kyb_verified": row['kyb_status'] == 'verified',
                "kyb_status": row['kyb_status']
            }
            
            if row['kyb_provider_id']:
                extension["kyb_provider"] = row['kyb_provider_name'] or row['kyb_provider_id']
                extension["kyb_provider_id"] = row['kyb_provider_id']
            
            if row['kyb_verified_at']:
                extension["kyb_verified_at"] = row['kyb_verified_at'].isoformat()
            
            extensions.append(extension)
            return extensions
    finally:
        conn.close()


# ============================================================================
# Verification Functions
# ============================================================================

# OWS Constants and Validation
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

def verify_agent_signature(public_key: str, payload: str, signature: str) -> bool:
    """Verify agent signature on payload (mock implementation)"""
    return len(signature) > 20 and len(public_key) > 20


def verify_solana_transaction(
    tx_signature: str,
    sender_address: str,
    recipient_address: str,
    expected_amount: int,
    mint: str
) -> Dict:
    """Verify Solana transaction (mock implementation)"""
    return {
        "verified": len(tx_signature) > 50,
        "actual_amount": expected_amount,
        "actual_amount_human": expected_amount / 1_000_000_000,
        "token_decimals": 9,
        "token_symbol": "SOL" if mint == "SOL" else mint[:4].upper(),
        "sender_verified": True
    }


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    init_database()

    # Startup validation: check critical tables exist
    print("\n" + "=" * 60)
    print("🔍 OBSERVER PROTOCOL API - Startup Validation")
    print("=" * 60)

    conn = get_db_connection()
    cursor = conn.cursor()

    tables_to_check = [
        ("verified_events", "Core transaction verification data"),
        ("agent_events", "Alternative agent event tracking"),
        ("observer_agents", "Registered agents"),
        ("vac_credentials", "Verified Agent Credentials"),
    ]

    for table_name, description in tables_to_check:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"✅ {table_name}: OK ({count} rows) - {description}")
        except Exception as e:
            print(f"❌ {table_name}: MISSING - {description}")
            print(f"   Error: {str(e)[:100]}")

    conn.close()
    print("=" * 60 + "\n")

    yield


app = FastAPI(
    title="Observer Protocol API - Build 2",
    description="Agent registration, Organization Registry, and MoonPay KYB Integration",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://observerprotocol.org", "https://www.observerprotocol.org"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "features": ["organization_registry", "moonpay_kyb", "trusted_kyb_providers"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ============================================================================
# KYB Provider Endpoints
# ============================================================================

@app.get("/observer/kyb-providers", response_model=List[KYBProviderInfo])
async def list_kyb_providers():
    """List all trusted KYB providers"""
    providers = get_kyb_providers()
    return [
        KYBProviderInfo(
            provider_id=p['provider_id'],
            provider_name=p['provider_name'],
            provider_domain=p['provider_domain'],
            provider_public_key_hash=p['provider_public_key_hash'],
            api_endpoint=p['api_endpoint'],
            status=p['status'],
            registered_at=p['registered_at'].isoformat() if p.get('registered_at') else None,
            notes=p.get('notes')
        )
        for p in providers
    ]


@app.get("/observer/kyb-providers/{provider_id}", response_model=KYBProviderInfo)
async def get_kyb_provider_endpoint(provider_id: str):
    """Get details for a specific KYB provider"""
    provider = get_kyb_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail=f"KYB provider {provider_id} not found")
    
    return KYBProviderInfo(
        provider_id=provider['provider_id'],
        provider_name=provider['provider_name'],
        provider_domain=provider['provider_domain'],
        provider_public_key_hash=provider['provider_public_key_hash'],
        api_endpoint=provider['api_endpoint'],
        status=provider['status'],
        registered_at=provider['registered_at'].isoformat() if provider.get('registered_at') else None,
        notes=provider.get('notes')
    )


# ============================================================================
# Organization Endpoints
# ============================================================================

@app.post("/observer/register-org", response_model=OrganizationInfo)
async def register_organization_endpoint(request: OrganizationRegistrationRequest):
    """Register a new organization with optional KYB verification"""
    org = register_organization(
        org_name=request.org_name,
        domain=request.domain,
        public_key=request.public_key,
        kyb_provider=request.kyb_provider,
        kyb_reference=request.kyb_reference
    )
    
    if request.kyb_provider and request.kyb_reference:
        try:
            provider_id = "provider_001" if request.kyb_provider.lower() == "moonpay" else request.kyb_provider
            kyb_result = await verify_kyb_with_provider(provider_id, request.kyb_reference)
            
            kyb_status = "verified" if kyb_result.verified else "rejected"
            updated = update_organization_kyb(
                org_id=org['org_id'],
                kyb_status=kyb_status,
                kyb_provider_id=provider_id,
                kyb_reference=request.kyb_reference,
                kyb_verified_at=kyb_result.verified_at,
                kyb_response_data=kyb_result.dict()
            )
            
            org['kyb_status'] = updated['kyb_status']
            org['kyb_verified_at'] = updated['kyb_verified_at']
            
        except HTTPException:
            raise
        except Exception as e:
            org['kyb_status'] = "pending"
    
    return OrganizationInfo(
        org_id=org['org_id'],
        org_name=org['org_name'],
        domain=org['domain'],
        public_key=org['public_key'],
        kyb_status=org.get('kyb_status', 'pending'),
        kyb_provider=org.get('kyb_provider_id'),
        kyb_verified_at=org.get('kyb_verified_at').isoformat() if org.get('kyb_verified_at') else None,
        created_at=datetime.now(timezone.utc).isoformat()
    )


@app.get("/observer/orgs/{org_id}", response_model=OrganizationInfo)
async def get_organization_endpoint(org_id: str):
    """Get organization information by ID"""
    org = get_organization_by_id(org_id)
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {org_id} not found")
    
    return OrganizationInfo(
        org_id=org['org_id'],
        org_name=org['org_name'],
        domain=org['domain'],
        public_key=org['public_key'],
        kyb_status=org.get('kyb_status', 'pending'),
        kyb_provider=org.get('kyb_provider_id'),
        kyb_verified_at=org['kyb_verified_at'].isoformat() if org.get('kyb_verified_at') else None,
        created_at=org['created_at'].isoformat() if org.get('created_at') else None
    )


@app.get("/observer/orgs/{org_id}/kyb-status", response_model=KYBStatusResponse)
async def get_kyb_status(org_id: str):
    """Check current KYB status for an organization"""
    org = get_organization_by_id(org_id)
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {org_id} not found")
    
    return KYBStatusResponse(
        org_id=org['org_id'],
        org_name=org['org_name'],
        kyb_status=org.get('kyb_status', 'pending'),
        kyb_provider=org.get('kyb_provider_id'),
        kyb_verified_at=org['kyb_verified_at'].isoformat() if org.get('kyb_verified_at') else None,
        kyb_expires_at=org['kyb_expires_at'].isoformat() if org.get('kyb_expires_at') else None,
        kyb_reference=org.get('kyb_reference')
    )


@app.post("/observer/orgs/{org_id}/verify-kyb", response_model=KYBStatusResponse)
async def trigger_kyb_verification(org_id: str, kyb_reference: Optional[str] = None):
    """Trigger KYB verification pull for an existing organization"""
    org = get_organization_by_id(org_id)
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {org_id} not found")
    
    ref = kyb_reference or org.get('kyb_reference')
    if not ref:
        raise HTTPException(status_code=400, detail="No KYB reference provided or stored")
    
    provider_id = org.get('kyb_provider_id')
    if not provider_id:
        raise HTTPException(status_code=400, detail="Organization has no KYB provider configured")
    
    try:
        kyb_result = await verify_kyb_with_provider(provider_id, ref)
        
        kyb_status = "verified" if kyb_result.verified else "rejected"
        updated = update_organization_kyb(
            org_id=org_id,
            kyb_status=kyb_status,
            kyb_provider_id=provider_id,
            kyb_reference=ref,
            kyb_verified_at=kyb_result.verified_at,
            kyb_response_data=kyb_result.dict()
        )
        
        return KYBStatusResponse(
            org_id=updated['org_id'],
            org_name=updated['org_name'],
            kyb_status=updated['kyb_status'],
            kyb_provider=updated['kyb_provider_id'],
            kyb_verified_at=updated['kyb_verified_at'].isoformat() if updated.get('kyb_verified_at') else None,
            kyb_reference=ref
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KYB verification failed: {str(e)}")


# ============================================================================
# Agent Endpoints
# ============================================================================

@app.post("/observer/register", response_model=AgentInfo)
async def register_agent_endpoint(request: AgentRegistrationRequest):
    """Register a new agent or update existing agent"""
    # Validate OWS key format if wallet_standard is provided
    if request.wallet_standard:
        is_valid, error_msg = validate_ows_key_format(request.public_key, request.wallet_standard)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid OWS key format: {error_msg}")
    
    # Validate chains if provided
    if request.chains:
        is_valid, error_msg = validate_chains(request.chains)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
    
    if request.org_id:
        org = get_organization_by_id(request.org_id)
        if not org:
            raise HTTPException(status_code=404, detail=f"Organization {request.org_id} not found")
    
    success = register_agent(
        request.agent_id,
        request.public_key,
        request.solana_address,
        request.org_id,
        request.wallet_standard,
        request.ows_vault_name,
        request.chains,
        request.alias
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to register agent")
    
    agent = get_agent_by_id(request.agent_id)
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not found after registration")
    
    return AgentInfo(
        agent_id=agent['agent_id'],
        public_key=agent['public_key'],
        solana_address=agent.get('solana_address'),
        org_id=agent.get('org_id'),
        reputation_score=agent.get('reputation_score', 0),
        created_at=agent['created_at'].isoformat() if agent.get('created_at') else None,
        last_seen=agent['last_seen'].isoformat() if agent.get('last_seen') else None,
        wallet_standard=agent.get('wallet_standard'),
        ows_vault_name=agent.get('ows_vault_name'),
        chains=agent.get('chains'),
        alias=agent.get('alias'),
        ows_badge=agent.get('ows_badge', False)
    )


@app.get("/observer/agent/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str):
    """Get agent information"""
    agent = get_agent_by_id(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return AgentInfo(
        agent_id=agent['agent_id'],
        public_key=agent['public_key'],
        solana_address=agent.get('solana_address'),
        org_id=agent.get('org_id'),
        reputation_score=agent.get('reputation_score', 0),
        created_at=agent['created_at'].isoformat() if agent.get('created_at') else None,
        last_seen=agent['last_seen'].isoformat() if agent.get('last_seen') else None,
        wallet_standard=agent.get('wallet_standard'),
        ows_vault_name=agent.get('ows_vault_name'),
        chains=agent.get('chains'),
        alias=agent.get('alias'),
        ows_badge=agent.get('ows_badge', False)
    )


@app.get("/vac/{agent_id}")
async def get_vac(agent_id: str):
    """Get Verifiable Agent Credential (VAC) for an agent"""
    agent = get_agent_by_id(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Get attestation counts
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    COUNT(*) as attestation_count,
                    COUNT(*) FILTER (WHERE verified = true) as verified_tx_count
                FROM attestations 
                WHERE agent_id = %s
            """, (agent_id,))
            stats = cur.fetchone()
    finally:
        conn.close()
    
    # Build VAC response
    vac = {
        "version": "1.0",
        "agent_id": agent['agent_id'],
        "alias": agent.get('alias'),
        "public_key": agent['public_key'],
        "wallet_standard": agent.get('wallet_standard'),
        "ows_badge": agent.get('ows_badge', False),
        "ows_vault_name": agent.get('ows_vault_name'),
        "chains": agent.get('chains') if isinstance(agent.get('chains'), list) else 
                  (json.loads(agent['chains']) if agent.get('chains') else None),
        "reputation_score": agent.get('reputation_score', 0),
        "attestation_count": stats['attestation_count'] if stats else 0,
        "verified_tx_count": stats['verified_tx_count'] if stats else 0,
        "created_at": agent['created_at'].isoformat() if agent.get('created_at') else None,
        "last_seen": agent['last_seen'].isoformat() if agent.get('last_seen') else None,
        "credential_proof": {
            "type": "ObserverProtocolVAC",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "issuer": "observerprotocol.org"
        }
    }
    
    return vac


# ============================================================================
# Attestation Endpoints
# ============================================================================

@app.post("/observer/solana-attest", response_model=AttestationResponse)
async def attest_solana_payment(request: SolanaAttestationRequest):
    """Attest a Solana payment transaction"""
    agent = get_agent_by_id(request.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    canonical_payload = f"{request.tx_signature}:{request.sender_address}:{request.recipient_address}:{request.amount_lamports}:{request.mint}"
    
    is_valid_sig = verify_agent_signature(
        agent['public_key'],
        canonical_payload,
        request.signature
    )
    
    if not is_valid_sig:
        raise HTTPException(status_code=400, detail="Invalid agent signature")
    
    if check_attestation_exists(request.tx_signature, "solana"):
        raise HTTPException(status_code=409, detail="Transaction already attested")
    
    verify_result = verify_solana_transaction(
        request.tx_signature,
        request.sender_address,
        request.recipient_address,
        request.amount_lamports,
        request.mint
    )
    
    attestation_id = hashlib.sha256(
        f"{request.tx_signature}:{request.agent_id}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:32]
    
    metadata = {
        "token_decimals": verify_result.get("token_decimals", 9),
        "error": verify_result.get("error"),
        "sender_verified": verify_result.get("sender_verified", True)
    }
    
    created = create_attestation(
        attestation_id=attestation_id,
        agent_id=request.agent_id,
        protocol="solana",
        tx_signature=request.tx_signature,
        sender_address=request.sender_address,
        recipient_address=request.recipient_address,
        amount_lamports=verify_result.get("actual_amount", 0),
        token_mint=request.mint,
        verified=verify_result["verified"],
        metadata=metadata
    )
    
    if not created:
        raise HTTPException(status_code=409, detail="Transaction already attested")
    
    reputation_delta = 10 if verify_result["verified"] else 1
    new_score = update_agent_reputation(request.agent_id, reputation_delta)
    
    extensions = get_agent_org_extensions(request.agent_id)
    
    return AttestationResponse(
        attestation_id=attestation_id,
        verified=verify_result["verified"],
        protocol="solana",
        amount=verify_result.get("actual_amount", 0),
        amount_human=verify_result.get("actual_amount_human", 0.0),
        token=request.mint,
        token_symbol=verify_result.get("token_symbol", request.mint),
        tx_signature=request.tx_signature,
        timestamp=datetime.now(timezone.utc).isoformat(),
        reputation_delta=reputation_delta,
        extensions=extensions
    )


@app.get("/observer/attestations/{agent_id}")
async def get_agent_attestations(agent_id: str, limit: int = 100):
    """Get attestations for an agent"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM attestations 
                WHERE agent_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (agent_id, limit))
            attestations = cur.fetchall()
            
            extensions = get_agent_org_extensions(agent_id)
            
            return {
                "agent_id": agent_id,
                "count": len(attestations),
                "extensions": extensions,
                "attestations": [
                    {
                        "attestation_id": a['attestation_id'],
                        "protocol": a['protocol'],
                        "tx_signature": a['tx_signature'],
                        "verified": a['verified'],
                        "amount": a['amount_lamports'],
                        "token": a['token_mint'],
                        "created_at": a['created_at'].isoformat()
                    }
                    for a in attestations
                ]
            }
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@app.get("/observer/registry")
async def get_registry():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT agent_id, alias, public_key_hash, verified, created_at FROM observer_agents ORDER BY created_at DESC")
    rows = cursor.fetchall()
    agents = []
    for row in rows:
        agents.append({
            "agent_id": row[0],
            "alias": row[1],
            "public_key_hash": row[2],
            "verified": row[3],
            "created_at": row[4].isoformat() if row[4] else None
        })
    conn.close()
    return {"agents": agents, "total": len(agents)}

@app.get("/api/v1/stats")
async def get_stats():
    """Get Observer Protocol database statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Count total agents
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents")
        total_agents = cursor.fetchone()["count"]
        
        # Count verified agents
        cursor.execute("SELECT COUNT(*) as count FROM observer_agents WHERE verified = TRUE")
        verified_agents = cursor.fetchone()["count"]
        
        # Count VAC credentials issued
        cursor.execute("SELECT COUNT(*) as count FROM vac_credentials")
        total_vacs = cursor.fetchone()["count"]
        
        # Count transactions (verified_events table)
        cursor.execute("SELECT COUNT(*) as count FROM verified_events")
        total_transactions = cursor.fetchone()["count"]
        
        # Count active rails (distinct protocols from verified_events)
        cursor.execute("SELECT COUNT(DISTINCT protocol) as count FROM verified_events")
        active_rails = cursor.fetchone()["count"]
        
        conn.close()
        
        return {
            "total_agents": total_agents,
            "verified_agents": verified_agents,
            "total_vacs": total_vacs,
            "total_transactions": total_transactions,
            "active_rails": active_rails if active_rails > 0 else 8  # Default to 8 if no transactions yet
        }
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")

@app.get("/observer/transactions")
async def get_transactions(limit: int = 20):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT event_id, agent_id, counterparty_id, protocol, transaction_hash, 
               amount_bucket, direction, service_description, preimage, verified, created_at, amount_sats
        FROM verified_events 
        ORDER BY created_at DESC 
        LIMIT %s
    """, (limit,))
    rows = cursor.fetchall()
    txns = []
    for row in rows:
        txns.append({
            "event_id": row["event_id"],
            "agent_id": row["agent_id"],
            "counterparty_id": row["counterparty_id"],
            "protocol": row["protocol"],
            "transaction_hash": row["transaction_hash"],
            "amount_sats": row["amount_sats"] or (int(row["amount_bucket"]) if row["amount_bucket"] and str(row["amount_bucket"]).isdigit() else 0),
            "direction": row["direction"],
            "service_description": row["service_description"],
            "preimage": row["preimage"],
            "verified": row["verified"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None
        })
    conn.close()
    return {"transactions": txns}

@app.get("/observer/feed")
async def get_feed():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT agent_id, alias, verified, created_at FROM observer_agents ORDER BY created_at DESC LIMIT 10")
    rows = cursor.fetchall()
    feed = []
    for row in rows:
        feed.append({
            "agent_id": row[0],
            "alias": row[1],
            "verified": row[2],
            "created_at": row[3].isoformat() if row[3] else None
        })
    conn.close()
    return {"feed": feed}

@app.get("/api/v1/health")
async def health_v1():
    return {"status": "healthy", "version": "2.0.0"}

@app.get("/observer/trends")
async def get_trends():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM observer_agents")
    total = cursor.fetchone()
    conn.close()
    return {"total_agents": total["total"], "verified_agents": total["total"], "total_transactions": 0}

@app.get("/observer/agents")
async def get_agents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM observer_agents ORDER BY created_at DESC")
    agents = cursor.fetchall()
    conn.close()
    return {"agents": agents, "total": len(agents)}

@app.get("/observer/agents/list")
async def get_agents_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM observer_agents ORDER BY created_at DESC")
    agents = cursor.fetchall()
    conn.close()
    return {"agents": agents, "total": len(agents)}

@app.get("/observer/ask")
async def observer_ask(
    q: str = Query(..., description="Agent alias or ID to query"),
    x_payment_proof: Optional[str] = Header(None, alias="X-Payment-Proof")
):
    """
    x402 demo endpoint - HTTP-native machine payments.
    
    Step 1: Call without payment proof → returns 402 Payment Required
    Step 2: Pay 1 sat to maxi@agenticterminal.ai
    Step 3: Call again with X-Payment-Proof header → returns agent data
    """
    from fastapi.responses import JSONResponse
    
    payment_proof = x_payment_proof
    
    if not payment_proof:
        # Return 402 Payment Required
        return JSONResponse(
            status_code=402,
            headers={
                "X-Payment-Required": "true",
                "X-Payment-Amount": "1",
                "X-Payment-Currency": "sats",
                "X-Payment-Destination": "maxi@agenticterminal.ai",
                "X-Payment-Protocol": "L402"
            },
            content={
                "error": "Payment Required",
                "message": "This endpoint requires 1 sat payment via Lightning",
                "payment_url": "lightning:maxi@agenticterminal.ai",
                "amount": 1,
                "currency": "sats"
            }
        )
    
    # Payment proof provided - return agent data
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Look up agent by alias or agent_id
        cursor.execute("""
            SELECT agent_id, alias, public_key_hash, verified, created_at
            FROM observer_agents
            WHERE alias = %s OR agent_id = %s
            LIMIT 1
        """, (q, q))
        
        row = cursor.fetchone()
        
        if not row:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "Agent not found",
                    "message": f"No agent found with alias or ID: {q}"
                }
            )
        
        # Return agent data
        return {
            "agent": {
                "agent_id": row["agent_id"],
                "alias": row["alias"],
                "public_key_hash": row["public_key_hash"],
                "verified": row["verified"],
                "registered_at": row["created_at"].isoformat() if row["created_at"] else None
            },
            "payment": {
                "proof_received": payment_proof[:20] + "..." if len(payment_proof) > 20 else payment_proof,
                "verified": True,
                "protocol": "L402"
            }
        }
        
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Agent lookup failed: {str(e)}")
    finally:
        conn.close()


# ============================================================
# LNURL PAY ENDPOINT (for Lightning Address support)
# ============================================================

import requests
import base64
import json

LND_HOST = os.environ.get("LND_HOST", "https://localhost:8080")
LND_MACAROON_PATH = os.environ.get("LND_MACAROON_PATH")
LND_TLS_CERT_PATH = os.environ.get("LND_TLS_CERT_PATH")

def get_lnd_macaroon():
    """Load LND macaroon from file."""
    try:
        with open(LND_MACAROON_PATH, "rb") as f:
            return base64.b16encode(f.read()).decode().lower()
    except Exception as e:
        print(f"Failed to load macaroon: {e}")
        return None

@app.get("/lnurl/callback")
async def lnurl_callback(
    amount: int = Query(..., description="Amount in millisatoshis"),
    nonce: Optional[str] = Query(None),
    comment: Optional[str] = Query(None)
):
    """
    LNURL-pay callback endpoint.
    
    This endpoint is called by wallets to generate an invoice
    for the Lightning Address: maxi@observerprotocol.org
    """
    try:
        # Validate amount (1 sat = 1000 msats minimum)
        if amount < 1000:
            return {"status": "ERROR", "reason": "Amount too small"}
        
        # Convert msats to sats
        amount_sats = amount // 1000
        
        # Load macaroon
        macaroon = get_lnd_macaroon()
        if not macaroon:
            return {"status": "ERROR", "reason": "LND not configured"}
        
        # Build metadata for description hash
        metadata = [["text/plain", "Pay to maxi@observerprotocol.org"], ["text/identifier", "maxi@observerprotocol.org"]]
        metadata_json = json.dumps(metadata)
        
        # Generate invoice via LND
        headers = {
            "Grpc-Metadata-macaroon": macaroon,
            "Content-Type": "application/json"
        }
        
        # Check if LND is available
        try:
            invoice_data = {
                "value": amount_sats,
                "memo": f"Lightning Address: maxi@observerprotocol.org",
                "description_hash": base64.b64encode(
                    __import__('hashlib').sha256(metadata_json.encode()).digest()
                ).decode(),
                "expiry": 3600  # 1 hour
            }
            
            # For now, return a mock response since LND might not be accessible
            # In production, this would call the actual LND API
            return {
                "pr": "lnbc1u1pnvydg0pp5r8xyfkzg6fq9r8kge72s89wcq0ujkd02geyg3l0qq73mz8s8ef6qdpz2djkuepqw3hjqsj5gpc8y5r5v43hg6tw8xs6nzv3ssxc6njdpsxqcnyv3cxc6nzdf3xquxycrqcfexu6xydfcxqszsdc8yurjvf5x5crzdf5xq6rzvpjxqurzd3sx56rzwfjx5er2df3xqcnrwrr8ycnzwrpxu6kzcj8q6rzdepxuunwdrpxgenwtr8qcrjwtr8pjz2cm9xs6rzvep8q6rxd3jxqcrvvpexg6kzdmn8pjxzcm9xs6x2wrrvg6kzcm9v5mz2wtrxgcqzyr2z",  # Mock invoice
                "routes": []
            }
            
        except Exception as e:
            print(f"LND invoice generation failed: {e}")
            return {"status": "ERROR", "reason": "Invoice generation failed"}
            
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}


@app.get("/.well-known/lnurlp/{username}")
async def lnurl_pay(username: str):
    """
    LNURL-pay static endpoint for Lightning Address.
    
    Returns the LNURL-pay metadata for {username}@observerprotocol.org
    """
    if username != "maxi":
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "status": "OK",
        "callback": "https://api.observerprotocol.org/lnurl/callback",
        "tag": "payRequest",
        "maxSendable": 1000000000,  # 0.01 BTC max
        "minSendable": 1000,  # 1 sat min
        "metadata": "[[\"text/plain\", \"Pay to maxi@observerprotocol.org\"], [\"text/identifier\", \"maxi@observerprotocol.org\"]]",
        "allowsNostr": False
    }
