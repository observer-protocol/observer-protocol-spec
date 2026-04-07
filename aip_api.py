#!/usr/bin/env python3
"""
AIP API Routes — FastAPI endpoints for Agentic Identity Protocol v0.3.1
Integrates with observer-protocol-repo/api-server-v2.py
"""

from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from aip_core import (
    DelegationScope, DelegationSignature,
    CounterpartyType, RevocationReason, DenialReason,
    RemediationOptionEnvelope, RemediationResponseEnvelope,
    DIDResolver, TypeRegistryError, CredentialValidationError,
    DIDResolutionError, AIPError
)
from aip_manager import AIPManager

# Create router
aip_router = APIRouter(prefix="/aip", tags=["AIP"])

# Initialize manager
aip_manager = AIPManager()


# ============================================================
# Pydantic Models for Request/Response
# ============================================================

class KYBVCIssueRequest(BaseModel):
    """Request to issue a KYB Verifiable Credential"""
    org_did: str
    kyb_provider: str
    kyb_result: str = Field(..., regex="^(pass|fail|pending)$")
    issuer_did: str = "did:web:agenticterminal.io"
    issuer_type: str = "at_anchored"
    kyb_provider_did: Optional[str] = None
    kyb_scope: str = "organization"
    expiration_days: int = 365


class KYBVCIssueResponse(BaseModel):
    """Response from KYB VC issuance"""
    credential_id: str
    issuer_did: str
    org_did: str
    kyb_result: str
    issuance_date: str
    expiration_date: str
    credential_json: Dict[str, Any]


class ScopeDefinition(BaseModel):
    """Delegation scope definition"""
    payment_settlement: bool = False
    max_transaction_value_usd: Optional[float] = None
    allowed_counterparty_types: List[str] = []
    allowed_rails: List[str] = []
    geographic_restriction: Optional[str] = None


class DelegationIssueRequest(BaseModel):
    """Request to issue a Delegation Credential"""
    org_did: str
    org_name: str
    kyb_credential_id: Optional[str] = None
    agent_did: str
    agent_label: Optional[str] = None
    scope: ScopeDefinition
    delegation_depth: int = Field(1, ge=1, le=10)
    max_delegation_depth: int = Field(3, ge=1, le=10)
    parent_credential_id: Optional[str] = None
    expiration_days: int = 180


class DelegationIssueResponse(BaseModel):
    """Response from Delegation Credential issuance"""
    credential_id: str
    version: str = "0.3"
    org_did: str
    org_name: str
    agent_did: str
    agent_label: Optional[str]
    scope: Dict[str, Any]
    delegation_depth: int
    max_delegation_depth: int
    issued_at: str
    expires_at: str


class RevocationRequest(BaseModel):
    """Request to revoke a credential"""
    credential_id: str
    revoked_by: str  # did:web:...#revocation-key
    reason: str  # Type Registry value
    timestamp: str
    signature: str
    reason_description: Optional[str] = None
    cascade_to_children: bool = False


class RevocationResponse(BaseModel):
    """Response from revocation"""
    credential_id: str
    credential_type: str
    status: str = "revoked"
    revoked_at: str
    cascaded_count: int = 0


class CredentialStatusResponse(BaseModel):
    """Credential status check response"""
    credential_id: str
    credential_type: Optional[str]
    status: str
    checked_at: str


class RemediationOptionRequest(BaseModel):
    """Remediation option content (AT-provided)"""
    option_id: int
    action: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    action_endpoint: Optional[str] = None


class RemediationBuildRequest(BaseModel):
    """Request to build remediation envelope"""
    reason: str
    score: int
    threshold: int
    options: List[RemediationOptionRequest] = []


class RemediationResponse(BaseModel):
    """MINIMAL remediation response envelope per Section 9.1"""
    status: str = "denied"
    reason: str
    score_name: str = "AT Trust Score"
    score: int
    threshold: int
    gap: int
    remediation_options: List[Dict[str, Any]]
    remediation_note: str


class AgentCredentialsResponse(BaseModel):
    """Full credentials for an agent (Lane 2: authenticated)"""
    agent_did: str
    delegation_credentials: List[Dict[str, Any]]
    credential_count: int
    checked_at: str


class DIDResolveResponse(BaseModel):
    """DID resolution response"""
    did: str
    resolved_url: str
    did_document: Optional[Dict[str, Any]] = None
    valid: bool
    message: str


# ============================================================
# API Routes
# ============================================================

@aip_router.post("/credentials/kyb", response_model=KYBVCIssueResponse)
async def issue_kyb_vc(request: KYBVCIssueRequest):
    """
    Issue a KYB Verifiable Credential (Section 3.1).
    AT-anchored or provider-issued.
    """
    try:
        vc = aip_manager.issue_kyb_vc(
            org_did=request.org_did,
            kyb_provider=request.kyb_provider,
            kyb_result=request.kyb_result,
            issuer_did=request.issuer_did,
            issuer_type=request.issuer_type,
            kyb_provider_did=request.kyb_provider_did,
            kyb_scope=request.kyb_scope,
            expiration_days=request.expiration_days
        )
        
        return KYBVCIssueResponse(
            credential_id=vc.credential_id,
            issuer_did=vc.issuer_did,
            org_did=vc.org_did,
            kyb_result=vc.kyb_result,
            issuance_date=vc.issuance_date,
            expiration_date=vc.expiration_date,
            credential_json=vc.credential_json
        )
    except DIDResolutionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KYB VC issuance failed: {str(e)}")


@aip_router.get("/credentials/kyb/{credential_id}")
async def get_kyb_vc(credential_id: str):
    """Retrieve a KYB VC by ID"""
    vc = aip_manager.get_kyb_vc(credential_id)
    if not vc:
        raise HTTPException(status_code=404, detail="KYB VC not found")
    
    return {
        "credential_id": vc.credential_id,
        "issuer_did": vc.issuer_did,
        "issuer_type": vc.issuer_type,
        "org_did": vc.org_did,
        "kyb_provider": vc.kyb_provider,
        "kyb_result": vc.kyb_result,
        "issuance_date": vc.issuance_date,
        "expiration_date": vc.expiration_date,
        "status": vc.status,
        "credential": vc.credential_json
    }


@aip_router.post("/credentials/delegation", response_model=DelegationIssueResponse)
async def issue_delegation_credential(request: DelegationIssueRequest):
    """
    Issue an AIP Delegation Credential (Section 3.2).
    Validates Type Registry values for counterparty types.
    """
    try:
        scope = DelegationScope(
            payment_settlement=request.scope.payment_settlement,
            max_transaction_value_usd=request.scope.max_transaction_value_usd,
            allowed_counterparty_types=request.scope.allowed_counterparty_types,
            allowed_rails=request.scope.allowed_rails,
            geographic_restriction=request.scope.geographic_restriction
        )
        
        cred = aip_manager.issue_delegation_credential(
            org_did=request.org_did,
            org_name=request.org_name,
            kyb_credential_id=request.kyb_credential_id,
            agent_did=request.agent_did,
            agent_label=request.agent_label,
            scope=scope,
            delegation_depth=request.delegation_depth,
            max_delegation_depth=request.max_delegation_depth,
            parent_credential_id=request.parent_credential_id,
            expiration_days=request.expiration_days
        )
        
        return DelegationIssueResponse(
            credential_id=cred.credential_id,
            org_did=cred.org_did,
            org_name=cred.org_name,
            agent_did=cred.agent_did,
            agent_label=cred.agent_label,
            scope=cred.scope.to_dict(),
            delegation_depth=cred.delegation_depth,
            max_delegation_depth=cred.max_delegation_depth,
            issued_at=cred.issued_at,
            expires_at=cred.expires_at
        )
    except TypeRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except DIDResolutionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except CredentialValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delegation issuance failed: {str(e)}")


@aip_router.get("/credentials/delegation/{credential_id}")
async def get_delegation_credential(credential_id: str):
    """Retrieve a Delegation Credential by ID"""
    cred = aip_manager.get_delegation_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Delegation credential not found")
    
    return {
        "credential_id": cred.credential_id,
        "version": cred.version,
        "issuer": {
            "org_did": cred.org_did,
            "org_name": cred.org_name,
            "kyb_credential_id": cred.kyb_credential_id
        },
        "subject": {
            "agent_did": cred.agent_did,
            "agent_label": cred.agent_label
        },
        "scope": cred.scope.to_dict(),
        "delegation_depth": cred.delegation_depth,
        "max_delegation_depth": cred.max_delegation_depth,
        "parent_credential_id": cred.parent_credential_id,
        "signature": cred.signature.to_dict(),
        "issued_at": cred.issued_at,
        "expires_at": cred.expires_at,
        "status": cred.status
    }


@aip_router.post("/revoke", response_model=RevocationResponse)
async def revoke_credential(request: RevocationRequest):
    """
    Revoke a credential (Section 4).
    Validates reason against Type Registry.
    Optionally cascades to child delegations.
    """
    try:
        # Extract credential type from the key ID
        credential_type = "delegation"  # Default, could be inferred from credential_id format
        
        # Determine credential type from ID prefix
        if request.credential_id.startswith("aip-cred-"):
            credential_type = "delegation"
        else:
            # Assume KYB VC (UUID format)
            credential_type = "kyb_vc"
        
        record = aip_manager.revoke_credential(
            credential_id=request.credential_id,
            credential_type=credential_type,
            revoked_by_did=request.revoked_by.split("#")[0],
            revoked_by_key_id=request.revoked_by,
            reason=request.reason,
            revocation_signature=request.signature,
            reason_description=request.reason_description,
            cascade_to_children=request.cascade_to_children
        )
        
        return RevocationResponse(
            credential_id=record.credential_id,
            credential_type=record.credential_type,
            revoked_at=record.revoked_at,
            cascaded_count=len(record.cascaded_credential_ids)
        )
    except TypeRegistryError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revocation failed: {str(e)}")


@aip_router.get("/credential-status/{credential_id}", response_model=CredentialStatusResponse)
async def check_credential_status(credential_id: str):
    """
    Check credential status (Section 7.2).
    Returns active, expired, revoked, or not_found.
    """
    status = aip_manager.check_credential_status(credential_id)
    return CredentialStatusResponse(**status)


@aip_router.post("/remediation/build", response_model=RemediationResponse)
async def build_remediation_response(request: RemediationBuildRequest):
    """
    Build MINIMAL remediation response envelope (Section 5, 9.1).
    AIP provides envelope structure; AT provides option content.
    """
    try:
        # Validate denial reason
        if not aip_manager.type_registry.validate_denial_reason(request.reason):
            valid_reasons = aip_manager.type_registry.get_valid_values('denial_reason')
            raise HTTPException(
                status_code=400,
                detail=f"Invalid denial reason. Valid: {', '.join(valid_reasons)}"
            )
        
        # Build options from request
        options = [
            RemediationOptionEnvelope(
                option_id=opt.option_id,
                action=opt.action,
                title=opt.title,
                description=opt.description,
                action_endpoint=opt.action_endpoint
            )
            for opt in request.options
        ]
        
        envelope = aip_manager.build_remediation_envelope(
            reason=request.reason,
            score=request.score,
            threshold=request.threshold,
            options=options
        )
        
        return RemediationResponse(**envelope.to_dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation build failed: {str(e)}")


@aip_router.get("/chain/verify/{credential_id}")
async def verify_delegation_chain(credential_id: str, agent_did: str, expected_org_did: Optional[str] = None):
    """
    Verify delegation chain EAGERLY (Section 9.3).
    Verifies FULL chain regardless of depth.
    """
    try:
        is_valid, message, chain = aip_manager.chain_verifier.verify_chain(
            credential_id=credential_id,
            agent_did=agent_did,
            expected_org_did=expected_org_did
        )
        
        return {
            "credential_id": credential_id,
            "valid": is_valid,
            "message": message,
            "chain_length": len(chain),
            "chain": [
                {
                    "credential_id": c.credential_id,
                    "org_did": c.org_did,
                    "agent_did": c.agent_did,
                    "delegation_depth": c.delegation_depth
                }
                for c in chain
            ],
            "verified_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chain verification failed: {str(e)}")


@aip_router.get("/type-registry/{category}")
async def get_type_registry_values(category: str):
    """Get valid values for a Type Registry category (Section 6)"""
    valid_categories = ['counterparty_type', 'revocation_reason', 'denial_reason']
    
    if category not in valid_categories:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Valid: {', '.join(valid_categories)}"
        )
    
    values = aip_manager.type_registry.get_valid_values(category)
    
    return {
        "category": category,
        "values": values,
        "count": len(values)
    }


@aip_router.get("/did/resolve/{did:path}")
async def resolve_did(did: str):
    """
    Resolve did:web to URL (Section 7.1, Lane 1).
    Public endpoint - no authentication required.
    """
    if not did.startswith('did:web:'):
        raise HTTPException(
            status_code=400,
            detail="Only did:web method is supported (Section 9.2)"
        )
    
    resolved_url = DIDResolver.resolve_to_url(did)
    
    if not resolved_url:
        raise HTTPException(status_code=400, detail="Invalid did:web format")
    
    return {
        "did": did,
        "resolved_url": resolved_url,
        "message": f"DID resolves to {resolved_url}"
    }


# ============================================================
# Lane 2: Authenticated Credential Viewer Endpoints
# ============================================================

# Note: These endpoints require authentication and should be added to
# the main API server with proper auth middleware

credentials_viewer_router = APIRouter(prefix="/api/v1", tags=["AIP Credential Viewer"])


@credentials_viewer_router.get("/credentials/{agent_did}", response_model=AgentCredentialsResponse)
async def get_agent_credentials(agent_did: str, authorization: str = Header(None)):
    """
    Get full credential set for an agent (Section 7, Lane 2).
    Requires AT API key authentication.
    """
    # TODO: Implement proper auth verification
    # For now, just return the credentials
    
    try:
        summary = aip_manager.get_agent_credentials_summary(agent_did)
        return AgentCredentialsResponse(**summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve credentials: {str(e)}")


@credentials_viewer_router.get("/credential-status/{credential_id}")
async def get_credential_status_api(credential_id: str, authorization: str = Header(None)):
    """
    Check credential status via authenticated API (Section 7.2).
    Requires AT API key authentication.
    """
    status = aip_manager.check_credential_status(credential_id)
    return status
