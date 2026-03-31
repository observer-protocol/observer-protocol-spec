#!/usr/bin/env python3
"""
Organization Models — Observer Protocol
Pydantic models for organization registration and management.
"""

import re
from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, Field, validator


class OrganizationBase(BaseModel):
    """Base organization model with common fields."""
    name: str = Field(..., min_length=1, max_length=200, description="Organization name")
    domain: str = Field(..., min_length=4, max_length=255, description="Organization domain (e.g., example.com)")
    display_name: Optional[str] = Field(None, max_length=200, description="Display name (defaults to name if not provided)")
    description: Optional[str] = Field(None, max_length=2000, description="Organization description")

    @validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.lower().strip()
        if "." not in v or len(v) < 4:
            raise ValueError("Invalid domain format")
        if not re.match(r"^[a-z0-9][a-z0-9-]*\.[a-z]{2,}$", v):
            raise ValueError("Domain must be a valid format (e.g., example.com)")
        return v

    @validator("display_name", always=True)
    @classmethod
    def set_display_name(cls, v, values):
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return values.get("name", "")
        return v


class OrganizationKeypair(BaseModel):
    """Organization keypair model."""
    master_public_key: str = Field(
        ..., min_length=32, max_length=500,
        description="Master public key for signing attestations"
    )
    revocation_public_key: str = Field(
        ..., min_length=32, max_length=500,
        description="Revocation public key (separate from master for security)"
    )
    key_type: Literal["secp256k1", "ed25519"] = Field(
        ..., description="Cryptographic key type"
    )

    @validator("master_public_key", "revocation_public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        if v.startswith("0x"):
            v = v[2:]
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("Public key must be hex-encoded")
        return v

    @validator("revocation_public_key")
    @classmethod
    def keys_must_differ(cls, v, values):
        master = values.get("master_public_key", "")
        if v.lower().replace("0x", "") == master.lower().replace("0x", ""):
            raise ValueError("Revocation public key must be different from master public key")
        return v


class OrganizationRegistrationRequest(OrganizationBase, OrganizationKeypair):
    """Request body for registering a new organization."""
    contact_email: Optional[str] = Field(None, max_length=255)
    metadata: Optional[dict] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Acme Corporation",
                "domain": "acme.com",
                "display_name": "Acme Corp",
                "description": "Enterprise software solutions",
                "master_public_key": "04a1b2c3d4e5f6...",
                "revocation_public_key": "04f6e5d4c3b2a1...",
                "key_type": "secp256k1",
                "contact_email": "security@acme.com",
                "metadata": {"industry": "technology"},
            }
        }


class OrganizationResponse(BaseModel):
    """Response model for organization queries."""
    org_id: str = Field(..., description="Unique organization identifier (UUID)")
    name: str
    domain: str
    display_name: str
    description: Optional[str] = None
    org_did: Optional[str] = Field(None, description="did:web DID for this organization")
    did_document: Optional[dict] = Field(None, description="W3C DID Document")
    master_public_key_hash: str
    revocation_public_key_hash: str
    key_type: Literal["secp256k1", "ed25519"]
    status: Literal["active", "suspended", "revoked"]
    verification_status: Literal["self_attested", "pending_kyb", "kyb_verified", "kyb_failed"]
    registered_at: datetime
    updated_at: datetime
    metadata: dict = Field(default_factory=dict)

    class Config:
        from_attributes = True


class OrganizationDetailResponse(OrganizationResponse):
    """Detailed response including public keys (for authorized access)."""
    master_public_key: str
    revocation_public_key: str

    class Config:
        from_attributes = True


class OrganizationRevocationRequest(BaseModel):
    """Request body for revoking an organization."""
    reason: str = Field(..., min_length=10, max_length=1000)
    revocation_signature: Optional[str] = None


class OrganizationRevocationResponse(BaseModel):
    """Response model for organization revocation."""
    org_id: str
    status: Literal["revoked"]
    revoked_at: datetime
    reason: str
    message: str


class OrganizationListResponse(BaseModel):
    """Response model for listing organizations."""
    organizations: list[OrganizationResponse]
    count: int
