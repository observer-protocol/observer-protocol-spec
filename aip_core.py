#!/usr/bin/env python3
"""
AIP (Agentic Identity Protocol) Core Module
Version: 0.3.1 — Leo Bebchuk Architectural Sign-off Implemented

Key Changes from v0.3:
- Remediation: MINIMAL ENVELOPE ONLY (Section 9.1)
- Chain verification: EAGER REQUIRED (Section 9.3)
- DID method: did:web ONLY (Section 9.2)
- Remediation endpoints: AT-owned (Section 9.4)
"""

import json
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import psycopg2
import psycopg2.extras
import uuid

DB_URL = "postgresql://agentic_terminal:at_secure_2026@localhost/agentic_terminal_db"


class CounterpartyType(str, Enum):
    """6.1 allowed_counterparty_types"""
    VERIFIED_MERCHANT = "verified_merchant"
    KYB_VERIFIED_ORG = "kyb_verified_org"
    DID_VERIFIED_AGENT = "did_verified_agent"
    AIP_DELEGATED_AGENT = "aip_delegated_agent"
    SOVEREIGN_INDIVIDUAL = "sovereign_individual"
    UNVERIFIED = "unverified"


class RevocationReason(str, Enum):
    """6.2 Revocation reason codes"""
    AGENT_COMPROMISED = "agent_compromised"
    AGENT_DECOMMISSIONED = "agent_decommissioned"
    SCOPE_VIOLATION = "scope_violation"
    ORG_KYB_EXPIRED = "org_kyb_expired"
    ORG_KYB_REVOKED = "org_kyb_revoked"
    ORG_OFFBOARDED = "org_offboarded"
    FRAUD_SUSPECTED = "fraud_suspected"
    ADMIN_OVERRIDE = "admin_override"


class DenialReason(str, Enum):
    """6.3 Denial reason codes"""
    SCORE_BELOW_THRESHOLD = "score_below_threshold"
    NO_DELEGATION_CREDENTIAL = "no_delegation_credential"
    DELEGATION_CREDENTIAL_EXPIRED = "delegation_credential_expired"
    DELEGATION_CREDENTIAL_REVOKED = "delegation_credential_revoked"
    SCOPE_MISMATCH = "scope_mismatch"
    COUNTERPARTY_NOT_ELIGIBLE = "counterparty_not_eligible"
    KYB_CREDENTIAL_MISSING = "kyb_credential_missing"
    KYB_CREDENTIAL_EXPIRED = "kyb_credential_expired"
    KYB_CREDENTIAL_REVOKED = "kyb_credential_revoked"
    DID_RESOLUTION_FAILED = "did_resolution_failed"
    DELEGATION_DEPTH_EXCEEDED = "delegation_depth_exceeded"
    GEOGRAPHIC_RESTRICTION = "geographic_restriction"
    RAIL_NOT_PERMITTED = "rail_not_permitted"


class AIPError(Exception):
    """Base AIP error"""
    pass


class TypeRegistryError(AIPError):
    pass


class CredentialValidationError(AIPError):
    pass


class DIDResolutionError(AIPError):
    pass


@dataclass
class KYBVerifiableCredential:
    credential_id: str
    issuer_did: str
    issuer_type: str
    org_did: str
    kyb_provider: Optional[str]
    kyb_provider_did: Optional[str]
    kyb_result: str
    kyb_completed_at: Optional[str]
    kyb_scope: str
    issuance_date: str
    expiration_date: Optional[str]
    credential_json: Dict[str, Any]
    status: str = "active"


@dataclass
class DelegationScope:
    payment_settlement: bool = False
    max_transaction_value_usd: Optional[float] = None
    allowed_counterparty_types: List[str] = field(default_factory=list)
    allowed_rails: List[str] = field(default_factory=list)
    geographic_restriction: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"payment_settlement": self.payment_settlement}
        if self.max_transaction_value_usd is not None:
            result["max_transaction_value_usd"] = self.max_transaction_value_usd
        if self.allowed_counterparty_types:
            result["allowed_counterparty_types"] = self.allowed_counterparty_types
        if self.allowed_rails:
            result["allowed_rails"] = self.allowed_rails
        if self.geographic_restriction:
            result["geographic_restriction"] = self.geographic_restriction
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DelegationScope':
        return cls(
            payment_settlement=data.get("payment_settlement", False),
            max_transaction_value_usd=data.get("max_transaction_value_usd"),
            allowed_counterparty_types=data.get("allowed_counterparty_types", []),
            allowed_rails=data.get("allowed_rails", []),
            geographic_restriction=data.get("geographic_restriction")
        )


@dataclass
class DelegationSignature:
    signed_by: str
    algorithm: str
    value: str
    
    def to_dict(self) -> Dict[str, str]:
        return {"signed_by": self.signed_by, "algorithm": self.algorithm, "value": self.value}


@dataclass
class DelegationCredential:
    credential_id: str
    version: str
    org_did: str
    org_name: str
    kyb_credential_id: Optional[str]
    agent_did: str
    agent_label: Optional[str]
    scope: DelegationScope
    delegation_depth: int
    max_delegation_depth: int
    parent_credential_id: Optional[str]
    signature: DelegationSignature
    issued_at: str
    expires_at: str
    status: str = "active"


@dataclass
class RevocationRecord:
    credential_id: str
    credential_type: str
    revoked_by_did: str
    revoked_by_key_id: str
    reason: str
    reason_description: Optional[str]
    revocation_signature: str
    cascade_to_children: bool
    cascaded_credential_ids: List[str]
    revoked_at: str


@dataclass
class RemediationOptionEnvelope:
    """MINIMAL remediation option — envelope only per Section 9.1"""
    option_id: int
    action: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    action_endpoint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"option_id": self.option_id}
        if self.action:
            result["action"] = self.action
        if self.title:
            result["title"] = self.title
        if self.description:
            result["description"] = self.description
        if self.action_endpoint:
            result["action_endpoint"] = self.action_endpoint
        return result


@dataclass
class RemediationResponseEnvelope:
    """MINIMAL remediation response envelope per Section 9.1"""
    status: str = "denied"
    reason: str = ""
    score_name: str = "AT Trust Score"
    score: int = 0
    threshold: int = 0
    gap: int = 0
    options: List[RemediationOptionEnvelope] = field(default_factory=list)
    remediation_note: str = "Options are ordered by estimated time to resolution."
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "score_name": self.score_name,
            "score": self.score,
            "threshold": self.threshold,
            "gap": self.gap,
            "remediation_options": [opt.to_dict() for opt in self.options],
            "remediation_note": self.remediation_note
        }


class TypeRegistryValidator:
    """Validates values against the AIP Type Registry (Section 6)"""
    
    def __init__(self, db_url: str = DB_URL):
        self.db_url = db_url
        self._cache: Dict[str, List[str]] = {}
        self._load_cache()
    
    def _get_connection(self):
        return psycopg2.connect(self.db_url)
    
    def _load_cache(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT category, value FROM aip_type_registry WHERE status = 'active'")
            rows = cursor.fetchall()
            self._cache = {}
            for category, value in rows:
                if category not in self._cache:
                    self._cache[category] = []
                self._cache[category].append(value)
        finally:
            cursor.close()
            conn.close()
    
    def validate_counterparty_type(self, value: str) -> bool:
        return value in self._cache.get('counterparty_type', [])
    
    def validate_revocation_reason(self, value: str) -> bool:
        return value in self._cache.get('revocation_reason', [])
    
    def validate_denial_reason(self, value: str) -> bool:
        return value in self._cache.get('denial_reason', [])
    
    def validate_counterparty_types_list(self, values: List[str]) -> Tuple[bool, List[str]]:
        valid_values = self._cache.get('counterparty_type', [])
        invalid = [v for v in values if v not in valid_values]
        return len(invalid) == 0, invalid
    
    def get_valid_values(self, category: str) -> List[str]:
        return self._cache.get(category, [])
    
    def refresh_cache(self):
        self._load_cache()


class DIDResolver:
    """W3C DID resolver for did:web method ONLY (Section 9.2)"""
    
    DID_WEB_PATTERN = re.compile(r'^did:web:(?P<domain>[^:]+)(?::(?P<path>.+))?$')
    
    @classmethod
    def parse_did_web(cls, did: str) -> Optional[Dict[str, str]]:
        if not did.startswith('did:web:'):
            return None
        match = cls.DID_WEB_PATTERN.match(did)
        if not match:
            return None
        return {
            'domain': match.group('domain'),
            'path': match.group('path') or '',
            'did': did
        }
    
    @classmethod
    def resolve_to_url(cls, did: str) -> Optional[str]:
        parsed = cls.parse_did_web(did)
        if not parsed:
            return None
        domain = parsed['domain']
        path = parsed['path']
        if path:
            url_path = '/'.join(path.split(':'))
            return f"https://{domain}/{url_path}/did.json"
        return f"https://{domain}/.well-known/did.json"
    
    @classmethod
    def extract_domain(cls, did: str) -> Optional[str]:
        parsed = cls.parse_did_web(did)
        return parsed['domain'] if parsed else None
    
    @classmethod
    def validate_did_document(cls, doc: Dict) -> Tuple[bool, str]:
        if not isinstance(doc, dict):
            return False, "DID document must be a JSON object"
        if not doc.get('@context'):
            return False, "Missing @context"
        if not doc.get('id'):
            return False, "Missing id"
        vms = doc.get('verificationMethod')
        if not vms or not isinstance(vms, list):
            return False, "Missing or invalid verificationMethod"
        if not (doc.get('authentication') or doc.get('assertionMethod')):
            return False, "Missing authentication or assertionMethod"
        return True, "Valid DID document"
    
    @classmethod
    def validate_domain_match(cls, agent_did: str, org_did: str) -> bool:
        agent_domain = cls.extract_domain(agent_did)
        org_domain = cls.extract_domain(org_did)
        if not agent_domain or not org_domain:
            return False
        return agent_domain == org_domain
