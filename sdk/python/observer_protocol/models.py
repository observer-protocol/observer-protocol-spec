"""
Observer Protocol SDK - Data Models

Type-safe dataclasses for all API responses.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Agent Identity ───────────────────────────────────────────

@dataclass
class Agent:
    """A registered agent on Observer Protocol."""
    agent_id: str
    agent_did: str
    agent_name: Optional[str] = None
    verified: bool = False
    verified_at: Optional[str] = None
    trust_score: Optional[float] = None
    rails: Optional[List[str]] = None
    transaction_count: int = 0
    attestation_count: int = 0
    did_document: Optional[Dict[str, Any]] = None

    @classmethod
    def from_registration(cls, data: dict) -> "Agent":
        return cls(
            agent_id=data["agent_id"],
            agent_did=data.get("agent_did", ""),
            agent_name=data.get("agent_name"),
            did_document=data.get("did_document"),
        )

    @classmethod
    def from_profile(cls, data: dict) -> "Agent":
        return cls(
            agent_id=data["agent_id"],
            agent_did=data.get("did", ""),
            agent_name=data.get("agent_name") or data.get("alias"),
            verified=data.get("verified", False),
            verified_at=data.get("verified_at"),
            trust_score=data.get("trust_score"),
            rails=data.get("rails"),
            transaction_count=data.get("transaction_count", 0),
            attestation_count=data.get("attestation_count", 0),
        )


@dataclass
class Challenge:
    """A cryptographic challenge for agent verification."""
    challenge_id: str
    nonce: str
    expires_at: str


# ── Trust Score ──────────────────────────────────────────────

@dataclass
class TrustScoreComponents:
    """AT-ARS trust score component breakdown."""
    receipt_score: float = 0
    counterparty_score: float = 0
    org_score: float = 0
    recency_score: float = 0
    volume_score: float = 0


@dataclass
class TrustScore:
    """AT-ARS trust score with component breakdown."""
    agent_id: str
    trust_score: float
    receipt_count: int = 0
    unique_counterparties: int = 0
    total_stablecoin_volume: str = "0"
    last_activity: Optional[str] = None
    components: Optional[TrustScoreComponents] = None

    @classmethod
    def from_response(cls, data: dict) -> "TrustScore":
        components = None
        if data.get("components"):
            c = data["components"]
            components = TrustScoreComponents(
                receipt_score=c.get("receipt_score", 0),
                counterparty_score=c.get("counterparty_score", 0),
                org_score=c.get("org_score", 0),
                recency_score=c.get("recency_score", 0),
                volume_score=c.get("volume_score", 0),
            )
        return cls(
            agent_id=data["agent_id"],
            trust_score=data["trust_score"],
            receipt_count=data.get("receipt_count", 0),
            unique_counterparties=data.get("unique_counterparties", 0),
            total_stablecoin_volume=data.get("total_stablecoin_volume", "0"),
            last_activity=data.get("last_activity"),
            components=components,
        )


# ── Delegation ───────────────────────────────────────────────

@dataclass
class Delegation:
    """A delegation credential request."""
    request_id: str
    agent_id: str
    agent_name: Optional[str] = None
    org_did: str = ""
    requested_by: str = ""
    status: str = "pending_approval"
    created_at: Optional[str] = None
    expiry: Optional[str] = None
    spending_limits: Optional[Dict[str, str]] = None
    permissions: Optional[List[str]] = None
    attestation_tier: str = "enterprise"

    @classmethod
    def from_response(cls, data: dict) -> "Delegation":
        return cls(
            request_id=data["request_id"],
            agent_id=data["agent_id"],
            agent_name=data.get("agent_name") or data.get("alias"),
            org_did=data.get("org_did", ""),
            requested_by=data.get("requested_by", ""),
            status=data.get("status", "pending_approval"),
            created_at=data.get("created_at"),
            expiry=data.get("expiry"),
            spending_limits=data.get("spending_limits"),
            permissions=data.get("permissions"),
            attestation_tier=data.get("attestation_tier", "enterprise"),
        )


# ── Magic Link ───────────────────────────────────────────────

@dataclass
class MagicLink:
    """A magic link for human-in-the-loop authorization."""
    token: str
    url: str
    slug: str
    intro: str
    transaction_context: Dict[str, str]
    expires_at: str
    jti: str

    @classmethod
    def from_response(cls, data: dict) -> "MagicLink":
        return cls(
            token=data["token"],
            url=data["url"],
            slug=data.get("slug", ""),
            intro=data["intro"],
            transaction_context=data.get("transaction_context", {}),
            expires_at=data["expires_at"],
            jti=data["jti"],
        )


# ── x402 Verification ────────────────────────────────────────

@dataclass
class X402Verification:
    """Dual verification result for an x402 payment."""
    facilitator_verified: bool = False
    onchain_verified: bool = False
    discrepancy: bool = False
    onchain_confirmations: int = 0


@dataclass
class X402Credential:
    """An X402PaymentCredential issued after x402 verification."""
    credential: Dict[str, Any]
    verification: X402Verification
    event_id: str = ""

    @classmethod
    def from_response(cls, data: dict) -> "X402Credential":
        v = data.get("verification", {})
        return cls(
            credential=data.get("credential", {}),
            verification=X402Verification(
                facilitator_verified=v.get("facilitator_verified", False),
                onchain_verified=v.get("onchain_verified", False),
                discrepancy=v.get("discrepancy", False),
                onchain_confirmations=v.get("onchain_confirmations", 0),
            ),
            event_id=data.get("event_id", ""),
        )


# ── Chain Verification ───────────────────────────────────────

@dataclass
class ChainVerification:
    """Result of a chain verification call."""
    verified: bool
    chain: str
    receipt_reference: str
    transaction_reference: Optional[str] = None
    explorer_url: Optional[str] = None
    confirmed_at: Optional[str] = None
    chain_specific: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_response(cls, data: dict) -> "ChainVerification":
        return cls(
            verified=data.get("verified", False),
            chain=data.get("chain", ""),
            receipt_reference=data.get("receipt_reference", ""),
            transaction_reference=data.get("transaction_reference"),
            explorer_url=data.get("explorer_url"),
            confirmed_at=data.get("confirmed_at"),
            chain_specific=data.get("chain_specific", {}),
        )


# ── Attestations ─────────────────────────────────────────────

@dataclass
class Attestation:
    """A partner attestation credential."""
    attestation_id: str
    partner_name: str
    partner_type: str
    claims: Dict[str, Any]
    issued_at: str
    credential_id: Optional[str] = None
    expires_at: Optional[str] = None


# ── 8004 Integration ─────────────────────────────────────────

@dataclass
class ERC8004Summary:
    """An agent's on-chain 8004 presence summary."""
    agent_id: str
    has_8004_presence: bool = False
    nfts: List[Dict[str, Any]] = field(default_factory=list)
    feedback_count: int = 0
    op_backed_count: int = 0
    validation_count: int = 0

    @classmethod
    def from_response(cls, data: dict) -> "ERC8004Summary":
        fb = data.get("feedback", {})
        val = data.get("validations", {})
        return cls(
            agent_id=data.get("agent_id", ""),
            has_8004_presence=data.get("has_8004_presence", False),
            nfts=data.get("nfts", []),
            feedback_count=fb.get("feedback_count", 0),
            op_backed_count=fb.get("op_backed_count", 0),
            validation_count=val.get("validation_count", 0),
        )


# ── Audit ────────────────────────────────────────────────────

@dataclass
class AuditEventResult:
    """Result of writing an audit event."""
    event_id: str
    receipt_reference: str
    dashboard_url: str = ""


# ── Errors ───────────────────────────────────────────────────

class ObserverError(Exception):
    """Error from the Observer Protocol API."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"OP API Error {status_code}: {detail}")
