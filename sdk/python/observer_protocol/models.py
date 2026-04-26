"""
Data models for Observer Protocol SDK responses.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
            agent_name=data.get("agent_name"),
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
            components = TrustScoreComponents(**data["components"])
        return cls(
            agent_id=data["agent_id"],
            trust_score=data["trust_score"],
            receipt_count=data.get("receipt_count", 0),
            unique_counterparties=data.get("unique_counterparties", 0),
            total_stablecoin_volume=data.get("total_stablecoin_volume", "0"),
            last_activity=data.get("last_activity"),
            components=components,
        )


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
    extension_id: Optional[str] = None


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
    idempotent_replay: bool = False
    error: Optional[str] = None

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
            idempotent_replay=data.get("idempotent_replay", False),
            error=data.get("detail", {}).get("detail") if isinstance(data.get("detail"), dict) else data.get("error"),
        )


@dataclass
class AuditActivity:
    """An agent activity credential from the audit trail."""
    id: int
    credential_id: str
    activity_type: str
    activity_timestamp: str
    counterparty_did: Optional[str] = None
    transaction_rail: Optional[str] = None
    transaction_amount: Optional[float] = None
    transaction_currency: Optional[str] = None


@dataclass
class VAC:
    """A Verified Agent Credential (W3C Verifiable Presentation)."""
    raw: Dict[str, Any]

    @property
    def holder(self) -> str:
        return self.raw.get("holder", "")

    @property
    def credentials(self) -> List[Dict[str, Any]]:
        return self.raw.get("verifiableCredential", [])
