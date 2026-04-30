"""
Observer Protocol Python SDK

Agent identity, delegation, x402 verification, and chargeback
prevention for the agentic economy.

Usage:
    from observer_protocol import ObserverClient

    client = ObserverClient()
    pub, priv = ObserverClient.generate_keypair()
    agent = client.register_agent(public_key=pub, agent_name="My Agent")
    challenge = client.request_challenge(agent.agent_id)
    sig = ObserverClient.sign_challenge(priv, challenge.nonce)
    client.verify_agent(agent.agent_id, sig)
"""

from observer_protocol.client import ObserverClient
from observer_protocol.models import (
    Agent,
    Attestation,
    AuditEventResult,
    ChainVerification,
    Challenge,
    Delegation,
    ERC8004Summary,
    MagicLink,
    ObserverError,
    TrustScore,
    TrustScoreComponents,
    X402Credential,
    X402Verification,
)

__version__ = "0.2.0"
__all__ = [
    "ObserverClient",
    "Agent",
    "Attestation",
    "AuditEventResult",
    "ChainVerification",
    "Challenge",
    "Delegation",
    "ERC8004Summary",
    "MagicLink",
    "ObserverError",
    "TrustScore",
    "TrustScoreComponents",
    "X402Credential",
    "X402Verification",
]
