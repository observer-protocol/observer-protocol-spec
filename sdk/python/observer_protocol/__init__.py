"""
Observer Protocol Python SDK

Register agents, verify transactions, manage attestations, and retrieve
Verified Agent Credentials on Observer Protocol.

Usage:
    from observer_protocol import ObserverClient

    client = ObserverClient()
    agent = client.register_agent(public_key="your_ed25519_hex_key")
    client.verify_agent(agent.agent_id, signed_challenge)
    vac = client.get_vac(agent.agent_id)
"""

from observer_protocol.client import ObserverClient
from observer_protocol.models import (
    Agent,
    Attestation,
    AuditActivity,
    ChainVerification,
    Challenge,
    TrustScore,
    VAC,
)

__version__ = "0.1.1"
__all__ = [
    "ObserverClient",
    "Agent",
    "Attestation",
    "AuditActivity",
    "ChainVerification",
    "Challenge",
    "TrustScore",
    "VAC",
]
