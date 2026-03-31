#!/usr/bin/env python3
"""
Attestation Scoping and Hybrid Trust Model — Observer Protocol

Implements attestation scoping with a hybrid trust model differentiating
between trust levels based on partner type, verification depth, and
cryptographic assurance.

Trust Levels:
    LEVEL_1  Self-attested (agent itself)
    LEVEL_2  Counterparty attested (transaction counterparties)
    LEVEL_3  Partner attested (registered protocol partners)
    LEVEL_4  Organization attested (registered organizations with legal backing)
    LEVEL_5  OP Verified (Observer Protocol direct verification)

Note: Trust scoring (ARS-1.0) lives in AT, not OP.
  get_effective_trust_score() has been removed from this module.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from dataclasses import dataclass, field


class TrustLevel(Enum):
    LEVEL_0 = 0  # No attestation / Revoked
    LEVEL_1 = 1  # Self-attested
    LEVEL_2 = 2  # Counterparty attested
    LEVEL_3 = 3  # Partner attested
    LEVEL_4 = 4  # Organization attested
    LEVEL_5 = 5  # OP verified


class AttestationScope(Enum):
    IDENTITY = "identity"
    LEGAL_ENTITY = "legal_entity"
    COMPLIANCE = "compliance"
    REPUTATION = "reputation"
    CAPABILITY = "capability"
    TRANSACTION = "transaction"
    INFRASTRUCTURE = "infrastructure"
    CUSTOM = "custom"


@dataclass
class AttestationProof:
    """Cryptographic proof for an attestation."""
    signature: str
    signer_public_key: str
    timestamp: str
    hash_algorithm: str = "sha256"
    signature_scheme: str = "ecdsa-secp256k1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.signature,
            "signer_public_key": self.signer_public_key,
            "timestamp": self.timestamp,
            "hash_algorithm": self.hash_algorithm,
            "signature_scheme": self.signature_scheme,
        }


@dataclass
class AttestationScopeDetails:
    """Details about the scope of an attestation."""
    scope_type: AttestationScope
    scope_description: str
    valid_from: str
    valid_until: Optional[str] = None
    restrictions: List[str] = field(default_factory=list)

    def is_valid(self) -> bool:
        now = datetime.utcnow()
        valid_from = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
        if valid_from.tzinfo:
            from datetime import timezone
            now = datetime.now(timezone.utc)
        if valid_from > now:
            return False
        if self.valid_until:
            valid_until = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            if valid_until.tzinfo:
                from datetime import timezone
                now = datetime.now(timezone.utc)
            if valid_until < now:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "scope_type": self.scope_type.value,
            "scope_description": self.scope_description,
            "valid_from": self.valid_from,
        }
        if self.valid_until:
            result["valid_until"] = self.valid_until
        if self.restrictions:
            result["restrictions"] = self.restrictions
        return result


@dataclass
class HybridAttestation:
    """
    Hybrid attestation combining on-chain and off-chain verification.

    Note: Trust scoring (ARS-1.0) is the responsibility of AT, not OP.
    This class carries the attestation data only.
    """
    agent_id: str
    trust_level: TrustLevel
    claims: Dict[str, Any]
    scope: AttestationScopeDetails
    proof: Optional[AttestationProof] = None

    # Layer 5: agent_did is the W3C DID string for the agent.
    # Preferred over agent_id in all external-facing payloads.
    agent_did: Optional[str] = None

    attestor_type: str = ""
    attestor_id: Optional[str] = None

    on_chain_anchor: Optional[str] = None
    off_chain_evidence: Optional[str] = None
    verification_depth: int = 0

    def compute_hash(self) -> str:
        data = {
            "agent_id": self.agent_id,
            "trust_level": self.trust_level.value,
            "claims": self.claims,
            "scope": self.scope.to_dict(),
            "attestor_type": self.attestor_type,
            "attestor_id": self.attestor_id,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "trust_level": {
                "level": self.trust_level.value,
                "name": self.trust_level.name,
            },
            "claims": self.claims,
            "scope": self.scope.to_dict(),
            "attestor": {
                "type": self.attestor_type,
            },
        }
        # Layer 5: include agent_did when available (preferred over agent_id externally)
        if self.agent_did:
            result["agent_did"] = self.agent_did
        if self.attestor_id:
            result["attestor"]["id"] = self.attestor_id
        if self.on_chain_anchor:
            result["hybrid"] = {"on_chain_anchor": self.on_chain_anchor}
        if self.off_chain_evidence:
            result.setdefault("hybrid", {})["off_chain_evidence"] = self.off_chain_evidence
        if self.proof:
            result["proof"] = self.proof.to_dict()
        return result


class AttestationValidator:
    """
    Validator for hybrid attestations.

    Validates based on: cryptographic proof, trust level, scope validity,
    and revocation status.
    """

    def __init__(self, min_trust_level: TrustLevel = TrustLevel.LEVEL_1):
        self.min_trust_level = min_trust_level
        self._trusted_attestors: set = set()
        self._revoked_attestations: set = set()

    def add_trusted_attestor(self, attestor_id: str) -> None:
        self._trusted_attestors.add(attestor_id)

    def revoke_attestation(self, attestation_hash: str) -> None:
        self._revoked_attestations.add(attestation_hash)

    def validate(self, attestation: HybridAttestation) -> Dict[str, Any]:
        """Validate a hybrid attestation. Returns result dict with checks."""
        result: Dict[str, Any] = {"valid": True, "checks": {}, "errors": []}

        # Trust level check
        if attestation.trust_level.value < self.min_trust_level.value:
            result["valid"] = False
            result["errors"].append(
                f"Trust level {attestation.trust_level.name} below minimum "
                f"{self.min_trust_level.name}"
            )
        result["checks"]["trust_level"] = (
            attestation.trust_level.value >= self.min_trust_level.value
        )

        # Scope validity
        scope_valid = attestation.scope.is_valid()
        if not scope_valid:
            result["valid"] = False
            result["errors"].append("Attestation scope has expired or is not yet valid")
        result["checks"]["scope_valid"] = scope_valid

        # Cryptographic proof
        if attestation.proof:
            proof_valid = self._verify_proof(attestation)
            if not proof_valid:
                result["valid"] = False
                result["errors"].append("Cryptographic proof verification failed")
            result["checks"]["proof_valid"] = proof_valid
        else:
            result["checks"]["proof_valid"] = None

        # Attestor trust
        attestor_trusted = (
            attestation.attestor_id in self._trusted_attestors
            if attestation.attestor_id
            else attestation.trust_level == TrustLevel.LEVEL_1
        )
        result["checks"]["attestor_trusted"] = attestor_trusted

        # Revocation
        attestation_hash = attestation.compute_hash()
        not_revoked = attestation_hash not in self._revoked_attestations
        if not not_revoked:
            result["valid"] = False
            result["errors"].append("Attestation has been revoked")
        result["checks"]["not_revoked"] = not_revoked

        return result

    def _verify_proof(self, attestation: HybridAttestation) -> bool:
        """Verify cryptographic proof of attestation."""
        if not attestation.proof:
            return True
        try:
            from crypto_verification import verify_signature
            message = attestation.compute_hash().encode()
            return verify_signature(
                message,
                attestation.proof.signature,
                attestation.proof.signer_public_key,
            )
        except Exception as exc:
            print(f"Proof verification error: {exc}")
            return False


class AttestationScopeManager:
    """Handles creation of scoped attestations."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url
        self._attestations: Dict[str, HybridAttestation] = {}

    def create_self_attestation(
        self,
        agent_id: str,
        claims: Dict[str, Any],
        scope_type: AttestationScope = AttestationScope.IDENTITY,
    ) -> HybridAttestation:
        scope = AttestationScopeDetails(
            scope_type=scope_type,
            scope_description=f"Self-attested {scope_type.value}",
            valid_from=datetime.utcnow().isoformat(),
            valid_until=(datetime.utcnow() + timedelta(days=30)).isoformat(),
        )
        return HybridAttestation(
            agent_id=agent_id,
            trust_level=TrustLevel.LEVEL_1,
            claims=claims,
            scope=scope,
            attestor_type="self",
            attestor_id=agent_id,
            verification_depth=0,
        )

    def create_partner_attestation(
        self,
        agent_id: str,
        partner_id: str,
        claims: Dict[str, Any],
        partner_public_key: str,
        partner_private_key: str,
        scope_type: AttestationScope = AttestationScope.LEGAL_ENTITY,
    ) -> HybridAttestation:
        from crypto_verification import sign_message_secp256k1

        scope = AttestationScopeDetails(
            scope_type=scope_type,
            scope_description=f"Partner-attested {scope_type.value}",
            valid_from=datetime.utcnow().isoformat(),
            valid_until=(datetime.utcnow() + timedelta(days=90)).isoformat(),
        )
        attestation = HybridAttestation(
            agent_id=agent_id,
            trust_level=TrustLevel.LEVEL_3,
            claims=claims,
            scope=scope,
            attestor_type="partner",
            attestor_id=partner_id,
            verification_depth=1,
        )
        hash_to_sign = attestation.compute_hash()
        signature = sign_message_secp256k1(hash_to_sign.encode(), partner_private_key)
        attestation.proof = AttestationProof(
            signature=signature,
            signer_public_key=partner_public_key,
            timestamp=datetime.utcnow().isoformat(),
        )
        return attestation

    def create_op_attestation(
        self,
        agent_id: str,
        claims: Dict[str, Any],
        op_signing_key: str,
        op_public_key: str,
        scope_type: AttestationScope = AttestationScope.IDENTITY,
    ) -> HybridAttestation:
        from crypto_verification import sign_message_secp256k1

        scope = AttestationScopeDetails(
            scope_type=scope_type,
            scope_description=f"OP-verified {scope_type.value}",
            valid_from=datetime.utcnow().isoformat(),
            valid_until=(datetime.utcnow() + timedelta(days=365)).isoformat(),
        )
        attestation = HybridAttestation(
            agent_id=agent_id,
            trust_level=TrustLevel.LEVEL_5,
            claims=claims,
            scope=scope,
            attestor_type="op",
            attestor_id="observer_protocol",
            verification_depth=3,
        )
        hash_to_sign = attestation.compute_hash()
        signature = sign_message_secp256k1(hash_to_sign.encode(), op_signing_key)
        attestation.proof = AttestationProof(
            signature=signature,
            signer_public_key=op_public_key,
            timestamp=datetime.utcnow().isoformat(),
        )
        return attestation


def create_legal_entity_attestation(
    agent_id: str,
    legal_entity_id: str,
    partner_id: str,
    partner_public_key: str,
    partner_private_key: str,
    jurisdiction: Optional[str] = None,
) -> HybridAttestation:
    manager = AttestationScopeManager()
    claims: Dict[str, Any] = {
        "legal_entity_id": legal_entity_id,
        "attestation_type": "legal_entity_verification",
    }
    if jurisdiction:
        claims["jurisdiction"] = jurisdiction
    return manager.create_partner_attestation(
        agent_id=agent_id,
        partner_id=partner_id,
        claims=claims,
        partner_public_key=partner_public_key,
        partner_private_key=partner_private_key,
        scope_type=AttestationScope.LEGAL_ENTITY,
    )


def create_identity_attestation(
    agent_id: str,
    identity_claims: Dict[str, Any],
    op_signing_key: str,
    op_public_key: str,
) -> HybridAttestation:
    manager = AttestationScopeManager()
    return manager.create_op_attestation(
        agent_id=agent_id,
        claims=identity_claims,
        op_signing_key=op_signing_key,
        op_public_key=op_public_key,
        scope_type=AttestationScope.IDENTITY,
    )
