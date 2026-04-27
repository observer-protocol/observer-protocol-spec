"""
Observer Protocol Python SDK Client.

Usage:
    from observer_protocol import ObserverClient

    # Public endpoints (no API key needed)
    client = ObserverClient()

    # Register and verify an agent
    agent = client.register_agent(public_key="ed25519_hex_key")
    challenge = client.request_challenge(agent.agent_id)
    # ... sign challenge.nonce with your private key ...
    client.verify_agent(agent.agent_id, signature_hex)

    # Retrieve credentials
    vac = client.get_vac(agent.agent_id)
    score = client.get_trust_score(agent.agent_id)
    attestations = client.get_attestations(agent.agent_id)

    # Authenticated endpoints (API key required)
    client = ObserverClient(api_key="your_api_key")

    # Verify a Lightning payment
    result = client.verify_lightning_payment(
        receipt_reference="urn:uuid:...",
        payment_hash="abc123...",
        preimage="def456...",
        presenter_role="payee",
    )

    # Register a VAC extension
    client.register_extension(
        extension_id="myplatform_reputation_v1",
        display_name="My Reputation Score",
        issuer_did="did:web:myplatform.com:op-identity",
        schema={"type": "object", "properties": {"score": {"type": "integer"}}},
    )
"""

import hashlib
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from observer_protocol.models import (
    Agent,
    Attestation,
    AuditActivity,
    ChainVerification,
    Challenge,
    TrustScore,
    VAC,
)

DEFAULT_BASE_URL = "https://api.observerprotocol.org"


class ObserverError(Exception):
    """Error from the Observer Protocol API."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"OP API Error {status_code}: {detail}")


class ObserverClient:
    """
    Observer Protocol Python SDK.

    All public endpoints work without an API key.
    Chain verification, audit, and extension endpoints require an API key.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"

    # ── HTTP helpers ──────────────────────────────────────────

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, params=params, timeout=self.timeout)
        return self._handle_response(resp)

    def _post(self, path: str, data: Optional[dict] = None, params: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self._session.post(url, json=data, params=params, timeout=self.timeout)
        return self._handle_response(resp)

    def _handle_response(self, resp: requests.Response) -> dict:
        if resp.status_code >= 400:
            try:
                detail = resp.json()
                msg = detail.get("detail", detail.get("error", str(detail)))
                if isinstance(msg, dict):
                    msg = msg.get("detail", msg.get("error", str(msg)))
            except (ValueError, KeyError):
                msg = resp.text or f"HTTP {resp.status_code}"
            raise ObserverError(resp.status_code, str(msg))
        if resp.status_code == 204:
            return {}
        return resp.json()

    # ── Agent Registration ────────────────────────────────────

    def register_agent(
        self,
        public_key: str,
        agent_name: Optional[str] = None,
        alias: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> Agent:
        """
        Register a new agent on Observer Protocol.

        Args:
            public_key: Ed25519 public key (hex-encoded, 64 chars)
            agent_name: Optional human-readable name
            alias: Optional short alias
            framework: Optional agent framework identifier

        Returns:
            Agent with agent_id, agent_did, and did_document
        """
        params: Dict[str, Any] = {"public_key": public_key}
        if agent_name:
            params["agent_name"] = agent_name
        if alias:
            params["alias"] = alias
        if framework:
            params["framework"] = framework

        data = self._post("/observer/register-agent", params=params)
        return Agent.from_registration(data)

    def request_challenge(self, agent_id: str) -> Challenge:
        """
        Request a cryptographic challenge for key ownership verification.

        Args:
            agent_id: The agent's ID from registration

        Returns:
            Challenge with nonce to sign
        """
        data = self._post("/observer/challenge", params={"agent_id": agent_id})
        return Challenge(
            challenge_id=data["challenge_id"],
            nonce=data["nonce"],
            expires_at=data["expires_at"],
        )

    def verify_agent(self, agent_id: str, signed_challenge: str) -> dict:
        """
        Submit a signed challenge to prove key ownership.

        Args:
            agent_id: The agent's ID
            signed_challenge: Hex-encoded Ed25519 signature of the challenge nonce

        Returns:
            Verification result with verified=True on success
        """
        return self._post(
            "/observer/verify-agent",
            params={"agent_id": agent_id, "signed_challenge": signed_challenge},
        )

    # ── Agent Profile ─────────────────────────────────────────

    def get_agent(self, agent_id: str) -> Agent:
        """
        Get an agent's public profile.

        Args:
            agent_id: The agent's ID

        Returns:
            Agent with profile data including trust score
        """
        data = self._get(f"/api/v1/agents/{agent_id}/profile")
        return Agent.from_profile(data)

    def get_did_document(self, agent_id: str) -> dict:
        """
        Get an agent's W3C DID document.

        Args:
            agent_id: The agent's ID

        Returns:
            DID document (JSON)
        """
        return self._get(f"/agents/{agent_id}/did.json")

    # ── VAC ───────────────────────────────────────────────────

    def get_vac(self, agent_id: str) -> VAC:
        """
        Get an agent's Verified Agent Credential.

        The VAC is a W3C Verifiable Presentation containing the agent's
        credentials, attestations, and extension references.

        Args:
            agent_id: The agent's ID

        Returns:
            VAC (Verifiable Presentation)
        """
        data = self._get(f"/vac/{agent_id}")
        return VAC(raw=data)

    # ── Trust Score ───────────────────────────────────────────

    def get_trust_score(self, agent_id: str) -> TrustScore:
        """
        Get an agent's AT-ARS trust score with component breakdown.

        AT-ARS 1.0 components:
          - Transactions (25%): verified receipt count
          - Counterparties (20%): unique counterparty diversity
          - Organization (20%): org affiliation
          - Recency (15%): days since last activity
          - Volume (15%): total transaction volume

        Args:
            agent_id: The agent's ID

        Returns:
            TrustScore with component breakdown
        """
        data = self._get(f"/api/v1/trust/tron/score/{agent_id}")
        return TrustScore.from_response(data)

    # ── Attestations ──────────────────────────────────────────

    def get_attestations(
        self, agent_id: str, partner_type: Optional[str] = None
    ) -> List[Attestation]:
        """
        Get all attestations for an agent.

        Args:
            agent_id: The agent's ID
            partner_type: Optional filter (corpo, verifier, counterparty, infrastructure)

        Returns:
            List of Attestation objects
        """
        params = {}
        if partner_type:
            params["partner_type"] = partner_type

        data = self._get(f"/vac/{agent_id}/attestations", params=params)
        return [
            Attestation(
                attestation_id=a["attestation_id"],
                partner_name=a["partner_name"],
                partner_type=a["partner_type"],
                claims=a.get("claims", {}),
                issued_at=a["issued_at"],
                credential_id=a.get("credential_id"),
                expires_at=a.get("expires_at"),
                extension_id=a.get("extension_id"),
            )
            for a in data.get("attestations", [])
        ]

    # ── Chain Verification ────────────────────────────────────

    def verify_chain(
        self,
        receipt_reference: str,
        chain: str,
        chain_specific: Dict[str, Any],
        transaction: Optional[Dict[str, Any]] = None,
    ) -> ChainVerification:
        """
        Verify a transaction on any supported chain.

        Requires API key.

        Args:
            receipt_reference: Unique ID (idempotency key), e.g. "urn:uuid:..."
            chain: "lightning", "tron", or "stacks"
            chain_specific: Chain-specific verification parameters
            transaction: Optional transaction details (amount, sender, recipient)

        Returns:
            ChainVerification result
        """
        body: Dict[str, Any] = {
            "receipt_reference": receipt_reference,
            "chain": chain,
            "chain_specific": chain_specific,
        }
        if transaction:
            body["transaction"] = transaction

        data = self._post("/v1/chain/verify", body)
        return ChainVerification.from_response(data)

    def verify_lightning_payment(
        self,
        receipt_reference: str,
        payment_hash: str,
        preimage: str,
        presenter_role: str = "payee",
        payee_attestation: Optional[dict] = None,
    ) -> ChainVerification:
        """
        Verify a Lightning payment. Convenience wrapper around verify_chain.

        Requires API key.

        Three verification tiers:
          Tier 1: Payee attestation (payer presents payee's signed receipt) — strongest
          Tier 2: LND node query (if OP has LND access) — medium
          Tier 3: Preimage only (payee presents preimage) — payee-side only

        Key rule: payer with preimage only (no attestation, no LND) is REJECTED.

        Args:
            receipt_reference: Unique ID (idempotency key)
            payment_hash: Lightning payment hash (hex)
            preimage: Lightning preimage (hex)
            presenter_role: "payer" or "payee"
            payee_attestation: Optional signed LightningPaymentReceipt VC (for Tier 1)

        Returns:
            ChainVerification result
        """
        chain_specific: Dict[str, Any] = {
            "payment_hash": payment_hash,
            "preimage": preimage,
            "presenter_role": presenter_role,
        }
        if payee_attestation:
            chain_specific["payee_attestation"] = payee_attestation

        return self.verify_chain(receipt_reference, "lightning", chain_specific)

    def verify_tron_transaction(
        self,
        receipt_reference: str,
        tron_tx_hash: str,
        network: str = "mainnet",
    ) -> ChainVerification:
        """
        Verify a TRON TRC-20 transaction. Convenience wrapper around verify_chain.

        Requires API key.

        Args:
            receipt_reference: Unique ID (idempotency key)
            tron_tx_hash: TRON transaction hash (hex)
            network: "mainnet" or "shasta"

        Returns:
            ChainVerification result
        """
        return self.verify_chain(
            receipt_reference,
            "tron",
            {"tron_tx_hash": tron_tx_hash, "network": network},
        )

    # ── Audit Trail ───────────────────────────────────────────

    def get_activities(
        self,
        agent_did: str,
        limit: int = 50,
        since: Optional[str] = None,
    ) -> List[AuditActivity]:
        """
        Get an agent's verified activity history.

        Args:
            agent_did: The agent's DID
            limit: Max results (default 50)
            since: ISO timestamp filter

        Returns:
            List of AuditActivity objects
        """
        params: Dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since

        data = self._get(f"/audit/agent/{agent_did}/activities", params=params)
        return [
            AuditActivity(
                id=a["id"],
                credential_id=a["credential_id"],
                activity_type=a["activity_type"],
                activity_timestamp=a["activity_timestamp"],
                counterparty_did=a.get("counterparty_did"),
                transaction_rail=a.get("transaction_rail"),
                transaction_amount=a.get("transaction_amount"),
                transaction_currency=a.get("transaction_currency"),
            )
            for a in data.get("activities", [])
        ]

    def write_audit_event(
        self,
        receipt_reference: str,
        agent_id: str,
        amount: str,
        currency: str,
        category: str,
        agent_did: Optional[str] = None,
        rail: Optional[str] = None,
        settlement_tx_hash: Optional[str] = None,
    ) -> dict:
        """
        Write a verified event to the audit trail.

        Requires API key.

        Args:
            receipt_reference: Receipt UUID (idempotency key)
            agent_id: The agent's ID
            amount: Transaction amount as string
            currency: Currency code
            category: Transaction category
            agent_did: Optional agent DID
            rail: Optional rail identifier
            settlement_tx_hash: Optional settlement transaction hash

        Returns:
            Event creation result with event_id and dashboard_url
        """
        body: Dict[str, Any] = {
            "receipt_reference": receipt_reference,
            "agent": {"agent_id": agent_id},
            "transaction": {
                "amount": {"value": amount, "currency": currency},
                "category": category,
            },
        }
        if agent_did:
            body["agent"]["did"] = agent_did
        if rail:
            body["transaction"]["rail"] = rail
        if settlement_tx_hash:
            body["settlement_reference"] = {"transaction_hash": settlement_tx_hash, "rail": rail}

        return self._post("/v1/audit/verified-event", body)

    # ── VAC Extensions ────────────────────────────────────────

    def register_extension(
        self,
        extension_id: str,
        display_name: str,
        issuer_did: str,
        schema: Dict[str, Any],
        issuer_display_name: Optional[str] = None,
        issuer_domain: Optional[str] = None,
        summary_fields: Optional[List[str]] = None,
    ) -> dict:
        """
        Register a VAC extension schema.

        Requires API key.

        Namespace rules:
          - Extension ID must be prefixed with your integrator identity
          - Reserved prefixes (op_, at_, lightning_, etc.) are blocked
          - First registrant claims the namespace

        Args:
            extension_id: e.g. "myplatform_reputation_v1"
            display_name: Human-readable name
            issuer_did: Your DID (did:web:...)
            schema: JSON Schema defining the extension fields
            issuer_display_name: Optional display name
            issuer_domain: Optional domain
            summary_fields: Fields to show in VAC summary

        Returns:
            Registration result with schema_url
        """
        body: Dict[str, Any] = {
            "extension_id": extension_id,
            "display_name": display_name,
            "issuer": {"did": issuer_did},
            "schema": schema,
        }
        if issuer_display_name:
            body["issuer"]["display_name"] = issuer_display_name
        if issuer_domain:
            body["issuer"]["domain"] = issuer_domain
        if summary_fields:
            body["summary_fields"] = summary_fields

        return self._post("/v1/vac/extensions/register", body)

    def submit_extension_attestation(
        self,
        extension_id: str,
        credential: Dict[str, Any],
        summary_fields: Optional[List[str]] = None,
    ) -> dict:
        """
        Submit a pre-signed extension attestation credential.

        Requires API key. The credential must be signed by the extension
        issuer's key (issuer-direct signing — OP never touches your key).

        Args:
            extension_id: The registered extension ID
            credential: Pre-signed W3C VC (full JSON with proof)
            summary_fields: Fields to include in VAC summary

        Returns:
            Storage result with credential_id
        """
        body: Dict[str, Any] = {
            "extension_id": extension_id,
            "credential": credential,
        }
        if summary_fields:
            body["summary_fields"] = summary_fields

        return self._post("/v1/vac/extensions/attest", body)

    # ── Counterparties ────────────────────────────────────────

    def get_counterparties(self, agent_id: str, limit: int = 50) -> dict:
        """
        Get an agent's counterparty summary.

        Public view returns aggregate counts.

        Args:
            agent_id: The agent's ID
            limit: Max results

        Returns:
            Counterparty data
        """
        return self._get(f"/api/v1/agents/{agent_id}/counterparties", params={"limit": limit})

    # ── Signing Helper ────────────────────────────────────────

    @staticmethod
    def sign_challenge(private_key_hex: str, nonce: str) -> str:
        """
        Sign a challenge nonce with an Ed25519 private key.

        Convenience method for the challenge-response flow.

        Args:
            private_key_hex: Ed25519 private key (64 hex chars)
            nonce: The challenge nonce string

        Returns:
            Hex-encoded signature
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        signature = key.sign(nonce.encode("utf-8"))
        return signature.hex()

    @staticmethod
    def generate_keypair() -> tuple:
        """
        Generate a fresh Ed25519 keypair.

        Returns:
            (public_key_hex, private_key_hex) tuple
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        key = Ed25519PrivateKey.generate()
        private_hex = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        public_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        return public_hex, private_hex
