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

from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, quote

import httpx

from .models import (
    Agent, Challenge, TrustScore, Attestation, ChainVerification,
    Delegation, MagicLink, X402Credential, ERC8004Summary,
    AuditEventResult, ObserverError,
)

DEFAULT_BASE_URL = "https://api.observerprotocol.org"
DEFAULT_TIMEOUT = 30.0


class ObserverClient:
    """
    Observer Protocol API client.

    Args:
        base_url: API base URL (default: https://api.observerprotocol.org)
        api_key: API key for authenticated endpoints
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── HTTP helpers ─────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._client.get(url, params=params, headers=self._headers())
        return self._handle(resp)

    def _post(self, path: str, body: Any = None, params: Optional[Dict[str, str]] = None) -> Any:
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urlencode(params)
        resp = self._client.post(url, json=body, headers=self._headers())
        return self._handle(resp)

    def _handle(self, resp: httpx.Response) -> Any:
        if resp.status_code >= 400:
            try:
                data = resp.json()
                detail = data.get("detail", "")
                if isinstance(detail, list):
                    detail = ", ".join(d.get("msg", str(d)) for d in detail)
                elif isinstance(detail, dict):
                    detail = detail.get("detail", str(detail))
            except Exception:
                detail = f"HTTP {resp.status_code}"
            raise ObserverError(resp.status_code, str(detail))
        if resp.status_code == 204:
            return {}
        return resp.json()

    # ══════════════════════════════════════════════════════════
    # AGENT IDENTITY
    # ══════════════════════════════════════════════════════════

    def register_agent(
        self,
        public_key: str,
        agent_name: Optional[str] = None,
        alias: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> Agent:
        """Register a new agent with an Ed25519 public key."""
        params = {"public_key": public_key}
        if agent_name:
            params["agent_name"] = agent_name
        if alias:
            params["alias"] = alias
        if framework:
            params["framework"] = framework
        data = self._post("/observer/register-agent", params=params)
        return Agent.from_registration(data)

    def request_challenge(self, agent_id: str) -> Challenge:
        """Request a cryptographic challenge for key ownership verification."""
        data = self._post("/observer/challenge", params={"agent_id": agent_id})
        return Challenge(
            challenge_id=data["challenge_id"],
            nonce=data["nonce"],
            expires_at=data["expires_at"],
        )

    def verify_agent(self, agent_id: str, signed_challenge: str) -> Dict[str, Any]:
        """Submit a signed challenge to prove key ownership."""
        return self._post("/observer/verify-agent", params={
            "agent_id": agent_id,
            "signed_challenge": signed_challenge,
        })

    def get_agent(self, agent_id: str) -> Agent:
        """Get an agent's public profile."""
        data = self._get(f"/api/v1/agents/{agent_id}/profile")
        return Agent.from_profile(data)

    def get_did_document(self, agent_id: str) -> Dict[str, Any]:
        """Get an agent's W3C DID document."""
        return self._get(f"/agents/{agent_id}/did.json")

    # ══════════════════════════════════════════════════════════
    # TRUST SCORE
    # ══════════════════════════════════════════════════════════

    def get_trust_score(self, agent_id: str) -> TrustScore:
        """Get an agent's AT-ARS trust score with component breakdown."""
        data = self._get(f"/api/v1/trust/tron/score/{agent_id}")
        return TrustScore.from_response(data)

    # ══════════════════════════════════════════════════════════
    # DELEGATION
    # ══════════════════════════════════════════════════════════

    def request_delegation(
        self,
        agent_id: str,
        scope: Optional[List[str]] = None,
        rails: Optional[List[str]] = None,
        spending_limits: Optional[Dict[str, str]] = None,
        expiration: Optional[str] = None,
        attestation_tier: str = "enterprise",
        org_did: str = "did:web:observerprotocol.org",
        requested_by: str = "sdk",
    ) -> Delegation:
        """Request a new delegation credential for an agent."""
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "org_did": org_did,
            "requested_by": requested_by,
            "attestation_tier": attestation_tier,
        }
        if scope:
            body["scope"] = scope
        if rails:
            body["rails"] = rails
        if spending_limits:
            body["spending_limits"] = spending_limits
        if expiration:
            body["expiration"] = expiration
        data = self._post("/observer/request-delegation", body)
        return Delegation(
            request_id=data["request_id"],
            agent_id=agent_id,
            org_did=org_did,
            requested_by=requested_by,
            status=data.get("status", "pending_approval"),
            attestation_tier=attestation_tier,
        )

    def list_delegations(self) -> List[Delegation]:
        """List all delegation requests."""
        data = self._get("/observer/delegation-requests")
        return [Delegation.from_response(r) for r in data.get("requests", [])]

    def revoke_delegation(self, request_id: str, reason: str = "Revoked via SDK") -> Dict[str, Any]:
        """Revoke a delegation credential."""
        return self._post("/observer/revoke-delegation", {
            "request_id": request_id,
            "reason": reason,
        })

    # ══════════════════════════════════════════════════════════
    # MAGIC LINK (Chargeback Prevention Flow)
    # ══════════════════════════════════════════════════════════

    def generate_magic_link(
        self,
        agent_id: str,
        counterparty_did: str,
        counterparty_name: str,
        amount: str,
        currency: str,
        rail: str,
        purchase_description: str,
        intro: Optional[str] = None,
        ttl_minutes: int = 15,
    ) -> MagicLink:
        """Generate a magic link for human-in-the-loop authorization."""
        data = self._post("/api/v1/remediation/magic-link", {
            "agent_id": agent_id,
            "counterparty_did": counterparty_did,
            "counterparty_name": counterparty_name,
            "amount": amount,
            "currency": currency,
            "rail": rail,
            "purchase_description": purchase_description,
            "intro": intro,
            "ttl_minutes": ttl_minutes,
        })
        return MagicLink.from_response(data)

    def get_magic_link_credential(self, jti: str) -> Dict[str, Any]:
        """Poll for the credential after human approves a magic link."""
        return self._get(f"/api/v1/remediation/{jti}/credential")

    # ══════════════════════════════════════════════════════════
    # x402 VERIFICATION
    # ══════════════════════════════════════════════════════════

    def verify_x402(
        self,
        agent_id: str,
        agent_did: str,
        counterparty: str,
        amount: str,
        resource_uri: str,
        settlement_tx_hash: str,
        payment_payload: Dict[str, Any],
        payment_scheme: str = "exact",
        network: str = "eip155:8453",
        asset_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        asset_symbol: str = "USDC",
        facilitator_url: str = "https://x402.coinbase.com",
    ) -> X402Credential:
        """Verify an x402 payment and issue an X402PaymentCredential."""
        data = self._post("/api/v1/x402/verify", {
            "agent_id": agent_id,
            "agent_did": agent_did,
            "counterparty": counterparty,
            "payment_scheme": payment_scheme,
            "network": network,
            "asset_address": asset_address,
            "asset_symbol": asset_symbol,
            "amount": amount,
            "resource_uri": resource_uri,
            "facilitator_url": facilitator_url,
            "settlement_tx_hash": settlement_tx_hash,
            "payment_payload": payment_payload,
        })
        return X402Credential.from_response(data)

    def get_x402_credentials(self, agent_id: str) -> List[Dict[str, Any]]:
        """List X402PaymentCredentials for an agent."""
        data = self._get(f"/api/v1/x402/credentials/{agent_id}")
        return data.get("credentials", [])

    # ══════════════════════════════════════════════════════════
    # CHAIN VERIFICATION
    # ══════════════════════════════════════════════════════════

    def verify_chain(
        self,
        receipt_reference: str,
        chain: str,
        chain_specific: Dict[str, Any],
        transaction: Optional[Dict[str, Any]] = None,
    ) -> ChainVerification:
        """Verify a transaction on any supported chain. Requires API key."""
        body: Dict[str, Any] = {
            "receipt_reference": receipt_reference,
            "chain": chain,
            "chain_specific": chain_specific,
        }
        if transaction:
            body["transaction"] = transaction
        data = self._post("/v1/chain/verify", body)
        return ChainVerification.from_response(data)

    def verify_lightning(
        self,
        receipt_reference: str,
        payment_hash: str,
        preimage: str,
        presenter_role: str = "payee",
    ) -> ChainVerification:
        """Verify a Lightning payment. Convenience wrapper."""
        return self.verify_chain(
            receipt_reference=receipt_reference,
            chain="lightning",
            chain_specific={
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": presenter_role,
            },
        )

    def verify_tron(
        self,
        receipt_reference: str,
        tron_tx_hash: str,
        network: str = "mainnet",
    ) -> ChainVerification:
        """Verify a TRON TRC-20 transaction. Convenience wrapper."""
        return self.verify_chain(
            receipt_reference=receipt_reference,
            chain="tron",
            chain_specific={"tron_tx_hash": tron_tx_hash, "network": network},
        )

    # ══════════════════════════════════════════════════════════
    # ATTESTATIONS & VAC
    # ══════════════════════════════════════════════════════════

    def get_vac(self, agent_id: str) -> Dict[str, Any]:
        """Get an agent's Verified Agent Credential."""
        return self._get(f"/vac/{agent_id}")

    def get_attestations(self, agent_id: str) -> List[Attestation]:
        """Get attestations for an agent."""
        data = self._get(f"/vac/{agent_id}/attestations")
        return [
            Attestation(
                attestation_id=a["attestation_id"],
                partner_name=a["partner_name"],
                partner_type=a["partner_type"],
                claims=a.get("claims", {}),
                issued_at=a["issued_at"],
                credential_id=a.get("credential_id"),
                expires_at=a.get("expires_at"),
            )
            for a in data.get("attestations", [])
        ]

    # ══════════════════════════════════════════════════════════
    # AUDIT TRAIL
    # ══════════════════════════════════════════════════════════

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
    ) -> AuditEventResult:
        """Write a verified event to the audit trail. Requires API key."""
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
        data = self._post("/v1/audit/verified-event", body)
        return AuditEventResult(
            event_id=data["event_id"],
            receipt_reference=data["receipt_reference"],
            dashboard_url=data.get("dashboard_url", ""),
        )

    def get_activities(self, agent_did: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get an agent's activity history."""
        data = self._get(
            f"/audit/agent/{quote(agent_did, safe='')}/activities",
            params={"limit": str(limit)},
        )
        return data.get("activities", [])

    # ══════════════════════════════════════════════════════════
    # ERC-8004 / TRC-8004 ON-CHAIN REGISTRY
    # ══════════════════════════════════════════════════════════

    def get_8004_summary(self, agent_id: str) -> ERC8004Summary:
        """Get an agent's 8004 on-chain presence summary."""
        data = self._get(f"/api/v1/erc8004/agent/{agent_id}/summary")
        return ERC8004Summary.from_response(data)

    def resolve_8004_by_did(self, did: str) -> Dict[str, Any]:
        """Resolve an OP DID to any associated 8004 NFTs."""
        return self._get(f"/api/v1/erc8004/resolve/did/{quote(did, safe='')}")

    def resolve_8004_by_nft(self, chain: str, token_id: str) -> Dict[str, Any]:
        """Resolve an 8004 NFT to its OP DID."""
        return self._get(f"/api/v1/erc8004/resolve/nft/{chain}/{token_id}")

    def pin_registration(
        self,
        agent_id: str,
        agent_did: str,
        agent_name: str,
        description: str = "",
        image_url: str = "",
        a2a_endpoint: Optional[str] = None,
        mcp_endpoint: Optional[str] = None,
        web_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pin an 8004 registration file for an agent."""
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "agent_did": agent_did,
            "agent_name": agent_name,
            "description": description,
            "image_url": image_url,
        }
        if a2a_endpoint:
            body["a2a_endpoint"] = a2a_endpoint
        if mcp_endpoint:
            body["mcp_endpoint"] = mcp_endpoint
        if web_endpoint:
            body["web_endpoint"] = web_endpoint
        return self._post("/api/v1/erc8004/registration/pin", body)

    def get_8004_indexer_status(self) -> Dict[str, Any]:
        """Get 8004 indexer status across all chains."""
        return self._get("/api/v1/erc8004/indexer/status")

    # ══════════════════════════════════════════════════════════
    # STATIC HELPERS (Ed25519)
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def generate_keypair() -> tuple:
        """
        Generate an Ed25519 keypair.
        Returns (public_key_hex, private_key_hex).
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw().hex()
        priv = key.private_bytes_raw().hex()
        return pub, priv

    @staticmethod
    def sign_challenge(private_key_hex: str, nonce: str) -> str:
        """
        Sign a challenge nonce with an Ed25519 private key.
        Returns the signature as a hex string.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        sig = key.sign(nonce.encode("utf-8"))
        return sig.hex()
