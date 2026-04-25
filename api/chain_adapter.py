"""
ChainAdapter — Chain-agnostic verification interface.

Base class and adapter dispatch for /v1/chain/verify.
Lightning is the wedge, Stacks is designed-for, TRON is the reference.

Adding a chain = implement one adapter. No changes to the bridge,
sandbox, verify endpoint, or audit endpoint.
"""

import json
import os
import subprocess
from abc import ABC, abstractmethod
from typing import Optional


class ChainVerificationResult:
    """Chain-agnostic verification result."""

    def __init__(
        self,
        verified: bool,
        chain: str,
        transaction_reference: Optional[str] = None,
        explorer_url: Optional[str] = None,
        confirmed_at: Optional[str] = None,
        confirmations: Optional[int] = None,
        chain_specific: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        self.verified = verified
        self.chain = chain
        self.transaction_reference = transaction_reference
        self.explorer_url = explorer_url
        self.confirmed_at = confirmed_at
        self.confirmations = confirmations
        self.chain_specific = chain_specific or {}
        self.error = error

    def to_dict(self) -> dict:
        d = {
            "verified": self.verified,
            "chain": self.chain,
            "transaction_reference": self.transaction_reference,
            "explorer_url": self.explorer_url,
            "confirmed_at": self.confirmed_at,
            "confirmations": self.confirmations,
            "chain_specific": self.chain_specific,
        }
        if self.error:
            d["error"] = self.error
        return d


class ChainAdapter(ABC):
    """Abstract base for chain-specific verification adapters."""

    @property
    @abstractmethod
    def chain(self) -> str:
        """Chain identifier: 'lightning', 'stacks', 'tron'."""
        ...

    @abstractmethod
    def verify_transaction(self, transaction: dict, chain_specific: dict) -> ChainVerificationResult:
        """
        Verify a transaction on this chain.

        Args:
            transaction: Chain-agnostic envelope (reference, amount, sender, recipient)
            chain_specific: Chain-specific parameters

        Returns:
            ChainVerificationResult
        """
        ...

    @abstractmethod
    def get_explorer_url(self, transaction_reference: str) -> str:
        """Return a human-readable explorer URL for this transaction."""
        ...

    @abstractmethod
    def to_vac_extension(self, result: ChainVerificationResult) -> dict:
        """Convert verification result to VAC extension format."""
        ...


# ── TronAdapter ───────────────────────────────────────────────

class TronAdapter(ChainAdapter):
    """
    Thin wrapper around existing TronRail (rails/tron/).
    Delegates to the Node.js subprocess via the established pattern.
    """

    @property
    def chain(self) -> str:
        return "tron"

    def verify_transaction(self, transaction: dict, chain_specific: dict) -> ChainVerificationResult:
        """Verify a TRON TRC-20 transaction via TronGrid."""
        tx_hash = chain_specific.get("tron_tx_hash") or transaction.get("reference")
        if not tx_hash:
            return ChainVerificationResult(
                verified=False, chain="tron",
                error="Missing tron_tx_hash in chain_specific or reference in transaction",
            )

        # Build the VC-like structure the existing verifier expects
        receipt_vc = {
            "credentialSubject": {
                "tronTxHash": tx_hash,
                "rail": chain_specific.get("rail", "tron:trc20"),
                "asset": transaction.get("amount", {}).get("currency", "USDT"),
                "amount": transaction.get("amount", {}).get("value", "0"),
                "network": chain_specific.get("network", os.environ.get("TRON_NETWORK", "mainnet")),
            }
        }

        # Call existing Node.js verifier via subprocess
        rails_dir = os.path.join(os.path.dirname(__file__), "..", "rails", "tron")
        js_code = (
            f"import('./tron-verification.mjs')"
            f".then(m => new m.TronReceiptVerifier())"
            f".then(v => v.verifyReceipt({json.dumps(receipt_vc)}))"
            f".then(r => console.log(JSON.stringify(r)))"
            f".catch(e => {{ console.log(JSON.stringify({{error: e.message}})); process.exit(1); }})"
        )

        env = os.environ.copy()
        env["TRON_NETWORK"] = os.environ.get("TRON_NETWORK", "mainnet")

        try:
            result = subprocess.run(
                ["node", "-e", js_code],
                cwd=rails_dir,
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return ChainVerificationResult(
                verified=False, chain="tron",
                error="TRON verification timed out",
            )

        if result.returncode != 0:
            error_msg = result.stdout.strip() or result.stderr.strip()
            try:
                error_msg = json.loads(error_msg).get("error", error_msg)
            except (json.JSONDecodeError, AttributeError):
                pass
            return ChainVerificationResult(
                verified=False, chain="tron", error=error_msg,
            )

        try:
            verify_result = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return ChainVerificationResult(
                verified=False, chain="tron",
                error="Failed to parse TRON verification response",
            )

        verified = verify_result.get("verified", False)
        network = chain_specific.get("network", "mainnet")
        tronscan_base = "https://tronscan.org/#/transaction" if network == "mainnet" else f"https://{network}.tronscan.org/#/transaction"

        return ChainVerificationResult(
            verified=verified,
            chain="tron",
            transaction_reference=tx_hash,
            explorer_url=f"{tronscan_base}/{tx_hash}",
            confirmed_at=verify_result.get("timestamp"),
            confirmations=verify_result.get("confirmations"),
            chain_specific={
                "tron_tx_hash": tx_hash,
                "tron_grid_verified": verify_result.get("tronGridVerified", False),
                "signature_verified": verify_result.get("signatureValid", False),
                "receipt_hash": verify_result.get("receiptHash"),
                "network": network,
                "token_contract": chain_specific.get("token_contract"),
            },
        )

    def get_explorer_url(self, transaction_reference: str) -> str:
        network = os.environ.get("TRON_NETWORK", "mainnet")
        if network == "mainnet":
            return f"https://tronscan.org/#/transaction/{transaction_reference}"
        return f"https://{network}.tronscan.org/#/transaction/{transaction_reference}"

    def to_vac_extension(self, result: ChainVerificationResult) -> dict:
        return {
            "type": "tron_verification_v1",
            "chain": "tron",
            "receiptId": result.transaction_reference,
            "verified": result.verified,
            "transactionReference": result.transaction_reference,
            "amount": result.chain_specific.get("amount"),
            "currency": result.chain_specific.get("asset", "USDT"),
            "timestamp": result.confirmed_at,
            "chain_specific": result.chain_specific,
        }


# ── Adapter Registry ──────────────────────────────────────────

_adapters: dict = {}


def register_adapter(adapter: ChainAdapter):
    """Register an adapter for a chain."""
    _adapters[adapter.chain] = adapter


def get_adapter(chain: str) -> Optional[ChainAdapter]:
    """Get the registered adapter for a chain."""
    return _adapters.get(chain)


def get_supported_chains() -> list:
    """Return list of supported chain identifiers."""
    return list(_adapters.keys())


# Register built-in adapters
register_adapter(TronAdapter())
