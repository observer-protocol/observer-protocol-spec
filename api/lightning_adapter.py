"""
LightningAdapter — Lightning Network verification for OP.

Three-tier verification model with explicit payer/payee asymmetry:
  Tier 1: Payee attestation (LightningPaymentReceipt VC) — strongest
  Tier 2: LND node query — medium
  Tier 3: Preimage only — weakest, payee-only

Key rule: preimage alone from a payer is REJECTED.
Payer-side verification requires payee attestation (Tier 1) or LND evidence (Tier 2).

See CHAIN-ADAPTER-SPEC.md for full rationale and conflict resolution rules.
"""

import hashlib
import json
import os
import ssl
from datetime import datetime, timezone
from typing import Optional

import base58

from chain_adapter import ChainAdapter, ChainVerificationResult


class LightningAdapter(ChainAdapter):

    @property
    def chain(self) -> str:
        return "lightning"

    def verify_transaction(self, transaction: dict, chain_specific: dict) -> ChainVerificationResult:
        """
        Verify a Lightning payment using the three-tier model.

        Required in chain_specific:
          - payment_hash (hex)
          - preimage (hex)
          - presenter_role: "payer" | "payee"

        Optional:
          - payee_attestation: { credential: <signed W3C VC> }
          - bolt11_invoice: "lnbc..."
          - node_pubkey: "<hex>"
        """
        payment_hash = chain_specific.get("payment_hash")
        preimage = chain_specific.get("preimage")
        presenter_role = chain_specific.get("presenter_role")

        if not payment_hash or not preimage:
            return ChainVerificationResult(
                verified=False, chain="lightning",
                error="Missing required fields: payment_hash and preimage",
            )

        if presenter_role not in ("payer", "payee"):
            return ChainVerificationResult(
                verified=False, chain="lightning",
                error="presenter_role must be 'payer' or 'payee'",
            )

        # Step 1: Verify preimage hashes to payment_hash (mandatory for all tiers)
        preimage_valid = self._verify_preimage(preimage, payment_hash)
        if not preimage_valid:
            return ChainVerificationResult(
                verified=False, chain="lightning",
                error="Preimage does not hash to payment_hash",
                chain_specific={"payment_hash": payment_hash, "preimage_verified": False},
            )

        # Step 2: Determine verification tier
        payee_attestation = chain_specific.get("payee_attestation")
        lnd_result = self._query_lnd(payment_hash)

        tier = None
        tier1_verified = False
        tier2_verified = False
        conflict_info = {}

        # Tier 1: Payee attestation
        if payee_attestation and presenter_role == "payer":
            tier1_verified = self._verify_payee_attestation(
                payee_attestation, payment_hash, transaction
            )
            if tier1_verified:
                tier = "payee_attestation"

        # Tier 2: LND query
        if lnd_result is not None:
            tier2_verified = lnd_result.get("settled", False)
            if tier2_verified and tier is None:
                tier = "lnd_query"

        # Tier 3: Preimage only (payee-side only)
        if tier is None and presenter_role == "payee":
            tier = "preimage_only"

        # Conflict resolution (Tier 1 yes, Tier 2 no)
        if tier1_verified and lnd_result is not None and not tier2_verified:
            # Tier 1 wins — LND sync delay suspected
            tier = "payee_attestation"
            conflict_info = {
                "conflict_detected": True,
                "conflict_resolution": "tier1_wins_lnd_sync_delay",
                "lnd_sync_delay_suspected": True,
            }

        # Reverse conflict (Tier 2 yes, Tier 1 no)
        if tier2_verified and payee_attestation and not tier1_verified:
            # Tier 2 stands independently — payee attestation invalid or absent
            tier = "lnd_query"
            if payee_attestation:
                conflict_info = {
                    "conflict_detected": True,
                    "conflict_resolution": "tier2_wins_attestation_invalid",
                }

        # Rejection: payer with preimage only (no attestation, no LND)
        if tier is None and presenter_role == "payer":
            return ChainVerificationResult(
                verified=False, chain="lightning",
                error="Payer-side verification requires payee attestation (Tier 1) or LND node evidence (Tier 2). Preimage alone is insufficient for payer.",
                chain_specific={
                    "payment_hash": payment_hash,
                    "preimage_verified": True,
                    "presenter_role": "payer",
                    "verification_tier": None,
                },
            )

        # Build result
        amount_msat = None
        if lnd_result and lnd_result.get("amt_paid_msat"):
            amount_msat = lnd_result["amt_paid_msat"]
        elif transaction.get("amount", {}).get("value"):
            # Convert from BTC to msat if needed
            try:
                btc_val = float(transaction["amount"]["value"])
                amount_msat = int(btc_val * 100_000_000_000)  # BTC to msat
            except (ValueError, TypeError):
                pass

        settled_at = None
        if lnd_result and lnd_result.get("settle_date"):
            settled_at = lnd_result["settle_date"]
        else:
            settled_at = datetime.now(timezone.utc).isoformat()

        result_specific = {
            "payment_hash": payment_hash,
            "preimage_verified": True,
            "verification_tier": tier,
            "payee_attestation_verified": tier1_verified,
            "lnd_settlement_confirmed": tier2_verified if lnd_result is not None else None,
            "amount_msat": amount_msat,
            "settled_at": settled_at,
            "presenter_role": presenter_role,
        }
        result_specific.update(conflict_info)

        return ChainVerificationResult(
            verified=True,
            chain="lightning",
            transaction_reference=payment_hash,
            explorer_url=self.get_explorer_url(chain_specific.get("node_pubkey", payment_hash)),
            confirmed_at=settled_at,
            chain_specific=result_specific,
        )

    def get_explorer_url(self, reference: str) -> str:
        return f"https://mempool.space/lightning/node/{reference}"

    def to_vac_extension(self, result: ChainVerificationResult) -> dict:
        cs = result.chain_specific
        return {
            "type": "lightning_verification_v1",
            "chain": "lightning",
            "receiptId": result.transaction_reference,
            "verified": result.verified,
            "transactionReference": result.transaction_reference,
            "amount_msat": cs.get("amount_msat"),
            "currency": "BTC",
            "timestamp": result.confirmed_at,
            "chain_specific": {
                "payment_hash": cs.get("payment_hash"),
                "verification_tier": cs.get("verification_tier"),
                "payee_attestation_verified": cs.get("payee_attestation_verified"),
                "lnd_settlement_confirmed": cs.get("lnd_settlement_confirmed"),
            },
        }

    # ── Internal methods ──────────────────────────────────────

    def _verify_preimage(self, preimage_hex: str, payment_hash_hex: str) -> bool:
        """Verify SHA256(preimage) == payment_hash."""
        try:
            preimage_bytes = bytes.fromhex(preimage_hex)
            expected_hash = hashlib.sha256(preimage_bytes).hexdigest()
            return expected_hash == payment_hash_hex.lower()
        except (ValueError, TypeError):
            return False

    def _query_lnd(self, payment_hash: str) -> Optional[dict]:
        """
        Query LND for invoice settlement status.
        Returns None if LND is not configured.
        Returns dict with {settled, settle_date, amt_paid_msat} if available.
        """
        lnd_host = os.environ.get("LND_HOST")
        macaroon_path = os.environ.get("LND_MACAROON_PATH")

        if not lnd_host or not macaroon_path:
            return None

        try:
            with open(macaroon_path, "rb") as f:
                macaroon = f.read().hex()
        except (FileNotFoundError, PermissionError):
            return None

        # LND REST API: lookup invoice by payment hash
        import urllib.request

        url = f"https://{lnd_host}/v1/invoice/{payment_hash}"
        req = urllib.request.Request(url)
        req.add_header("Grpc-Metadata-macaroon", macaroon)

        tls_cert_path = os.environ.get("LND_TLS_CERT_PATH")
        ctx = None
        if tls_cert_path:
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(tls_cert_path)

        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                data = json.loads(resp.read())
                return {
                    "settled": data.get("state") == "SETTLED" or data.get("settled", False),
                    "settle_date": data.get("settle_date"),
                    "amt_paid_msat": int(data.get("amt_paid_msat", 0)),
                }
        except Exception:
            # LND unreachable — return None (not an error, just unavailable)
            return None

    def _verify_payee_attestation(
        self, attestation: dict, payment_hash: str, transaction: dict,
        public_key_override=None,
    ) -> bool:
        """
        Verify a LightningPaymentReceipt VC from the payee.

        Checks:
        1. Schema validation (Pydantic — required fields, types, hex format)
        2. Payment hash matches the request
        3. Preimage in credential hashes to payment_hash
        4. Ed25519 signature valid against issuer DID

        Args:
            public_key_override: Ed25519PublicKey to use instead of DID resolution.
                Used in testing when DID endpoint isn't available.
        """
        credential = attestation.get("credential")
        if not credential:
            return False

        # 1. Schema validation
        from schemas.lightning_payment_receipt import validate_lightning_receipt
        valid, error, parsed = validate_lightning_receipt(credential)
        if not valid:
            return False

        # 2. Payment hash matches
        if parsed.credentialSubject.payment.payment_hash != payment_hash.lower():
            return False

        # 3. Preimage verification
        if not self._verify_preimage(
            parsed.credentialSubject.payment.preimage,
            payment_hash,
        ):
            return False

        # 4. Ed25519 signature verification
        proof = credential.get("proof")
        if not proof or proof.get("type") != "Ed25519Signature2020":
            return False

        proof_value = proof.get("proofValue", "")
        if not proof_value.startswith("z"):
            return False

        doc_to_verify = {k: v for k, v in credential.items() if k != "proof"}
        canonical = json.dumps(doc_to_verify, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Resolve public key (or use override for testing)
        if public_key_override:
            public_key = public_key_override
        else:
            issuer_did = credential.get("issuer")
            if isinstance(issuer_did, dict):
                issuer_did = issuer_did.get("id")
            if not issuer_did:
                return False
            public_key = self._resolve_issuer_key(issuer_did)
            if not public_key:
                return False

        try:
            sig_bytes = base58.b58decode(proof_value[1:])
            public_key.verify(sig_bytes, canonical)
            return True
        except Exception:
            return False

    def _resolve_issuer_key(self, issuer_did: str):
        """
        Resolve an issuer's Ed25519 public key from their DID document.
        Returns Ed25519PublicKey or None.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        # Try local resolution via did:web
        # did:web:domain:path → https://domain/path/did.json
        if not issuer_did.startswith("did:web:"):
            return None

        parts = issuer_did[8:].split(":")
        domain = parts[0]
        path = "/".join(parts[1:]) if len(parts) > 1 else ""

        url = f"https://{domain}/{path}/did.json" if path else f"https://{domain}/.well-known/did.json"

        try:
            import urllib.request
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                did_doc = json.loads(resp.read())

            # Find the first Ed25519 verification method
            for vm in did_doc.get("verificationMethod", []):
                if vm.get("type") == "Ed25519VerificationKey2020":
                    multibase = vm.get("publicKeyMultibase", "")
                    if multibase.startswith("z"):
                        raw = base58.b58decode(multibase[1:])
                        # Strip multicodec prefix (0xed01)
                        if raw[:2] == b"\xed\x01":
                            raw = raw[2:]
                        return Ed25519PublicKey.from_public_bytes(raw)
        except Exception:
            pass

        return None


# Register with adapter registry
from chain_adapter import register_adapter
register_adapter(LightningAdapter())
