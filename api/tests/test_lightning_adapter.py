"""
Lightning Adapter Tests — Tier 1, Tier 2, and conflict resolution.

Tests the three-tier verification model with real Ed25519 signatures,
fixture LightningPaymentReceipt VCs, and mocked LND responses.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Set env to prevent DB connection attempts
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/test")

from chain_adapter import get_adapter
import lightning_adapter  # noqa — registers adapter

adapter = get_adapter("lightning")


# ── Fixture helpers ───────────────────────────────────────────

def _generate_keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def _sign_credential(credential: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign a credential dict with Ed25519, return credential with proof."""
    doc_to_sign = {k: v for k, v in credential.items() if k != "proof"}
    canonical = json.dumps(doc_to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = private_key.sign(canonical)
    proof_value = "z" + base58.b58encode(sig_bytes).decode("ascii")

    credential["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": f"{credential['issuer']}#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }
    return credential


def _make_preimage_and_hash():
    """Generate a random preimage and its SHA-256 payment hash."""
    preimage_bytes = os.urandom(32)
    preimage_hex = preimage_bytes.hex()
    payment_hash = hashlib.sha256(preimage_bytes).hexdigest()
    return preimage_hex, payment_hash


def _make_receipt_vc(preimage: str, payment_hash: str, private_key: Ed25519PrivateKey,
                     payer_did: str = "did:web:op.test:agents:payer_001",
                     payee_did: str = "did:web:op.test:agents:payee_001",
                     amount_msat: int = 10000):
    """Build and sign a complete LightningPaymentReceipt VC."""
    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://observerprotocol.org/contexts/lightning-payment-receipt/v1",
        ],
        "type": ["VerifiableCredential", "LightningPaymentReceipt"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": payee_did,
        "validFrom": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {
            "id": payer_did,
            "payment": {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "amount_msat": amount_msat,
                "currency": "BTC",
                "settled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        },
    }
    return _sign_credential(credential, private_key)


# ── Tier 1 Tests (Payee Attestation) ─────────────────────────


def test_tier1_valid_payee_attestation():
    """Tier 1: Payer presents preimage + valid payee attestation → verified."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    # Verify the attestation directly (bypass DID resolution with key override)
    assert adapter._verify_payee_attestation(
        {"credential": receipt_vc},
        payment_hash,
        {},
        public_key_override=payee_public,
    )


def test_tier1_full_verify_transaction():
    """Tier 1 end-to-end: payer presents preimage + attestation → approved."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    # Patch _verify_payee_attestation to use the test key
    # (since DID resolution won't work in test)
    original_method = adapter._verify_payee_attestation

    def patched_verify(attestation, ph, tx, **kwargs):
        return original_method(attestation, ph, tx, public_key_override=payee_public)

    with patch.object(adapter, '_verify_payee_attestation', side_effect=patched_verify):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payer",
                "payee_attestation": {"credential": receipt_vc},
            },
        )

    assert result.verified, f"Expected verified, got error: {result.error}"
    assert result.chain_specific["verification_tier"] == "payee_attestation"
    assert result.chain_specific["payee_attestation_verified"] is True


def test_tier1_tampered_attestation_rejected():
    """Tier 1: Tampered attestation (amount changed) fails signature check."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    # Tamper: change the amount after signing
    receipt_vc["credentialSubject"]["payment"]["amount_msat"] = 99999999

    assert not adapter._verify_payee_attestation(
        {"credential": receipt_vc},
        payment_hash,
        {},
        public_key_override=payee_public,
    )


def test_tier1_wrong_payment_hash_rejected():
    """Tier 1: Attestation for a different payment hash is rejected."""
    preimage, payment_hash = _make_preimage_and_hash()
    _, other_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    # Present against a different payment hash
    assert not adapter._verify_payee_attestation(
        {"credential": receipt_vc},
        other_hash,  # wrong hash
        {},
        public_key_override=payee_public,
    )


def test_tier1_wrong_key_rejected():
    """Tier 1: Attestation signed by wrong key is rejected."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, _ = _generate_keypair()
    _, wrong_public = _generate_keypair()  # different keypair

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    assert not adapter._verify_payee_attestation(
        {"credential": receipt_vc},
        payment_hash,
        {},
        public_key_override=wrong_public,  # wrong key
    )


def test_tier1_missing_required_fields_rejected():
    """Tier 1: Credential missing required schema fields is rejected."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    # Build a minimal credential missing amount_msat and settled_at
    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://observerprotocol.org/contexts/lightning-payment-receipt/v1",
        ],
        "type": ["VerifiableCredential", "LightningPaymentReceipt"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": "did:web:op.test:agents:payee",
        "validFrom": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {
            "id": "did:web:op.test:agents:payer",
            "payment": {
                "payment_hash": payment_hash,
                "preimage": preimage,
                # Missing: amount_msat, settled_at
            },
        },
    }
    credential = _sign_credential(credential, payee_private)

    # Schema validation should reject this
    assert not adapter._verify_payee_attestation(
        {"credential": credential},
        payment_hash,
        {},
        public_key_override=payee_public,
    )


# ── Tier 2 Tests (LND Query) ─────────────────────────────────


def test_tier2_lnd_settled():
    """Tier 2: LND reports settled → verified."""
    preimage, payment_hash = _make_preimage_and_hash()

    mock_lnd_response = {
        "settled": True,
        "settle_date": "1714000000",
        "amt_paid_msat": 10000,
    }

    with patch.object(adapter, '_query_lnd', return_value=mock_lnd_response):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payer",
                # No payee attestation — relying on LND
            },
        )

    assert result.verified, f"Expected verified, got: {result.error}"
    assert result.chain_specific["verification_tier"] == "lnd_query"
    assert result.chain_specific["lnd_settlement_confirmed"] is True


def test_tier2_lnd_not_settled():
    """Tier 2: LND reports not settled, no attestation → payer rejected."""
    preimage, payment_hash = _make_preimage_and_hash()

    mock_lnd_response = {
        "settled": False,
        "settle_date": None,
        "amt_paid_msat": 0,
    }

    with patch.object(adapter, '_query_lnd', return_value=mock_lnd_response):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payer",
            },
        )

    assert not result.verified
    assert "insufficient for payer" in result.error


def test_tier2_lnd_unavailable_payee_falls_to_tier3():
    """Tier 2: LND unavailable + payee presenting → falls to Tier 3."""
    preimage, payment_hash = _make_preimage_and_hash()

    # LND returns None (unavailable)
    with patch.object(adapter, '_query_lnd', return_value=None):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payee",
            },
        )

    assert result.verified
    assert result.chain_specific["verification_tier"] == "preimage_only"


# ── Conflict Resolution Tests ────────────────────────────────


def test_conflict_tier1_yes_tier2_no():
    """Conflict: Payee attests received, LND says not settled → Tier 1 wins."""
    preimage, payment_hash = _make_preimage_and_hash()
    payee_private, payee_public = _generate_keypair()

    receipt_vc = _make_receipt_vc(preimage, payment_hash, payee_private)

    mock_lnd_response = {
        "settled": False,
        "settle_date": None,
        "amt_paid_msat": 0,
    }

    # Patch both LND and attestation verification
    original_method = adapter._verify_payee_attestation

    def patched_verify(attestation, ph, tx, **kwargs):
        return original_method(attestation, ph, tx, public_key_override=payee_public)

    with patch.object(adapter, '_query_lnd', return_value=mock_lnd_response), \
         patch.object(adapter, '_verify_payee_attestation', side_effect=patched_verify):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payer",
                "payee_attestation": {"credential": receipt_vc},
            },
        )

    assert result.verified, f"Expected verified (Tier 1 wins), got: {result.error}"
    assert result.chain_specific["verification_tier"] == "payee_attestation"
    assert result.chain_specific.get("conflict_detected") is True
    assert result.chain_specific.get("lnd_sync_delay_suspected") is True
    assert result.chain_specific.get("conflict_resolution") == "tier1_wins_lnd_sync_delay"


def test_conflict_tier2_yes_tier1_invalid():
    """Conflict: LND says settled, payee attestation invalid → Tier 2 wins."""
    preimage, payment_hash = _make_preimage_and_hash()

    # Build an attestation signed with wrong key
    wrong_private, _ = _generate_keypair()
    _, payee_public = _generate_keypair()  # different key
    receipt_vc = _make_receipt_vc(preimage, payment_hash, wrong_private)

    mock_lnd_response = {
        "settled": True,
        "settle_date": "1714000000",
        "amt_paid_msat": 10000,
    }

    original_method = adapter._verify_payee_attestation

    def patched_verify(attestation, ph, tx, **kwargs):
        return original_method(attestation, ph, tx, public_key_override=payee_public)

    with patch.object(adapter, '_query_lnd', return_value=mock_lnd_response), \
         patch.object(adapter, '_verify_payee_attestation', side_effect=patched_verify):
        result = adapter.verify_transaction(
            {"amount": {"value": "0.0001", "currency": "BTC"}},
            {
                "payment_hash": payment_hash,
                "preimage": preimage,
                "presenter_role": "payer",
                "payee_attestation": {"credential": receipt_vc},
            },
        )

    assert result.verified
    assert result.chain_specific["verification_tier"] == "lnd_query"
    assert result.chain_specific.get("conflict_detected") is True
    assert result.chain_specific.get("conflict_resolution") == "tier2_wins_attestation_invalid"


# ── Run ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    test_functions = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for fn in test_functions:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
