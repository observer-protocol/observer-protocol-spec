#!/usr/bin/env python3
"""
VC Verifier — Observer Protocol
Real Ed25519Signature2020 verification for W3C Verifiable Credentials and
Verifiable Presentations.

Verification is never stubbed. Every call performs a real cryptographic check.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def _canonical_bytes(doc: dict) -> bytes:
    """
    Produce the canonical byte representation of a document for verification.
    The 'proof' key is excluded. Keys are sorted; no extra whitespace.
    Must match the encoding used in vc_issuer._canonical_bytes exactly.
    """
    doc_to_verify = {k: v for k, v in doc.items() if k != "proof"}
    return json.dumps(doc_to_verify, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_proof_value(proof_value: str) -> bytes:
    """
    Decode an Ed25519Signature2020 proofValue.
    Expects multibase base58btc encoding (prefix 'z').
    """
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise ValueError(
            f"proofValue must be multibase base58btc (prefix 'z'), got: {proof_value!r}"
        )
    return base58.b58decode(proof_value[1:])


def _load_public_key(public_key_hex: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a 64-hex-char (32-byte) hex string."""
    try:
        key_bytes = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise ValueError(f"public_key_hex is not valid hex: {exc}") from exc
    if len(key_bytes) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(key_bytes)}."
        )
    return Ed25519PublicKey.from_public_bytes(key_bytes)


def verify_vc(vc: dict, issuer_public_key_hex: str) -> tuple[bool, str]:
    """
    Verify the Ed25519Signature2020 proof on a W3C Verifiable Credential.

    Args:
        vc: The full VC dict including its 'proof' field.
        issuer_public_key_hex: Hex-encoded 32-byte Ed25519 public key of the issuer.

    Returns:
        (True, "ok") on success.
        (False, "<reason>") on any failure.
    """
    try:
        # --- structural checks ---
        proof = vc.get("proof")
        if not proof:
            return False, "VC is missing a proof"
        if proof.get("type") != "Ed25519Signature2020":
            return False, f"Unsupported proof type: {proof.get('type')!r}"
        proof_value = proof.get("proofValue")
        if not proof_value:
            return False, "proof.proofValue is missing"

        # --- expiration ---
        expiry_str = vc.get("expirationDate")
        if expiry_str:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expiry:
                return False, f"VC expired at {expiry_str}"

        # --- W3C conformance checks ---
        if "credentialSubject" not in vc:
            return False, "VC missing credentialSubject"
        if not vc.get("credentialSubject", {}).get("id"):
            return False, "credentialSubject.id is missing"
        if not vc.get("issuer"):
            return False, "VC missing issuer"

        # --- cryptographic verification ---
        sig_bytes = _decode_proof_value(proof_value)
        message = _canonical_bytes(vc)
        pub_key = _load_public_key(issuer_public_key_hex)
        pub_key.verify(sig_bytes, message)   # raises InvalidSignature on failure

        return True, "ok"

    except InvalidSignature:
        return False, "Ed25519 signature verification failed"
    except Exception as exc:
        return False, f"Verification error: {exc}"


def verify_vp(vp: dict, holder_public_key_hex: str) -> tuple[bool, str]:
    """
    Verify the Ed25519Signature2020 proof on a W3C Verifiable Presentation.

    The individual VCs inside the VP are NOT re-verified here; call verify_vc
    separately for each one.

    Args:
        vp: The full VP dict including its 'proof' field.
        holder_public_key_hex: Hex-encoded 32-byte Ed25519 public key of the holder.

    Returns:
        (True, "ok") on success.
        (False, "<reason>") on any failure.
    """
    try:
        proof = vp.get("proof")
        if not proof:
            return False, "VP is missing a proof"
        if proof.get("type") != "Ed25519Signature2020":
            return False, f"Unsupported proof type: {proof.get('type')!r}"
        proof_value = proof.get("proofValue")
        if not proof_value:
            return False, "proof.proofValue is missing"

        if not vp.get("holder"):
            return False, "VP missing holder"

        sig_bytes = _decode_proof_value(proof_value)
        message = _canonical_bytes(vp)
        pub_key = _load_public_key(holder_public_key_hex)
        pub_key.verify(sig_bytes, message)

        return True, "ok"

    except InvalidSignature:
        return False, "Ed25519 signature verification failed"
    except Exception as exc:
        return False, f"Verification error: {exc}"


def verify_vp_with_embedded_vcs(
    vp: dict,
    holder_public_key_hex: str,
    op_public_key_hex: str,
) -> dict:
    """
    Verify both the VP proof and every VC inside it.

    Returns a result dict:
        {
            "vp_valid": bool,
            "vp_error": str | None,
            "vc_results": [{"id": ..., "valid": bool, "error": str | None}, ...],
            "all_valid": bool,
        }
    """
    vp_ok, vp_err = verify_vp(vp, holder_public_key_hex)
    vc_results = []

    for vc in vp.get("verifiableCredential", []):
        vc_ok, vc_err = verify_vc(vc, op_public_key_hex)
        vc_results.append(
            {
                "id": vc.get("id"),
                "valid": vc_ok,
                "error": None if vc_ok else vc_err,
            }
        )

    all_valid = vp_ok and all(r["valid"] for r in vc_results)

    return {
        "vp_valid": vp_ok,
        "vp_error": None if vp_ok else vp_err,
        "vc_results": vc_results,
        "all_valid": all_valid,
    }
