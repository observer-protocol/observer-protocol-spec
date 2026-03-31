#!/usr/bin/env python3
"""
VP Builder — Observer Protocol
Assembles W3C Verifiable Presentations from one or more VCs.

Per architecture decision:
  - Agent signs the VP (authentication proof)
  - OP signs individual VCs within it (assertionMethod proof)
  - OP does NOT countersign the VP
  - holder is the presenting agent's DID

The agent's private key is required to produce a signed VP.
An unsigned VP skeleton can also be produced for inspection.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

W3C_CREDENTIALS_CONTEXT = "https://www.w3.org/2018/credentials/v1"


def _canonical_bytes(doc: dict) -> bytes:
    """
    Canonical byte representation excluding the 'proof' key.
    Must match vc_issuer._canonical_bytes and vc_verifier._canonical_bytes.
    """
    doc_to_sign = {k: v for k, v in doc.items() if k != "proof"}
    return json.dumps(doc_to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_vp(vp: dict, holder_private_key_hex: str, holder_did: str) -> dict:
    """
    Add an Ed25519Signature2020 authentication proof to the VP.
    Returns a new VP dict with the proof included.
    """
    if len(holder_private_key_hex) != 64:
        raise ValueError(
            f"holder_private_key_hex must be 64 hex chars (32 bytes), "
            f"got {len(holder_private_key_hex)}."
        )
    priv_bytes = bytes.fromhex(holder_private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    now = datetime.now(timezone.utc)
    vm_id = f"{holder_did}#key-1"

    sig_bytes = private_key.sign(_canonical_bytes(vp))
    proof_value = "z" + base58.b58encode(sig_bytes).decode("ascii")

    signed_vp = dict(vp)
    signed_vp["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": vm_id,
        "proofPurpose": "authentication",
        "proofValue": proof_value,
    }
    return signed_vp


def build_vp(
    holder_did: str,
    vcs: list,
    holder_private_key_hex: Optional[str] = None,
) -> dict:
    """
    Assemble a W3C Verifiable Presentation.

    Args:
        holder_did: The DID of the presenting agent (VP.holder).
        vcs: List of W3C VC dicts to embed in the VP.
        holder_private_key_hex: If provided, the VP is signed with the agent's
            Ed25519 private key (hex-encoded, 64 chars). If None, an unsigned
            VP is returned (useful for drafts / inspection).

    Returns:
        A W3C VP dict. Signed if holder_private_key_hex is given.
    """
    vp_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    vp: dict = {
        "@context": [W3C_CREDENTIALS_CONTEXT],
        "id": vp_id,
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": vcs,
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if holder_private_key_hex:
        vp = _sign_vp(vp, holder_private_key_hex, holder_did)

    return vp


def select_vcs_for_context(
    all_vcs: list,
    required_types: Optional[list] = None,
) -> list:
    """
    Selective disclosure: filter the VP's VC list to only the types
    relevant for a given presentation context.

    Args:
        all_vcs: All VCs the agent holds.
        required_types: VC type strings to include. If None, all are included.

    Returns:
        Filtered list of VCs.
    """
    if not required_types:
        return list(all_vcs)
    return [
        vc for vc in all_vcs
        if any(t in vc.get("type", []) for t in required_types)
    ]
