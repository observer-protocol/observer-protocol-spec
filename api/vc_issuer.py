#!/usr/bin/env python3
"""
VC Issuer — Observer Protocol
Issues W3C Verifiable Credentials signed with OP's Ed25519 key.

Every VC produced here satisfies:
  - @context includes W3C credentials v1 and OP context
  - issuer is OP's DID string
  - credentialSubject.id is the subject's DID string
  - proof uses Ed25519Signature2020 with a real signature
  - Optional fields are omitted entirely (never null)
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OP_CONTEXT = "https://observerprotocol.org/context/v1"
W3C_CREDENTIALS_CONTEXT = "https://www.w3.org/2018/credentials/v1"


def _load_op_signing_key() -> Ed25519PrivateKey:
    """Load OP's Ed25519 signing key from OP_SIGNING_KEY env var."""
    key_hex = os.environ.get("OP_SIGNING_KEY")
    if not key_hex:
        raise RuntimeError("OP_SIGNING_KEY environment variable is not set.")
    if len(key_hex) != 64:
        raise RuntimeError(
            f"OP_SIGNING_KEY must be exactly 64 hex characters (32 bytes), got {len(key_hex)}."
        )
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))


def _op_did() -> str:
    """Return OP's DID from OP_DID env var."""
    did = os.environ.get("OP_DID")
    if not did:
        raise RuntimeError("OP_DID environment variable is not set.")
    return did


def _canonical_bytes(doc: dict) -> bytes:
    """
    Produce the canonical byte representation of a document for signing.
    The 'proof' key is excluded. Keys are sorted; no extra whitespace.
    """
    doc_to_sign = {k: v for k, v in doc.items() if k != "proof"}
    return json.dumps(doc_to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_bytes(message: bytes) -> str:
    """
    Sign message bytes with OP's Ed25519 key.
    Returns a multibase base58btc proof value (prefix 'z').
    """
    key = _load_op_signing_key()
    sig_bytes = key.sign(message)
    return "z" + base58.b58encode(sig_bytes).decode("ascii")


def issue_vc(
    subject_did: str,
    credential_type: str,
    claims: dict,
    expiration_days: Optional[int] = None,
    extra_types: Optional[list] = None,
) -> dict:
    """
    Issue a W3C Verifiable Credential signed by OP.

    Args:
        subject_did: The DID of the credential subject (credentialSubject.id).
        credential_type: A string type name, e.g. "AgentActivityCredential".
        claims: A dict of claims to embed in credentialSubject (besides 'id').
        expiration_days: If given, sets expirationDate this many days from now.
        extra_types: Additional type strings beyond VerifiableCredential.

    Returns:
        A W3C VC dict with a real Ed25519Signature2020 proof.
    """
    now = datetime.now(timezone.utc)
    credential_id = f"urn:uuid:{uuid.uuid4()}"
    op_did = _op_did()
    vm_id = f"{op_did}#key-1"

    vc_types = ["VerifiableCredential", credential_type]
    if extra_types:
        vc_types.extend(t for t in extra_types if t not in vc_types)

    credential_subject = {"id": subject_did}
    credential_subject.update(claims)

    vc: dict = {
        "@context": [W3C_CREDENTIALS_CONTEXT, OP_CONTEXT],
        "id": credential_id,
        "type": vc_types,
        "issuer": op_did,
        "issuanceDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": credential_subject,
    }

    if expiration_days is not None:
        expiry = now + timedelta(days=expiration_days)
        vc["expirationDate"] = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build and sign the proof
    proof_value = _sign_bytes(_canonical_bytes(vc))

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": vm_id,
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }

    return vc
