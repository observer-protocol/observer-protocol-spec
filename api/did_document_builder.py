#!/usr/bin/env python3
"""
DID Document Builder — Observer Protocol
Builds W3C DID Documents for agents, organizations, and OP itself.
All documents use Ed25519VerificationKey2020 with multibase base58btc encoding.
"""

import os
import base58


OP_BASE_DOMAIN = os.environ.get("OP_BASE_DOMAIN", "observerprotocol.org")


def _decode_public_key_to_bytes(public_key: str) -> bytes:
    """
    Decode a public key string to raw bytes.
    Accepts hex-encoded (32 or 33 bytes) or base58-encoded input.
    Tries hex first, falls back to base58, raises ValueError only if both fail.
    """
    stripped = public_key.strip()
    hex_candidate = stripped.lower().replace("0x", "")

    # Try hex first
    if len(hex_candidate) % 2 == 0:
        try:
            return bytes.fromhex(hex_candidate)
        except ValueError:
            pass

    # Fall back to base58
    try:
        return base58.b58decode(stripped)
    except Exception:
        pass

    raise ValueError(
        f"public_key is neither valid hex nor valid base58: {public_key!r}"
    )


def encode_public_key_multibase(public_key: str) -> str:
    """
    Encode a public key as multibase base58btc (prefix 'z').
    Accepts hex-encoded or base58-encoded input.
    """
    key_bytes = _decode_public_key_to_bytes(public_key)
    return "z" + base58.b58encode(key_bytes).decode("ascii")


def decode_multibase_to_bytes(multibase_key: str) -> bytes:
    """
    Decode a multibase base58btc key (prefix 'z') to raw bytes.
    """
    if not multibase_key.startswith("z"):
        raise ValueError(
            "Only base58btc multibase encoding (prefix 'z') is supported"
        )
    return base58.b58decode(multibase_key[1:])


def build_agent_did(agent_id: str, domain: str = OP_BASE_DOMAIN) -> str:
    """Return the canonical DID string for an agent."""
    return f"did:web:{domain}:agents:{agent_id}"


def build_org_did(org_id: str, domain: str = OP_BASE_DOMAIN) -> str:
    """Return the canonical DID string for an organization."""
    return f"did:web:{domain}:orgs:{org_id}"


def build_op_did(domain: str = OP_BASE_DOMAIN) -> str:
    """Return OP's own DID string."""
    return f"did:web:{domain}"


def build_agent_did_document(
    agent_id: str,
    public_key: str,
    domain: str = OP_BASE_DOMAIN,
) -> dict:
    """
    Build a W3C DID Document for an agent.

    Args:
        agent_id: The agent's unique identifier.
        public_key: The agent's Ed25519 public key (hex or base58 encoded).
        domain: Base domain for the DID (default: observerprotocol.org).

    Returns:
        W3C-compliant DID Document dict.
    """
    did = build_agent_did(agent_id, domain)
    key_id = f"{did}#key-1"
    pubkey_multibase = encode_public_key_multibase(public_key)

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": pubkey_multibase,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def build_org_did_document(
    org_id: str,
    public_key: str,
    domain: str = OP_BASE_DOMAIN,
) -> dict:
    """
    Build a W3C DID Document for an organization.

    Args:
        org_id: The organization's unique identifier.
        public_key: The org's Ed25519 public key (hex or base58 encoded).
        domain: Base domain for the DID.

    Returns:
        W3C-compliant DID Document dict.
    """
    did = build_org_did(org_id, domain)
    key_id = f"{did}#key-1"
    pubkey_multibase = encode_public_key_multibase(public_key)

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": pubkey_multibase,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def build_op_did_document(
    public_key: str,
    domain: str = OP_BASE_DOMAIN,
) -> dict:
    """
    Build the DID Document for Observer Protocol itself.
    OP's DID is the issuer DID for all OP-signed VCs.

    Args:
        public_key: OP's Ed25519 public key (hex-encoded, 64 chars / 32 bytes).
        domain: Base domain.

    Returns:
        W3C-compliant DID Document dict.
    """
    did = build_op_did(domain)
    key_id = f"{did}#key-1"
    pubkey_multibase = encode_public_key_multibase(public_key)

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": pubkey_multibase,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }
