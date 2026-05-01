#!/usr/bin/env python3
"""
Observer Protocol x LightningProx Demo

Demonstrates OP-verified agent identity on every LightningProx inference call.
Zero changes required on LightningProx's side — the attestation travels as a
custom header that LightningProx ignores. The audit trail lives locally.

Usage:
    export LIGHTNINGPROX_TOKEN="your_spend_token"
    python demo.py

    # Or with a custom prompt:
    python demo.py "Explain Bitcoin in one sentence"

Requirements:
    pip install httpx cryptography observer-protocol
"""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Configuration ────────────────────────────────────────────

LIGHTNINGPROX_URL = "https://lightningprox.com/api/ask_ai"
LIGHTNINGPROX_TOKEN = os.environ.get("LIGHTNINGPROX_TOKEN", "")

# Agent identity (Maxi — OP's reference agent)
AGENT_ID = "d13cdfceaa8f895afe56dc902179d279"
AGENT_DID = "did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279"

# Signing key — generate fresh if not provided
SIGNING_KEY_HEX = os.environ.get("OP_AGENT_KEY", "")

AUDIT_LOG = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")
OP_API = "https://api.observerprotocol.org"


# ── Ed25519 Helpers ──────────────────────────────────────────

def load_or_generate_key(key_hex: str) -> tuple:
    """Load an Ed25519 key from hex, or generate a new one."""
    if key_hex:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    else:
        priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    priv_hex = priv.private_bytes_raw().hex()
    return priv, pub, priv_hex


def sign_attestation(private_key: Ed25519PrivateKey, payload: dict) -> str:
    """Sign a JSON payload with Ed25519. Returns hex signature."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = private_key.sign(canonical.encode("utf-8"))
    return sig.hex()


# ── Attestation Builder ─────────────────────────────────────

def build_attestation(
    agent_did: str,
    public_key_hex: str,
    private_key: Ed25519PrivateKey,
    prompt: str,
    counterparty: str = "lightningprox.com",
) -> dict:
    """
    Build a signed agent attestation for a LightningProx call.

    This is a lightweight W3C VC-shaped credential that proves:
    - Which agent is making the call
    - The agent's DID (resolvable, cryptographically verifiable)
    - What the agent is requesting
    - When the request was made
    - Ed25519 signature binding it all together
    """
    now = datetime.now(timezone.utc).isoformat()
    attestation_id = f"urn:uuid:{uuid.uuid4()}"

    payload = {
        "id": attestation_id,
        "type": "AgentInferenceAttestation",
        "agent_did": agent_did,
        "counterparty": counterparty,
        "action": "ask_ai",
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "timestamp": now,
        "public_key": public_key_hex,
    }

    signature = sign_attestation(private_key, payload)

    return {
        **payload,
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"{agent_did}#key-1",
            "signature": signature,
        },
    }


# ── LightningProx Call ───────────────────────────────────────

def call_lightningprox(
    prompt: str,
    token: str,
    attestation: dict,
) -> dict:
    """
    Make an ask_ai call to LightningProx with the OP attestation
    as a custom header. LightningProx ignores the header — zero
    integration required on their side.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Observer-Agent-DID": attestation["agent_did"],
        "X-Observer-Attestation": json.dumps(attestation, separators=(",", ":")),
    }

    body = {
        "token": token,
        "prompt": prompt,
    }

    resp = httpx.post(LIGHTNINGPROX_URL, json=body, headers=headers, timeout=30)
    return resp.json()


# ── Audit Log ────────────────────────────────────────────────

def log_to_audit(attestation: dict, response: dict, prompt: str):
    """Append the attestation + response to local audit log."""
    entry = {
        "timestamp": attestation["timestamp"],
        "attestation_id": attestation["id"],
        "agent_did": attestation["agent_did"],
        "action": "ask_ai",
        "prompt_hash": attestation["prompt_hash"],
        "counterparty": attestation["counterparty"],
        "response_status": "success" if response.get("response") else "error",
        "response_length": len(response.get("response", "")),
        "signature": attestation["proof"]["signature"][:32] + "...",
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


# ── Main ─────────────────────────────────────────────────────

def main():
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "What is Observer Protocol?"

    if not LIGHTNINGPROX_TOKEN:
        print("Error: Set LIGHTNINGPROX_TOKEN environment variable")
        print("  export LIGHTNINGPROX_TOKEN='your_spend_token'")
        sys.exit(1)

    # Load or generate signing key
    priv_key, pub_hex, priv_hex = load_or_generate_key(SIGNING_KEY_HEX)

    print("=" * 60)
    print("Observer Protocol x LightningProx Demo")
    print("=" * 60)
    print(f"Agent:    {AGENT_DID}")
    print(f"Key:      {pub_hex[:16]}...{pub_hex[-8:]}")
    print(f"Prompt:   {prompt[:60]}{'...' if len(prompt) > 60 else ''}")
    print()

    # Build signed attestation
    attestation = build_attestation(
        agent_did=AGENT_DID,
        public_key_hex=pub_hex,
        private_key=priv_key,
        prompt=prompt,
    )
    print(f"[1] Attestation signed: {attestation['id']}")
    print(f"    Proof: {attestation['proof']['signature'][:32]}...")
    print()

    # Call LightningProx with attestation header
    print(f"[2] Calling LightningProx ask_ai...")
    response = call_lightningprox(prompt, LIGHTNINGPROX_TOKEN, attestation)

    if response.get("response"):
        print(f"    Response: {response['response'][:200]}{'...' if len(response.get('response','')) > 200 else ''}")
    elif response.get("error"):
        print(f"    Error: {response['error']}")
    else:
        print(f"    Raw: {json.dumps(response)[:200]}")
    print()

    # Log to audit trail
    entry = log_to_audit(attestation, response, prompt)
    print(f"[3] Audit log entry saved to {AUDIT_LOG}")
    print(f"    {json.dumps(entry, indent=2)}")
    print()
    print("=" * 60)
    print("The attestation header proves which agent made this call.")
    print("LightningProx didn't need to change anything.")
    print(f"DID Document: {OP_API}/agents/{AGENT_ID}/did.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
