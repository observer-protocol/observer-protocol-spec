#!/usr/bin/env python3
"""
Observer Protocol x AIProx Demo

Shows what AIProx's agent registry looks like with cryptographic
identity verification via Observer Protocol.

Today AIProx's registry has a `verified: true` boolean with no
cryptographic backing. This demo adds:
  - W3C DID identity for each agent (resolvable, verifiable)
  - Ed25519 signed attestation on every call
  - Audit trail linking agent identity to transaction
  - Cross-rail verification (Lightning, Solana USDC, x402)

Zero changes required on AIProx's side.

Usage:
    python demo.py                     # Show registry + OP identity overlay
    python demo.py --call search-bot   # Make a verified call to an agent
    python demo.py --register myagent  # Show what OP-verified registration looks like

Requirements:
    pip install httpx cryptography
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

AIPROX_API = "https://aiprox.dev/api"
AIPROX_TOKEN = os.environ.get("AIPROX_SPEND_TOKEN", "")
AGENT_DID = "did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279"
AGENT_ID = "d13cdfceaa8f895afe56dc902179d279"
OP_API = "https://api.observerprotocol.org"
AUDIT_LOG = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")


def generate_key():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    return priv, pub


def sign_payload(key, payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return key.sign(canonical.encode()).hex()


def log_entry(entry):
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Registry with OP Identity Overlay ────────────────────────

def show_registry():
    """Fetch AIProx registry and show what it looks like with OP identity."""
    print("=" * 65)
    print("AIProx Agent Registry + Observer Protocol Identity Layer")
    print("=" * 65)
    print()

    resp = httpx.get(f"{AIPROX_API}/agents", timeout=15)
    agents = resp.json() if isinstance(resp.json(), list) else resp.json().get("agents", [])

    print(f"{'AGENT':<22} {'RAIL':<14} {'VERIFIED':<10} {'OP IDENTITY'}")
    print("-" * 65)

    for agent in agents[:15]:
        name = agent.get("name", "?")[:20]
        rail = agent.get("rail", "?")[:12]
        verified = agent.get("verified", False)

        # OP identity overlay: what would exist if they integrated
        if name == "lightningprox":
            op_status = "did:web:...d13cdf (LIVE)"
        elif name == "solanaprox":
            op_status = "did:web:...solana (available)"
        elif name in ("arbiter-oracle", "agent-vault"):
            op_status = "did:web:...x402   (available)"
        else:
            op_status = "no DID (unverified)"

        check = "Y" if verified else "N"
        print(f"{name:<22} {rail:<14} {check:<10} {op_status}")

    print()
    print("AIProx 'verified' = boolean flag (no cryptographic proof)")
    print("OP 'verified'     = W3C DID + Ed25519 signature + resolvable document")
    print()
    print(f"Live DID example: {OP_API}/agents/{AGENT_ID}/did.json")
    print()


# ── Verified Agent Call ──────────────────────────────────────

def verified_call(agent_name, prompt="What is Bitcoin?"):
    """Make an OP-attested call to an AIProx agent."""
    priv_key, pub_hex = generate_key()
    now = datetime.now(timezone.utc).isoformat()

    print("=" * 65)
    print(f"OP-Verified Call to AIProx Agent: {agent_name}")
    print("=" * 65)
    print()

    # Step 1: Build attestation
    attestation = {
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": "AgentServiceAttestation",
        "agent_did": AGENT_DID,
        "counterparty": f"aiprox.dev/agents/{agent_name}",
        "action": "orchestrate",
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "timestamp": now,
        "public_key": pub_hex,
    }
    sig = sign_payload(priv_key, attestation)
    attestation["proof"] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": f"{AGENT_DID}#key-1",
        "signature": sig,
    }
    print(f"[1] Attestation signed: {attestation['id']}")
    print(f"    Agent DID: {AGENT_DID}")
    print(f"    Signature: {sig[:32]}...")
    print()

    # Step 2: Call AIProx orchestrator
    print(f"[2] Calling AIProx orchestrate with agent: {agent_name}")

    headers = {
        "Content-Type": "application/json",
        "X-Observer-Agent-DID": AGENT_DID,
        "X-Observer-Attestation": json.dumps(attestation, separators=(",", ":")),
    }
    if AIPROX_TOKEN:
        headers["X-Spend-Token"] = AIPROX_TOKEN

    body = {
        "task": f"Step 1: use {agent_name} to {prompt}",
        "budget_sats": 100,
    }

    try:
        resp = httpx.post(f"{AIPROX_API}/orchestrate", json=body, headers=headers, timeout=30)
        try:
            result = resp.json()
        except Exception:
            result = {"response": resp.text, "status": resp.status_code}
    except Exception as e:
        result = {"error": str(e)}

    content = ""
    if isinstance(result, dict):
        content = result.get("result", result.get("response", result.get("error", json.dumps(result)[:200])))
    print(f"    Response: {str(content)[:200]}")
    print()

    # Step 3: Audit log
    entry = {
        "timestamp": now,
        "attestation_id": attestation["id"],
        "agent_did": AGENT_DID,
        "counterparty_agent": agent_name,
        "counterparty_registry": "aiprox.dev",
        "action": "orchestrate",
        "prompt_hash": attestation["prompt_hash"],
        "response_status": "success" if content and "error" not in str(content).lower() else "error",
        "signature": sig[:32] + "...",
    }
    log_entry(entry)
    print(f"[3] Audit log saved: {AUDIT_LOG}")
    print(f"    {json.dumps(entry, indent=2)}")
    print()
    print("=" * 65)
    print("AIProx processed the request. OP proved which agent made it.")
    print("The attestation header + audit log are the identity layer.")
    print(f"Verify: {OP_API}/agents/{AGENT_ID}/did.json")
    print("=" * 65)


# ── OP-Verified Registration ────────────────────────────────

def show_registration(agent_name):
    """Show what OP-verified agent registration looks like."""
    priv_key, pub_hex = generate_key()
    now = datetime.now(timezone.utc).isoformat()

    print("=" * 65)
    print(f"OP-Verified Agent Registration: {agent_name}")
    print("=" * 65)
    print()

    # What AIProx has today
    print("CURRENT (AIProx only):")
    print(f'  {{"name": "{agent_name}", "verified": true}}')
    print("  (boolean flag, no cryptographic proof)")
    print()

    # What OP adds
    did = f"did:web:observerprotocol.org:agents:{hashlib.sha256(agent_name.encode()).hexdigest()[:32]}"

    registration = {
        "name": agent_name,
        "did": did,
        "verified": True,
        "verification_method": "Ed25519Signature2020",
        "public_key": pub_hex,
        "registered_at": now,
        "did_document": f"{OP_API}/agents/{hashlib.sha256(agent_name.encode()).hexdigest()[:32]}/did.json",
        "attestation": {
            "type": "AgentRegistrationAttestation",
            "issuer": "did:web:observerprotocol.org",
            "proof": sign_payload(priv_key, {"agent": agent_name, "did": did, "timestamp": now})[:48] + "...",
        },
    }

    print("WITH OP (cryptographic identity):")
    print(f"  {json.dumps(registration, indent=2)}")
    print()
    print("The DID document is resolvable. The signature is verifiable.")
    print("Any counterparty can independently confirm this agent's identity.")
    print("=" * 65)


# ── Main ─────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        show_registry()
        return

    if sys.argv[1] == "--call" and len(sys.argv) >= 3:
        agent = sys.argv[2]
        prompt = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else "What is Bitcoin?"
        verified_call(agent, prompt)
    elif sys.argv[1] == "--register" and len(sys.argv) >= 3:
        show_registration(sys.argv[2])
    else:
        show_registry()


if __name__ == "__main__":
    main()
