#!/usr/bin/env python3
"""
Observer Protocol — Register an Agent in 60 Seconds

This script demonstrates the full agent lifecycle:
  1. Generate an Ed25519 keypair
  2. Register the agent on Observer Protocol
  3. Prove key ownership via challenge-response
  4. Retrieve the agent's DID document
  5. Retrieve the Verified Agent Credential (VAC)
  6. Check the trust score

Run:
    pip install observer-protocol
    python register_agent.py

Your agent will be live on Observer Protocol with a public profile at:
    https://app.agenticterminal.io/sovereign/agents/<your_agent_id>
"""

from observer_protocol import ObserverClient


def main():
    client = ObserverClient()

    # ── Step 1: Generate a keypair ────────────────────────────
    print("Generating Ed25519 keypair...")
    public_key, private_key = ObserverClient.generate_keypair()
    print(f"  Public key:  {public_key[:32]}...")
    print(f"  Private key: {private_key[:16]}... (keep this secret!)")
    print()

    # ── Step 2: Register on Observer Protocol ─────────────────
    print("Registering agent on Observer Protocol...")
    agent = client.register_agent(
        public_key=public_key,
        agent_name="My First Agent",
    )
    print(f"  Agent ID:  {agent.agent_id}")
    print(f"  Agent DID: {agent.agent_did}")
    print()

    # ── Step 3: Prove key ownership ───────────────────────────
    print("Requesting verification challenge...")
    challenge = client.request_challenge(agent.agent_id)
    print(f"  Nonce: {challenge.nonce[:32]}...")

    print("Signing challenge...")
    signature = ObserverClient.sign_challenge(private_key, challenge.nonce)
    print(f"  Signature: {signature[:32]}...")

    print("Submitting verification...")
    result = client.verify_agent(agent.agent_id, signature)
    print(f"  Verified: {result.get('verified', False)}")
    print()

    # ── Step 4: Retrieve DID document ─────────────────────────
    print("Fetching DID document...")
    did_doc = client.get_did_document(agent.agent_id)
    print(f"  DID: {did_doc['id']}")
    print(f"  Verification method: {did_doc['verificationMethod'][0]['type']}")
    print()

    # ── Step 5: Retrieve VAC ──────────────────────────────────
    print("Fetching Verified Agent Credential (VAC)...")
    vac = client.get_vac(agent.agent_id)
    print(f"  VAC holder: {vac.holder}")
    print(f"  Credentials: {len(vac.credentials)}")
    print()

    # ── Step 6: Check trust score ─────────────────────────────
    print("Checking trust score...")
    try:
        score = client.get_trust_score(agent.agent_id)
        print(f"  AT-ARS Score: {score.trust_score}/100")
        if score.components:
            print(f"  Components:")
            print(f"    Transactions:   {score.components.receipt_score}")
            print(f"    Counterparties: {score.components.counterparty_score}")
            print(f"    Recency:        {score.components.recency_score}")
    except Exception:
        print("  Score: 0 (new agent, no transaction history yet)")
    print()

    # ── Done ──────────────────────────────────────────────────
    print("=" * 60)
    print("Your agent is live on Observer Protocol!")
    print()
    print(f"  DID document: https://api.observerprotocol.org/agents/{agent.agent_id}/did.json")
    print(f"  Public profile: https://app.agenticterminal.io/sovereign/agents/{agent.agent_id}")
    print(f"  VAC: https://api.observerprotocol.org/vac/{agent.agent_id}")
    print()
    print("Save your private key — you'll need it to sign future transactions:")
    print(f"  {private_key}")
    print()
    print("Next steps:")
    print("  - Submit verified transactions to build your trust score")
    print("  - Get attestations from partners (KYB, compliance)")
    print("  - Register VAC extensions for your own reputation data")
    print("  - See the developer guide: https://github.com/observer-protocol/observer-protocol-spec/tree/master/docs/developer-guide")


if __name__ == "__main__":
    main()
