#!/usr/bin/env python3
"""
OWS Demo Agent Registration Script

Registers a live OWS-provisioned agent on Observer Protocol mainnet.
This script demonstrates the complete OWS registration flow.

Usage:
    export DATABASE_URL="postgresql://observer:observer@localhost/observer_protocol"
    python demo/register_ows_demo_agent.py

The demo agent will be registered with:
- OWS key format (Ed25519 derived from BIP-44 path m/44'/501'/0'/0')
- Multi-chain support (evm, solana, bitcoin)
- Live VAC at /vac/ows-demo-agent
"""

import os
import sys
import json
import hashlib
import base58
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from main import register_agent, get_agent_by_id, get_db_connection

# Demo agent configuration
DEMO_AGENT = {
    "agent_id": "ows-demo-agent",
    "alias": "OWS Demo Agent",
    "wallet_standard": "ows",
    "ows_vault_name": "agent-treasury-demo",
    "chains": ["evm", "solana", "bitcoin"],
    # Ed25519 public key (base58) - derived from m/44'/501'/0'/0'
    # This is a demo key - in production, derive from actual OWS vault
    "public_key": "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH",
    # Solana address derived from same key
    "solana_address": "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
}


def check_demo_agent_exists() -> bool:
    """Check if demo agent already exists"""
    agent = get_agent_by_id(DEMO_AGENT["agent_id"])
    return agent is not None


def create_demo_attestation():
    """Create a demo attestation for the agent"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if attestation already exists
            cur.execute(
                "SELECT id FROM attestations WHERE agent_id = %s LIMIT 1",
                (DEMO_AGENT["agent_id"],)
            )
            if cur.fetchone():
                print("  ℹ️  Demo attestation already exists")
                return

            # Create demo attestation
            attestation_id = hashlib.sha256(
                f"demo-tx:{DEMO_AGENT['agent_id']}:{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:32]

            cur.execute("""
                INSERT INTO attestations
                (attestation_id, agent_id, protocol, tx_signature, sender_address,
                 recipient_address, amount_lamports, token_mint, verified, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (
                attestation_id,
                DEMO_AGENT["agent_id"],
                "solana",
                "5UfDuLhVW7fR1QFiRNTG9n2ES9L9yV8q7W8G9V9s8v7u6t5r4e3w2q1z2x3c4v5b6n7m8k9j0h1g2f3d4s5a6p7o8i9u0y8t7r6e5w4q3",
                DEMO_AGENT["solana_address"],
                "9xQ7dG8vH7j6K5l4P3o2I1u0Y9t8R7e6W5q4Z3x2C1v9B8n7M6k5J4h3G2f1D9s8A7p6O5i4U3y2T1r",
                1000000,  # 0.001 SOL in lamports
                "SOL",
                True,
                json.dumps({
                    "demo": True,
                    "note": "Demo attestation for OWS integration showcase",
                    "ows_vault": DEMO_AGENT["ows_vault_name"]
                })
            ))

            # Update agent reputation
            cur.execute("""
                UPDATE agent_keys
                SET reputation_score = reputation_score + 10,
                    last_seen = NOW()
                WHERE agent_id = %s
            """, (DEMO_AGENT["agent_id"],))

            conn.commit()
            print(f"  ✅ Created demo attestation: {attestation_id}")

    except Exception as e:
        print(f"  ⚠️  Attestation creation error: {e}")
        conn.rollback()
    finally:
        conn.close()


def register_demo_agent():
    """Register the OWS demo agent"""
    print("=" * 60)
    print("🔐 OWS Demo Agent Registration")
    print("=" * 60)

    # Check if agent already exists
    if check_demo_agent_exists():
        print(f"\nℹ️  Agent '{DEMO_AGENT['agent_id']}' already exists")
        agent = get_agent_by_id(DEMO_AGENT["agent_id"])
        print(f"   Wallet Standard: {agent.get('wallet_standard', 'None')}")
        print(f"   OWS Badge: {agent.get('wallet_standard') == 'ows'}")
    else:
        print(f"\n📝 Registering OWS demo agent...")

        # Register the agent
        success = register_agent(
            agent_id=DEMO_AGENT["agent_id"],
            public_key=DEMO_AGENT["public_key"],
            solana_address=DEMO_AGENT["solana_address"],
            wallet_standard=DEMO_AGENT["wallet_standard"],
            ows_vault_name=DEMO_AGENT["ows_vault_name"],
            chains=DEMO_AGENT["chains"],
            alias=DEMO_AGENT["alias"]
        )

        if success:
            print(f"  ✅ Agent registered successfully")
        else:
            print(f"  ❌ Registration failed")
            return False

    # Get agent details
    agent = get_agent_by_id(DEMO_AGENT["agent_id"])

    print(f"\n📋 Agent Details:")
    print(f"   Agent ID: {agent['agent_id']}")
    print(f"   Alias: {agent.get('alias', 'N/A')}")
    print(f"   Public Key: {agent['public_key'][:20]}...")
    print(f"   Solana Address: {agent.get('solana_address', 'N/A')[:20]}...")

    print(f"\n🔐 OWS Information:")
    print(f"   Wallet Standard: {agent.get('wallet_standard', 'None')}")
    print(f"   OWS Vault: {agent.get('ows_vault_name', 'N/A')}")

    chains = agent.get('chains')
    if isinstance(chains, str):
        chains = json.loads(chains)
    print(f"   Chains: {', '.join(chains) if chains else 'N/A'}")
    print(f"   OWS Badge: ✅ Yes" if agent.get('wallet_standard') == 'ows' else "   OWS Badge: ❌ No")

    # Create demo attestation
    print(f"\n📝 Creating demo attestation...")
    create_demo_attestation()

    # Get updated agent info
    agent = get_agent_by_id(DEMO_AGENT["agent_id"])

    print(f"\n📊 Current Status:")
    print(f"   Reputation Score: {agent.get('reputation_score', 0)}")
    print(f"   Created: {agent['created_at']}")

    print(f"\n🌐 Live URLs:")
    print(f"   VAC: https://observerprotocol.org/vac/{DEMO_AGENT['agent_id']}")
    print(f"   Agent Info: https://observerprotocol.org/observer/agent/{DEMO_AGENT['agent_id']}")
    print(f"   Registry: https://observerprotocol.org/observer/registry?wallet_standard=ows")

    print(f"\n✅ Demo agent setup complete!")
    print("=" * 60)

    return True


def verify_vac_output():
    """Verify the VAC endpoint output format"""
    print("\n🔍 Verifying VAC Output Format...")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM agent_keys WHERE agent_id = %s", (DEMO_AGENT["agent_id"],))
            agent = cur.fetchone()

            if not agent:
                print("  ❌ Agent not found")
                return

            # Get attestation stats
            cur.execute("""
                SELECT
                    COUNT(*) as total_count,
                    COUNT(CASE WHEN verified = true THEN 1 END) as verified_count
                FROM attestations
                WHERE agent_id = %s
            """, (DEMO_AGENT["agent_id"],))
            stats = cur.fetchone()

            # Parse chains
            chains = agent.get('chains')
            if isinstance(chains, str):
                chains = json.loads(chains)

            # Build VAC response
            vac = {
                "version": "1.0",
                "agent_id": agent['agent_id'],
                "alias": agent.get('alias'),
                "public_key": agent['public_key'],
                "wallet_standard": agent.get('wallet_standard'),
                "ows_badge": agent.get('wallet_standard') == "ows",
                "ows_vault_name": agent.get('ows_vault_name'),
                "chains": chains,
                "reputation_score": agent.get('reputation_score', 0),
                "attestation_count": stats['total_count'] or 0,
                "verified_tx_count": stats['verified_count'] or 0,
                "created_at": agent['created_at'].isoformat() if agent.get('created_at') else None,
                "last_seen": agent['last_seen'].isoformat() if agent.get('last_seen') else None,
                "credential_proof": {
                    "type": "ObserverProtocolVAC",
                    "issued_at": datetime.now(timezone.utc).isoformat(),
                    "issuer": "observerprotocol.org"
                }
            }

            print("  ✅ VAC Output:")
            print(json.dumps(vac, indent=4))

    finally:
        conn.close()


if __name__ == "__main__":
    # Run migration first if needed
    print("📦 Ensuring database schema is up to date...")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'migrations'))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ows_migration", "../migrations/001_add_ows_support.py")
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        migration.migrate()
    except Exception as e:
        print(f"  ⚠️  Migration check: {e}")

    # Register demo agent
    if register_demo_agent():
        verify_vac_output()
    else:
        print("\n❌ Demo agent registration failed")
        sys.exit(1)
