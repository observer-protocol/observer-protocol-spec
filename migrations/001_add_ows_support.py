#!/usr/bin/env python3
"""
Database Migration: Add OWS (Open Wallet Standard) Support

Adds columns for wallet_standard, ows_vault_name, and chains to agent_keys table

Run: python migrations/001_add_ows_support.py
"""

import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://observer:observer@localhost/observer_protocol"
)

def get_db_connection():
    """Get PostgreSQL connection"""
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def migrate():
    """Apply migration"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            print("Applying OWS support migration...")
            
            # Add wallet_standard column
            cur.execute("""
                ALTER TABLE agent_keys 
                ADD COLUMN IF NOT EXISTS wallet_standard VARCHAR(32) DEFAULT NULL
            """)
            print("  ✓ Added wallet_standard column")
            
            # Add ows_vault_name column
            cur.execute("""
                ALTER TABLE agent_keys 
                ADD COLUMN IF NOT EXISTS ows_vault_name VARCHAR(128) DEFAULT NULL
            """)
            print("  ✓ Added ows_vault_name column")
            
            # Add chains column (JSONB array of supported chains)
            cur.execute("""
                ALTER TABLE agent_keys 
                ADD COLUMN IF NOT EXISTS chains JSONB DEFAULT NULL
            """)
            print("  ✓ Added chains column (JSONB)")
            
            # Add alias column for agent display name
            cur.execute("""
                ALTER TABLE agent_keys 
                ADD COLUMN IF NOT EXISTS alias VARCHAR(128) DEFAULT NULL
            """)
            print("  ✓ Added alias column")
            
            # Create index on wallet_standard for filtering
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_keys_wallet_standard 
                ON agent_keys(wallet_standard)
            """)
            print("  ✓ Created index on wallet_standard")
            
            # Create index on chains for JSONB queries
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_keys_chains 
                ON agent_keys USING GIN(chains)
            """)
            print("  ✓ Created GIN index on chains")
            
            conn.commit()
            print("\n✅ Migration completed successfully!")
            print("\nNew columns added:")
            print("  - wallet_standard: VARCHAR(32) - 'ows' or NULL")
            print("  - ows_vault_name: VARCHAR(128) - OWS vault identifier")
            print("  - chains: JSONB - Array of supported chains ['evm', 'solana', 'bitcoin']")
            print("  - alias: VARCHAR(128) - Human-readable agent name")
            
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        conn.rollback()
        sys.exit(1)
    finally:
        conn.close()

def rollback():
    """Rollback migration (remove OWS columns)"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            print("Rolling back OWS support migration...")
            
            # Drop columns (careful - data loss!)
            cur.execute("ALTER TABLE agent_keys DROP COLUMN IF EXISTS wallet_standard")
            cur.execute("ALTER TABLE agent_keys DROP COLUMN IF EXISTS ows_vault_name")
            cur.execute("ALTER TABLE agent_keys DROP COLUMN IF EXISTS chains")
            cur.execute("ALTER TABLE agent_keys DROP COLUMN IF EXISTS alias")
            
            conn.commit()
            print("✅ Rollback completed")
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--rollback":
        rollback()
    else:
        migrate()
