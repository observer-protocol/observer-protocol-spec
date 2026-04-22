"""
Migration 006: Replace vac_revocation_registry for Bitstring Status List v1.0
Spec: Spec 3.3 — Revocation and Lifecycle (Phase 3, Capability 3)

This migration drops the existing vac_revocation_registry table and recreates it
for W3C Bitstring Status List v1.0 support. The new schema supports:
- OP-hosted status lists (Tier 3 hosting)
- Both revocation and suspension purposes
- Atomic index allocation
- Compressed bitstring storage (GZIP + base64)

Motivation: Spec 3.3 §12.1
"""

import os
import sys
import psycopg2

MIGRATION_SQL = """
-- Drop existing table if it exists
DROP TABLE IF EXISTS vac_revocation_registry;

-- Create new Bitstring Status List v1.0 registry table
CREATE TABLE vac_revocation_registry (
    id                       SERIAL PRIMARY KEY,
    status_list_id           TEXT UNIQUE NOT NULL,           -- the status list's URL identifier
    status_list_url          TEXT UNIQUE NOT NULL,           -- the public URL where the list is served
    owner_did                TEXT NOT NULL,                  -- the DID authorized to update this list
    status_purpose           TEXT NOT NULL,                  -- 'revocation' | 'suspension'
    current_bitstring        TEXT NOT NULL,                  -- compressed bitstring (base64-encoded GZIP)
    current_credential_jsonld JSONB NOT NULL,                -- the current signed BitstringStatusListCredential
    next_available_index     INTEGER NOT NULL DEFAULT 0,     -- next unallocated index
    total_capacity           INTEGER NOT NULL DEFAULT 131072, -- size of the bitstring (bits)
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries per Spec 3.3 §12.1
CREATE INDEX idx_revocation_registry_owner   ON vac_revocation_registry(owner_did);
CREATE INDEX idx_revocation_registry_purpose ON vac_revocation_registry(status_purpose);
CREATE INDEX idx_revocation_registry_url     ON vac_revocation_registry(status_list_url);

-- Add comments for documentation
COMMENT ON TABLE vac_revocation_registry IS 'Bitstring Status List v1.0 registry for OP-hosted status lists per Spec 3.3';
COMMENT ON COLUMN vac_revocation_registry.status_list_id IS 'Unique identifier for the status list (URL-friendly)';
COMMENT ON COLUMN vac_revocation_registry.owner_did IS 'DID authorized to update this status list';
COMMENT ON COLUMN vac_revocation_registry.status_purpose IS 'Purpose: revocation (terminal) or suspension (reversible)';
COMMENT ON COLUMN vac_revocation_registry.current_bitstring IS 'GZIP-compressed, base64-encoded bitstring';
COMMENT ON COLUMN vac_revocation_registry.current_credential_jsonld IS 'Full signed BitstringStatusListCredential VC';
COMMENT ON COLUMN vac_revocation_registry.next_available_index IS 'Next available bit index for new credentials (atomic allocation)';
COMMENT ON COLUMN vac_revocation_registry.total_capacity IS 'Total bit capacity (default 131072 = 16KB uncompressed)';
"""

ROLLBACK_SQL = """
-- Rollback: Drop the new table
DROP TABLE IF EXISTS vac_revocation_registry;
"""


def get_db_connection():
    """Get PostgreSQL database connection."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        # Try common local development URLs
        for url in [
            "postgresql://postgres:postgres@localhost:5432/agentic_terminal_db",
            "postgresql://localhost:5432/agentic_terminal_db",
        ]:
            try:
                conn = psycopg2.connect(url)
                print(f"Connected using fallback URL")
                return conn
            except:
                continue
        raise RuntimeError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(database_url)


def migrate():
    """Apply the migration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("Applying migration 006: Replace vac_revocation_registry for Bitstring Status List v1.0")
        cursor.execute(MIGRATION_SQL)
        conn.commit()
        print("✓ Migration applied successfully")
        
        # Verify table was created
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'vac_revocation_registry'
            ORDER BY ordinal_position
        """)
        columns = cursor.fetchall()
        print(f"\nTable structure:")
        for col_name, data_type in columns:
            print(f"  - {col_name}: {data_type}")
        
        # Verify indexes
        cursor.execute("""
            SELECT indexname, indexdef 
            FROM pg_indexes 
            WHERE tablename = 'vac_revocation_registry'
        """)
        indexes = cursor.fetchall()
        print(f"\nIndexes created:")
        for idx_name, idx_def in indexes:
            print(f"  - {idx_name}")
            
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"✗ Migration failed: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def rollback():
    """Rollback the migration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("Rolling back migration 006...")
        cursor.execute(ROLLBACK_SQL)
        conn.commit()
        print("✓ Rollback completed")
        return True
    except Exception as e:
        conn.rollback()
        print(f"✗ Rollback failed: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--rollback":
        rollback()
    else:
        migrate()
