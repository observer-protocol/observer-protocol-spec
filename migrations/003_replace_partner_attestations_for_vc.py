"""
Migration 003: Replace partner_attestations table for VC caching
Spec: Spec 3.1 — Third-Party Attestations (Phase 3, Capability 1)

This migration drops the obsolete partner_attestations schema and recreates it
as a Verifiable Credential cache for third-party attestations.

The old table (if it exists) had a different schema focused on partner identity
as a self-asserted string. Since no production data has been written, we can
cleanly drop and recreate.
"""

MIGRATION_SQL = """
-- Drop the obsolete schema (no data to preserve)
DROP TABLE IF EXISTS partner_attestations CASCADE;

-- Recreate as a VC cache per Spec 3.1 Section 9.2
CREATE TABLE partner_attestations (
    id                   SERIAL PRIMARY KEY,
    credential_id        TEXT UNIQUE NOT NULL,          -- the VC's id field (URL)
    credential_type      TEXT NOT NULL,                  -- e.g., 'KYBAttestationCredential'
    issuer_did           TEXT NOT NULL,                  -- the issuer's DID
    subject_did          TEXT NOT NULL,                  -- the subject's DID
    credential_jsonld    JSONB NOT NULL,                 -- the full signed VC
    credential_url       TEXT,                           -- the URL at issuer's hosting (may equal credential_id)
    valid_from           TIMESTAMPTZ NOT NULL,
    valid_until          TIMESTAMPTZ NOT NULL,
    cached_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at     TIMESTAMPTZ
);

-- Indexes for efficient queries per Spec 3.1
CREATE INDEX idx_partner_attestations_subject  ON partner_attestations(subject_did);
CREATE INDEX idx_partner_attestations_issuer   ON partner_attestations(issuer_did);
CREATE INDEX idx_partner_attestations_type     ON partner_attestations(credential_type);
CREATE INDEX idx_partner_attestations_validity ON partner_attestations(valid_until);

-- Additional composite index for common dashboard queries
CREATE INDEX idx_partner_attestations_subject_valid 
    ON partner_attestations(subject_did, valid_until) 
    WHERE valid_until > NOW();
"""


def migrate(conn):
    """
    Execute the migration.
    
    Args:
        conn: psycopg2 database connection
    """
    cursor = conn.cursor()
    try:
        cursor.execute(MIGRATION_SQL)
        conn.commit()
        print("✓ Migration 003 completed successfully")
        print("  - Dropped old partner_attestations table")
        print("  - Created new VC cache schema")
        print("  - Created indexes: subject, issuer, type, validity")
    except Exception as e:
        conn.rollback()
        print(f"✗ Migration 003 failed: {e}")
        raise
    finally:
        cursor.close()


def rollback(conn):
    """
    Rollback the migration.
    
    Note: This drops the partner_attestations table entirely.
    Use with caution - all cached credentials will be lost.
    """
    cursor = conn.cursor()
    try:
        cursor.execute("DROP TABLE IF EXISTS partner_attestations CASCADE;")
        conn.commit()
        print("✓ Migration 003 rolled back successfully")
    except Exception as e:
        conn.rollback()
        print(f"✗ Rollback failed: {e}")
        raise
    finally:
        cursor.close()


if __name__ == "__main__":
    import os
    import psycopg2
    
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    
    conn = psycopg2.connect(database_url)
    try:
        migrate(conn)
    finally:
        conn.close()
