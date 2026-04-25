"""
Migration 015: Integrator Registry and Settlement Executions
Sprint: AT Verify MVP Demo, Phase 1B

New tables:
  - integrator_registry: API key auth for /v1/verify, /v1/settlement/execute,
    /v1/audit/verified-event callers
  - settlement_executions: Idempotent settlement execution tracking

Seeds the sandbox demo integrator.

See PHASE-1B-DESIGN.md for full schema rationale.
"""

import hashlib
import os
import sys
import psycopg2


MIGRATION_SQL = """
-- ============================================================
-- Integrator Registry
-- ============================================================
CREATE TABLE IF NOT EXISTS integrator_registry (
    id SERIAL PRIMARY KEY,
    integrator_id VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    domain VARCHAR(200),
    api_key_hash VARCHAR(128) NOT NULL,
    api_key_prefix VARCHAR(8) NOT NULL,
    did VARCHAR(300),
    tier VARCHAR(20) NOT NULL DEFAULT 'production'
        CHECK (tier IN ('sandbox', 'production')),
    op_organization_id INTEGER NULL REFERENCES organizations(id),
    settlement_config JSONB NOT NULL DEFAULT '{}',
    webhook_config JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integrator_registry_prefix
    ON integrator_registry(api_key_prefix);
CREATE INDEX IF NOT EXISTS idx_integrator_registry_active
    ON integrator_registry(integrator_id) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_integrator_registry_tier
    ON integrator_registry(tier);

COMMENT ON TABLE integrator_registry IS 'Integrators who call /v1/verify, /v1/settlement/execute, /v1/audit/verified-event';
COMMENT ON COLUMN integrator_registry.tier IS 'sandbox or production — endpoints do not differ by tier in Phase 1B';
COMMENT ON COLUMN integrator_registry.op_organization_id IS 'Nullable FK to organizations(id) when integrator is also an OP org';
COMMENT ON COLUMN integrator_registry.webhook_config IS 'Reserved for future webhook delivery — not read by any code in Phase 1B';

-- ============================================================
-- Chain Verifications (replaces settlement_executions)
-- Chain-agnostic verification tracking for /v1/chain/verify
-- ============================================================
CREATE TABLE IF NOT EXISTS chain_verifications (
    id SERIAL PRIMARY KEY,
    receipt_reference VARCHAR(200) UNIQUE NOT NULL,
    integrator_id VARCHAR(100) NOT NULL REFERENCES integrator_registry(integrator_id),
    chain VARCHAR(50) NOT NULL,
    transaction_reference VARCHAR(200),
    amount VARCHAR(50),
    currency VARCHAR(10),
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_tier VARCHAR(50),
    explorer_url VARCHAR(500),
    chain_specific JSONB NOT NULL DEFAULT '{}',
    confirmed_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'failed')),
    error_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chain_verify_receipt
    ON chain_verifications(receipt_reference);
CREATE INDEX IF NOT EXISTS idx_chain_verify_integrator
    ON chain_verifications(integrator_id);
CREATE INDEX IF NOT EXISTS idx_chain_verify_chain
    ON chain_verifications(chain);

COMMENT ON TABLE chain_verifications IS 'Chain-agnostic verification tracking — receipt_reference is the idempotency key';

-- ============================================================
-- VAC Extension Registry
-- ============================================================
CREATE TABLE IF NOT EXISTS vac_extension_registry (
    id SERIAL PRIMARY KEY,
    extension_id VARCHAR(200) UNIQUE NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    issuer_did VARCHAR(300) NOT NULL,
    issuer_display_name VARCHAR(200),
    issuer_domain VARCHAR(200),
    registrant_integrator_id VARCHAR(100) NOT NULL REFERENCES integrator_registry(integrator_id),
    schema_json JSONB NOT NULL,
    schema_url VARCHAR(500) NOT NULL,
    summary_fields TEXT[] NOT NULL DEFAULT '{}',
    refresh_recommended_ttl INTERVAL,
    refresh_stale_after INTERVAL,
    tier VARCHAR(20) NOT NULL DEFAULT 'production',
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deprecated', 'deregistered')),
    successor_extension_id VARCHAR(200),
    sunset_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (namespace, version)
);

CREATE INDEX IF NOT EXISTS idx_vac_ext_namespace ON vac_extension_registry(namespace);
CREATE INDEX IF NOT EXISTS idx_vac_ext_issuer ON vac_extension_registry(issuer_did);
CREATE INDEX IF NOT EXISTS idx_vac_ext_active ON vac_extension_registry(status) WHERE status = 'active';

COMMENT ON TABLE vac_extension_registry IS 'VAC extension schema registry — integrator-claimed namespaces with identity binding';

-- Add extension_id column to partner_attestations for tagging
ALTER TABLE partner_attestations ADD COLUMN IF NOT EXISTS extension_id VARCHAR(200);
CREATE INDEX IF NOT EXISTS idx_attestation_extension ON partner_attestations(extension_id)
    WHERE extension_id IS NOT NULL;
"""


# Demo integrator API key — same as sandbox .env
DEMO_API_KEY = "sk_test_demo_integrator_001_a1b2c3d4e5f6"


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _api_key_prefix(key: str) -> str:
    return key[:8]


SEED_SQL = """
INSERT INTO integrator_registry
    (integrator_id, display_name, domain, api_key_hash, api_key_prefix, did, tier)
VALUES
    (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (integrator_id) DO UPDATE SET
    api_key_hash = EXCLUDED.api_key_hash,
    api_key_prefix = EXCLUDED.api_key_prefix,
    tier = EXCLUDED.tier;
"""


def get_db_connection():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        for url in [
            "postgresql://postgres:postgres@localhost:5432/agentic_terminal_db",
            "postgresql://localhost:5432/agentic_terminal_db",
        ]:
            try:
                conn = psycopg2.connect(url)
                return conn
            except Exception:
                continue
        raise RuntimeError("DATABASE_URL not set and fallback URLs failed")
    return psycopg2.connect(database_url)


def migrate():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        print("Applying migration 015: Integrator Registry and Chain Verifications")
        cursor.execute(MIGRATION_SQL)

        # Seed sandbox demo integrator
        cursor.execute(SEED_SQL, (
            "integrator_001",
            "Example AI Inference Platform",
            "example-ai.local",
            _hash_api_key(DEMO_API_KEY),
            _api_key_prefix(DEMO_API_KEY),
            "did:web:example-ai.local:op-identity",
            "sandbox",
        ))

        conn.commit()
        print("Migration applied successfully.")
        print(f"Sandbox demo integrator seeded: integrator_001 (tier=sandbox)")
        return True
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def rollback():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        print("Rolling back migration 015...")
        cursor.execute("ALTER TABLE partner_attestations DROP COLUMN IF EXISTS extension_id")
        cursor.execute("DROP TABLE IF EXISTS vac_extension_registry CASCADE")
        cursor.execute("DROP TABLE IF EXISTS chain_verifications CASCADE")
        cursor.execute("DROP TABLE IF EXISTS integrator_registry CASCADE")
        conn.commit()
        print("Rollback completed.")
        return True
    except Exception as e:
        conn.rollback()
        print(f"Rollback failed: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--rollback":
        rollback()
    else:
        migrate()
