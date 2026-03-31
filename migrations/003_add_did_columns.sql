-- Migration 003: Add DID columns for did:web identity support
-- Layer 1 of the DID/VC Rebuild — Observer Protocol — March 2026
--
-- NOTE: public_key_hash columns are intentionally kept during this transition.
-- They will be dropped in Migration 004 after Layer 2 is verified.

-- 1. Add DID columns to observer_agents
ALTER TABLE observer_agents
    ADD COLUMN IF NOT EXISTS agent_did TEXT UNIQUE,
    ADD COLUMN IF NOT EXISTS did_document JSONB,
    ADD COLUMN IF NOT EXISTS did_created_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS did_updated_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_observer_agents_did ON observer_agents(agent_did);

-- 2. Add DID columns to organizations
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS org_did TEXT UNIQUE,
    ADD COLUMN IF NOT EXISTS did_document JSONB;

-- 3. Store OP's own DID document
CREATE TABLE IF NOT EXISTS op_did_document (
    id          SERIAL PRIMARY KEY,
    did         TEXT        NOT NULL,
    document    JSONB       NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
