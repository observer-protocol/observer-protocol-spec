-- Migration 005: Drop legacy public_key_hash column from observer_agents
-- Layer 3 verified — DB is cache only, DID is the authoritative identity.
-- The public_key column (raw hex) is kept for DID Document reconstruction.

ALTER TABLE observer_agents DROP COLUMN IF EXISTS public_key_hash;
DROP INDEX IF EXISTS observer_agents_public_key_hash_key;
