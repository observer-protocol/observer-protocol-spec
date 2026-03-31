-- Migration 004: Add vp_document JSONB column to vac_credentials
-- Stores the W3C VP document (Layer 2 rebuild)

ALTER TABLE vac_credentials ADD COLUMN IF NOT EXISTS vp_document JSONB;

CREATE INDEX IF NOT EXISTS idx_vac_credentials_vp_document
    ON vac_credentials USING gin(vp_document)
    WHERE vp_document IS NOT NULL;
