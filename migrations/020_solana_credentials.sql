-- Migration 020: Solana payment credentials
-- Stores SolanaPaymentCredential VCs issued after verifying Solana payments

CREATE TABLE IF NOT EXISTS solana_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(200) UNIQUE NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    agent_did VARCHAR(300) NOT NULL,
    counterparty VARCHAR(300) NOT NULL,
    network VARCHAR(30) NOT NULL DEFAULT 'mainnet-beta',
    asset_symbol VARCHAR(20) NOT NULL DEFAULT 'USDC',
    amount VARCHAR(50) NOT NULL,
    tx_signature VARCHAR(200),
    sender_address VARCHAR(100),
    recipient_address VARCHAR(100),
    credential_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_solana_agent ON solana_credentials(agent_id);
CREATE INDEX idx_solana_tx ON solana_credentials(tx_signature);
CREATE INDEX idx_solana_created ON solana_credentials(created_at DESC);
