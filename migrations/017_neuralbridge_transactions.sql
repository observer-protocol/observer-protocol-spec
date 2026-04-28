-- Migration 017: NeuralBridge demo transactions
-- Stores transactions processed by the fictional NeuralBridge counterparty

CREATE TABLE IF NOT EXISTS neuralbridge_transactions (
    id SERIAL PRIMARY KEY,
    receipt_id VARCHAR(200) UNIQUE NOT NULL,
    agent_did VARCHAR(300) NOT NULL,
    amount VARCHAR(50) NOT NULL,
    currency VARCHAR(10) NOT NULL,
    rail VARCHAR(50) NOT NULL,
    product_id VARCHAR(100),
    auth_level VARCHAR(20),
    delegation_credential_id VARCHAR(300),
    receipt_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_nb_tx_agent ON neuralbridge_transactions(agent_did);
CREATE INDEX idx_nb_tx_created ON neuralbridge_transactions(created_at DESC);
