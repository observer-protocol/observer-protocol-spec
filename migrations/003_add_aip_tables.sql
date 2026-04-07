-- Migration: Add AIP (Agentic Identity Protocol) v0.3.1 tables
-- Date: 2026-04-06
-- Description: Core tables for AIP - KYB VCs, Delegation Credentials, Revocations, and Trust Registry

-- ============================================================
-- Table: kyb_verifiable_credentials
-- Stores W3C Verifiable Credentials for KYB attestations
-- ============================================================
CREATE TABLE IF NOT EXISTS kyb_verifiable_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(255) NOT NULL UNIQUE,  -- UUID v4
    credential_json JSONB NOT NULL,              -- Full W3C VC JSON
    
    -- Issuer (AT-anchored or provider-issued)
    issuer_did VARCHAR(255) NOT NULL,
    issuer_type VARCHAR(50) NOT NULL DEFAULT 'at_anchored',  -- 'at_anchored', 'provider_issued'
    
    -- Subject (the organization)
    org_did VARCHAR(255) NOT NULL,
    org_db_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- KYB details from credentialSubject
    kyb_provider VARCHAR(255),
    kyb_provider_did VARCHAR(255),
    kyb_result VARCHAR(50) NOT NULL,             -- 'pass', 'fail', 'pending'
    kyb_completed_at TIMESTAMP WITH TIME ZONE,
    kyb_scope VARCHAR(50) DEFAULT 'organization', -- 'organization', 'individual', etc.
    
    -- W3C VC standard fields
    issuance_date TIMESTAMP WITH TIME ZONE NOT NULL,
    expiration_date TIMESTAMP WITH TIME ZONE,
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'expired', 'revoked'
    
    -- Proof/signature data
    proof_type VARCHAR(100),
    verification_method VARCHAR(255),
    proof_value TEXT,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT valid_kyb_result CHECK (kyb_result IN ('pass', 'fail', 'pending')),
    CONSTRAINT valid_issuer_type CHECK (issuer_type IN ('at_anchored', 'provider_issued')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'expired', 'revoked', 'suspended'))
);

-- Indexes for KYB VCs
CREATE INDEX IF NOT EXISTS idx_kyb_vcs_org_did ON kyb_verifiable_credentials(org_did);
CREATE INDEX IF NOT EXISTS idx_kyb_vcs_org_db_id ON kyb_verifiable_credentials(org_db_id);
CREATE INDEX IF NOT EXISTS idx_kyb_vcs_issuer ON kyb_verifiable_credentials(issuer_did);
CREATE INDEX IF NOT EXISTS idx_kyb_vcs_status ON kyb_verifiable_credentials(status);
CREATE INDEX IF NOT EXISTS idx_kyb_vcs_expiration ON kyb_verifiable_credentials(expiration_date);

-- ============================================================
-- Table: delegation_credentials
-- Stores AIP Delegation Credentials (VAC extensions)
-- ============================================================
CREATE TABLE IF NOT EXISTS delegation_credentials (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(255) NOT NULL UNIQUE,  -- aip-cred-uuid-v4
    version VARCHAR(10) NOT NULL DEFAULT '0.3',
    
    -- Issuer (organization)
    org_did VARCHAR(255) NOT NULL,
    org_db_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    org_name VARCHAR(255) NOT NULL,
    kyb_credential_id VARCHAR(255) REFERENCES kyb_verifiable_credentials(credential_id),
    
    -- Subject (agent)
    agent_did VARCHAR(255) NOT NULL,
    agent_id VARCHAR(255),  -- OP agent_id (may be null until linked)
    agent_label VARCHAR(255),
    
    -- Scope (delegation permissions)
    scope_payment_settlement BOOLEAN NOT NULL DEFAULT FALSE,
    scope_max_transaction_value_usd DECIMAL(20, 2),
    scope_allowed_counterparty_types TEXT[],  -- Array of Type Registry values
    scope_allowed_rails TEXT[],               -- Array of rails
    scope_geographic_restriction VARCHAR(255), -- ISO country codes or null
    
    -- Delegation chain tracking
    delegation_depth INTEGER NOT NULL DEFAULT 1,
    max_delegation_depth INTEGER NOT NULL DEFAULT 3,
    parent_credential_id VARCHAR(255) REFERENCES delegation_credentials(credential_id),
    
    -- Signature
    signed_by VARCHAR(255) NOT NULL,          -- verification method ID
    signature_algorithm VARCHAR(50) NOT NULL DEFAULT 'Ed25519',
    signature_value TEXT NOT NULL,
    
    -- Validity period
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'expired', 'revoked'
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT valid_delegation_depth CHECK (delegation_depth >= 1 AND delegation_depth <= 10),
    CONSTRAINT valid_max_delegation_depth CHECK (max_delegation_depth >= 1 AND max_delegation_depth <= 10),
    CONSTRAINT valid_dc_status CHECK (status IN ('active', 'expired', 'revoked', 'suspended'))
);

-- Indexes for delegation credentials
CREATE INDEX IF NOT EXISTS idx_dc_agent_did ON delegation_credentials(agent_did);
CREATE INDEX IF NOT EXISTS idx_dc_agent_id ON delegation_credentials(agent_id);
CREATE INDEX IF NOT EXISTS idx_dc_org_did ON delegation_credentials(org_did);
CREATE INDEX IF NOT EXISTS idx_dc_org_db_id ON delegation_credentials(org_db_id);
CREATE INDEX IF NOT EXISTS idx_dc_status ON delegation_credentials(status);
CREATE INDEX IF NOT EXISTS idx_dc_expires ON delegation_credentials(expires_at);
CREATE INDEX IF NOT EXISTS idx_dc_kyb_cred ON delegation_credentials(kyb_credential_id);

-- ============================================================
-- Table: credential_revocations
-- Stores revocation records (append-only)
-- ============================================================
CREATE TABLE IF NOT EXISTS credential_revocations (
    id SERIAL PRIMARY KEY,
    credential_id VARCHAR(255) NOT NULL,
    credential_type VARCHAR(50) NOT NULL,      -- 'delegation', 'kyb_vc'
    
    -- Revoker details
    revoked_by_did VARCHAR(255) NOT NULL,
    revoked_by_key_id VARCHAR(255) NOT NULL,   -- specific key used
    
    -- Revocation details
    reason VARCHAR(100) NOT NULL,              -- Type Registry value
    reason_description TEXT,
    
    -- Signature of revocation
    revocation_signature TEXT NOT NULL,
    
    -- Cascade tracking
    cascade_to_children BOOLEAN DEFAULT FALSE,
    cascaded_credential_ids TEXT[],            -- Array of child cred IDs revoked
    
    -- Timestamp (immutable)
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_credential_type CHECK (credential_type IN ('delegation', 'kyb_vc')),
    CONSTRAINT valid_revocation_reason CHECK (
        reason IN (
            'agent_compromised',
            'agent_decommissioned',
            'scope_violation',
            'org_kyb_expired',
            'org_kyb_revoked',
            'org_offboarded',
            'fraud_suspected',
            'admin_override'
        )
    )
);

-- Indexes for revocations
CREATE INDEX IF NOT EXISTS idx_revocations_cred_id ON credential_revocations(credential_id);
CREATE INDEX IF NOT EXISTS idx_revocations_cred_type ON credential_revocations(credential_type);
CREATE INDEX IF NOT EXISTS idx_revocations_revoked_by ON credential_revocations(revoked_by_did);
CREATE INDEX IF NOT EXISTS idx_revocations_reason ON credential_revocations(reason);
CREATE INDEX IF NOT EXISTS idx_revocations_revoked_at ON credential_revocations(revoked_at);

-- ============================================================
-- Table: aip_type_registry
-- Canonical enumerated values for AIP spec compliance
-- ============================================================
CREATE TABLE IF NOT EXISTS aip_type_registry (
    id SERIAL PRIMARY KEY,
    category VARCHAR(100) NOT NULL,            -- 'counterparty_type', 'revocation_reason', 'denial_reason', 'scope_value'
    value VARCHAR(100) NOT NULL,               -- the enumerated value
    description TEXT NOT NULL,
    spec_version VARCHAR(10) NOT NULL DEFAULT '0.3',
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'deprecated', 'draft'
    
    -- Metadata
    added_in_version VARCHAR(10),
    deprecated_in_version VARCHAR(10),
    replacement_value VARCHAR(100),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    
    -- Unique constraint per category/value
    CONSTRAINT unique_type_value UNIQUE (category, value)
);

-- Index for type registry lookups
CREATE INDEX IF NOT EXISTS idx_type_registry_category ON aip_type_registry(category);
CREATE INDEX IF NOT EXISTS idx_type_registry_status ON aip_type_registry(status);

-- ============================================================
-- Table: aip_remediation_options
-- Remediation actions available per partner/score model
-- ============================================================
CREATE TABLE IF NOT EXISTS aip_remediation_options (
    id SERIAL PRIMARY KEY,
    option_id INTEGER NOT NULL,
    action VARCHAR(100) NOT NULL,              -- e.g., 'complete_org_kyb_linkage'
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    
    -- Score impact
    score_components_affected TEXT[],          -- Array of component names
    
    -- Complexity and timing
    complexity VARCHAR(50) NOT NULL,           -- 'instant', 'simple', 'medium', 'complex'
    estimated_time VARCHAR(255),
    
    -- Precondition
    precondition VARCHAR(100),
    precondition_check_endpoint VARCHAR(512),
    
    -- Action endpoint (where to execute)
    action_endpoint VARCHAR(512),
    action_method VARCHAR(10) DEFAULT 'POST',
    action_params_schema JSONB,                -- JSON Schema for params
    
    -- Partner configuration
    partner_id VARCHAR(255),                   -- null = global/default
    score_model_id VARCHAR(255),               -- null = applies to all
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,              -- Lower = higher priority
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_complexity CHECK (complexity IN ('instant', 'simple', 'medium', 'complex'))
);

-- Indexes for remediation options
CREATE INDEX IF NOT EXISTS idx_remediation_action ON aip_remediation_options(action);
CREATE INDEX IF NOT EXISTS idx_remediation_partner ON aip_remediation_options(partner_id);
CREATE INDEX IF NOT EXISTS idx_remediation_active ON aip_remediation_options(is_active);

-- ============================================================
-- Table: agent_trust_scores
-- Computed trust scores for agents (AT layer integration)
-- ============================================================
CREATE TABLE IF NOT EXISTS agent_trust_scores (
    id SERIAL PRIMARY KEY,
    agent_did VARCHAR(255) NOT NULL,
    agent_id VARCHAR(255),
    
    -- Score details
    score_name VARCHAR(255) NOT NULL DEFAULT 'AT Trust Score',
    score INTEGER NOT NULL,
    threshold INTEGER,
    score_version VARCHAR(20),
    
    -- Component breakdown
    components JSONB,                          -- {component_name: value}
    
    -- Model info
    score_model_id VARCHAR(255),
    partner_id VARCHAR(255),
    
    -- Timestamps
    computed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Unique constraint per agent/model
    CONSTRAINT unique_agent_score_model UNIQUE (agent_did, score_model_id, partner_id)
);

-- Indexes for trust scores
CREATE INDEX IF NOT EXISTS idx_trust_scores_agent_did ON agent_trust_scores(agent_did);
CREATE INDEX IF NOT EXISTS idx_trust_scores_agent_id ON agent_trust_scores(agent_id);
CREATE INDEX IF NOT EXISTS idx_trust_scores_computed ON agent_trust_scores(computed_at);

-- ============================================================
-- Table: aip_audit_log
-- Audit trail for all AIP operations
-- ============================================================
CREATE TABLE IF NOT EXISTS aip_audit_log (
    id SERIAL PRIMARY KEY,
    operation VARCHAR(100) NOT NULL,           -- 'credential_issued', 'revoked', 'verified', etc.
    credential_id VARCHAR(255),
    credential_type VARCHAR(50),
    
    actor_did VARCHAR(255),                    -- who performed the action
    actor_type VARCHAR(50),                    -- 'organization', 'agent', 'at_admin'
    
    -- Request/response details
    request_payload JSONB,
    response_summary JSONB,
    
    -- Outcome
    success BOOLEAN,
    error_code VARCHAR(100),
    error_message TEXT,
    
    -- IP and tracking
    client_ip INET,
    request_id VARCHAR(255),
    
    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_operation ON aip_audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_credential ON aip_audit_log(credential_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON aip_audit_log(actor_did);
CREATE INDEX IF NOT EXISTS idx_audit_created ON aip_audit_log(created_at);

-- ============================================================
-- Insert Type Registry default values
-- ============================================================

-- 6.1 allowed_counterparty_types
INSERT INTO aip_type_registry (category, value, description, spec_version) VALUES
('counterparty_type', 'verified_merchant', 'Counterparty is a registered merchant with a verified business identity in OP', '0.3'),
('counterparty_type', 'kyb_verified_org', 'Counterparty is an organization that has passed KYB through an AT Trusted KYB Provider', '0.3'),
('counterparty_type', 'did_verified_agent', 'Counterparty is an agent with a resolvable, valid did:web DID document', '0.3'),
('counterparty_type', 'aip_delegated_agent', 'Counterparty holds a valid, non-expired AIP Delegation Credential', '0.3'),
('counterparty_type', 'sovereign_individual', 'Counterparty is a self-sovereign individual registered in OP (Sovereign Dashboard tier)', '0.3'),
('counterparty_type', 'unverified', 'No counterparty verification required — used for low-value or open-access contexts', '0.3')
ON CONFLICT (category, value) DO NOTHING;

-- 6.2 Revocation reasons
INSERT INTO aip_type_registry (category, value, description, spec_version) VALUES
('revocation_reason', 'agent_compromised', 'Agent private key or credentials are known or suspected to be compromised', '0.3'),
('revocation_reason', 'agent_decommissioned', 'Agent has been intentionally retired by the issuing organization', '0.3'),
('revocation_reason', 'scope_violation', 'Agent exceeded its authorized scope — transaction or behavior outside Delegation Credential terms', '0.3'),
('revocation_reason', 'org_kyb_expired', 'The issuing organizations KYB attestation has expired and not been renewed', '0.3'),
('revocation_reason', 'org_kyb_revoked', 'The issuing organizations KYB status has been revoked by the KYB provider', '0.3'),
('revocation_reason', 'org_offboarded', 'The issuing organization has been removed from the OP organization registry', '0.3'),
('revocation_reason', 'fraud_suspected', 'Fraud or bad-faith behavior suspected — revocation pending investigation', '0.3'),
('revocation_reason', 'admin_override', 'Revocation issued by an AT enterprise administrator without a specific cause code', '0.3')
ON CONFLICT (category, value) DO NOTHING;

-- 6.3 Denial reasons
INSERT INTO aip_type_registry (category, value, description, spec_version) VALUES
('denial_reason', 'score_below_threshold', 'Agents computed trust score is below the policy engines minimum threshold', '0.3'),
('denial_reason', 'no_delegation_credential', 'No valid AIP Delegation Credential found in the agents VAC', '0.3'),
('denial_reason', 'delegation_credential_expired', 'Delegation Credential is present but past its expires_at date', '0.3'),
('denial_reason', 'delegation_credential_revoked', 'Delegation Credential has been explicitly revoked', '0.3'),
('denial_reason', 'scope_mismatch', 'Transaction type, value, rail, or counterparty type is outside the credentials authorized scope', '0.3'),
('denial_reason', 'counterparty_not_eligible', 'Counterparty does not satisfy the allowed_counterparty_types constraint', '0.3'),
('denial_reason', 'kyb_credential_missing', 'No KYB VC is associated with the issuing organization', '0.3'),
('denial_reason', 'kyb_credential_expired', 'KYB VC is present but past its expirationDate', '0.3'),
('denial_reason', 'kyb_credential_revoked', 'KYB VC has been explicitly revoked', '0.3'),
('denial_reason', 'did_resolution_failed', 'Agent or organization DID could not be resolved at transaction time', '0.3'),
('denial_reason', 'delegation_depth_exceeded', 'Delegation chain depth exceeds max_delegation_depth', '0.3'),
('denial_reason', 'geographic_restriction', 'Transaction violates the geographic_restriction constraint on the Delegation Credential', '0.3'),
('denial_reason', 'rail_not_permitted', 'The payment rail requested is not in allowed_rails', '0.3')
ON CONFLICT (category, value) DO NOTHING;

-- ============================================================
-- Insert default remediation options
-- ============================================================
INSERT INTO aip_remediation_options (option_id, action, title, description, complexity, estimated_time, precondition, action_endpoint, score_components_affected, priority) VALUES
(1, 'complete_org_kyb_linkage', 'Link to your organizations existing KYB record', 
 'Your parent organization has an existing KYB verification. Linking this agent to that record resolves the organizational attestation gap and is expected to bring your score above threshold.',
 'instant', '< 2 minutes', 'org_kyb_record_exists', 'https://agenticterminal.io/aip/kyb-link',
 ARRAY['org_attestation', 'kyb_verified'], 10),

(2, 'build_verified_transaction_history', 'Increase verified transaction history and counterparty diversity',
 'Complete additional verified transactions with diverse counterparties to increase your activity and diversity score components.',
 'medium', 'days to weeks depending on transaction volume', NULL, NULL,
 ARRAY['transaction_volume', 'counterparty_diversity'], 20)
ON CONFLICT DO NOTHING;

-- ============================================================
-- Add comments for documentation
-- ============================================================
COMMENT ON TABLE kyb_verifiable_credentials IS 'W3C Verifiable Credentials for KYB attestations per AIP v0.3';
COMMENT ON TABLE delegation_credentials IS 'AIP Delegation Credentials extending VAC with organizational authorization';
COMMENT ON TABLE credential_revocations IS 'Append-only revocation records for AIP credentials';
COMMENT ON TABLE aip_type_registry IS 'Canonical enumerated values for AIP spec compliance (Section 6)';
COMMENT ON TABLE aip_remediation_options IS 'Remediation actions available for trust deficit resolution';
COMMENT ON TABLE agent_trust_scores IS 'Computed trust scores from AT layer for policy engine integration';
COMMENT ON TABLE aip_audit_log IS 'Audit trail for all AIP operations';
