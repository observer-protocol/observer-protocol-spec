# DEPLOYMENT-LOG.md

Production deployment log for Observer Protocol. Updated on every migration or deployment to the FutureBit production server (`/media/nvme/observer-protocol/`).

**Purpose:** Prevent drift between local working copies and production. Check this file before writing new migrations.

**Rule:** Every production deployment gets one row. No exceptions.

| Date | Migration/Change | Applied by | DB | Notes |
|------|-----------------|------------|-----|-------|
| 2026-03-30 | 001_add_ows_support.py | claude | agentic_terminal_db | OWS vault support |
| 2026-04-01 | 002_add_delegation_vc.py | claude | agentic_terminal_db | Delegation VC columns on observer_agents |
| 2026-03-30 | 003_add_did_columns.sql | claude | agentic_terminal_db | DID columns on observer_agents |
| 2026-04-22 | 003_replace_partner_attestations_for_vc.py | claude | agentic_terminal_db | Spec 3.1 — partner attestations as W3C VCs |
| 2026-03-30 | 004_add_vp_document_column.sql | claude | agentic_terminal_db | VP document column |
| 2026-04-21 | 004_replace_delegation_credentials_for_recursive_model.py | claude | agentic_terminal_db | Spec 3.2 — recursive DID-to-DID delegation |
| 2026-04-21 | 005_add_revocation_tracking.py | claude | agentic_terminal_db | Revocation tracking |
| 2026-03-30 | 005_drop_public_key_hash.sql | claude | agentic_terminal_db | Drop redundant public_key_hash |
| 2026-04-21 | 006_replace_vac_revocation_registry_for_status_lists.py | claude | agentic_terminal_db | Spec 3.3 — Bitstring Status List v1.0 |
| 2026-04-22 | 007_create_schema_migrations_table.py | claude | agentic_terminal_db | Schema migrations tracking table |
| 2026-04-20 | 008_tron_receipt_support.sql | claude | agentic_terminal_db | TRON receipt tables, triggers, trust metrics |
| 2026-04-20 | 009_bridge_tron_receipts_to_agent_transactions.sql | claude | agentic_terminal_db | TRON receipts → agent_transactions bridge |
| 2026-04-23 | 010_create_audit_tables.sql | claude-spec-3.4 | agentic_terminal_db | Spec 3.4 — 6 audit tables (dual-source evidence) |
| 2026-04-23 | 011_add_sso_to_users.sql | claude-spec-3.8 | agentic_terminal_db | Spec 3.8 — SSO columns on users |
| 2026-04-23 | 012_create_org_idp_config.sql | claude-spec-3.8 | agentic_terminal_db | Spec 3.8 — per-org SAML IdP config |
| 2026-04-24 | 013_create_policy_engine_tables.sql | claude-spec-3.5 | agentic_terminal_db | Spec 3.5 — policy engine registration + consultation log |
| 2026-04-24 | 014_create_counterparties.sql | claude-spec-3.6 | agentic_terminal_db | Spec 3.6 — counterparties + auto-discovery trigger |
