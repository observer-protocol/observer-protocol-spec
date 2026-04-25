# DEPLOY-015.md — Deployment Runbook

Migration 015: Integrator Registry, Chain Verifications, VAC Extension Registry.
New endpoints: `/v1/chain/verify`, `/v1/audit/verified-event`, `/v1/vac/extensions/register`, `/v1/vac/extensions/attest`.

---

## Pre-deploy checklist

- [ ] Local tests pass: `cd api && python3 -m tests.test_lightning_adapter` (11 tests)
- [ ] Sandbox tests pass: `cd /Users/boydcohen/projects/at-verify-demo && python3 -m tests.test_delegation && python3 -m tests.test_receipt_and_remediation` (28 tests)
- [ ] DEPLOYMENT-LOG.md is up to date
- [ ] No one else is deploying right now

---

## Step 1: Apply migration

```bash
ssh futurebit@<server>
cd /media/nvme/observer-protocol/migrations
python3 015_integrator_registry_and_settlement.py
```

**Expected output:**
```
Applying migration 015: Integrator Registry and Chain Verifications
Migration applied successfully.
Sandbox demo integrator seeded: integrator_001 (tier=sandbox)
```

**Verify tables created:**
```bash
psql -d agentic_terminal_db -c "\dt integrator_registry; \dt chain_verifications; \dt vac_extension_registry;"
```

Should show all three tables.

**Verify sandbox integrator seeded:**
```bash
psql -d agentic_terminal_db -c "SELECT integrator_id, display_name, tier FROM integrator_registry;"
```

Should show: `integrator_001 | Example AI Inference Platform | sandbox`

---

## Step 2: Copy new files to production

```bash
# From local machine:
scp api/chain_adapter.py futurebit@<server>:/media/nvme/observer-protocol/api/
scp api/lightning_adapter.py futurebit@<server>:/media/nvme/observer-protocol/api/
scp api/stacks_adapter.py futurebit@<server>:/media/nvme/observer-protocol/api/
scp api/vac_extensions.py futurebit@<server>:/media/nvme/observer-protocol/api/
scp api/verify_endpoints.py futurebit@<server>:/media/nvme/observer-protocol/api/
scp -r api/schemas/ futurebit@<server>:/media/nvme/observer-protocol/api/schemas/
scp api/tests/test_lightning_adapter.py futurebit@<server>:/media/nvme/observer-protocol/api/tests/
```

---

## Step 3: Update api-server-v2.py

```bash
scp api/api-server-v2.py futurebit@<server>:/media/nvme/observer-protocol/api/
```

**Change is minimal:** 6 lines added (verify router mount + extensions router mount with graceful fallback). No existing endpoints affected.

---

## Step 4: Restart service

```bash
ssh futurebit@<server>
sudo systemctl restart observer-api.service
sudo systemctl status observer-api.service
```

**Expected:** Service active (running). Look for these lines in the log:
```
AT Verify endpoints mounted: /v1/chain/verify, /v1/audit/verified-event
VAC Extension endpoints mounted: /v1/vac/extensions/register, /v1/vac/extensions/attest
```

---

## Step 5: Smoke tests

**Test 1: Health check (existing endpoint, confirms server is up)**
```bash
curl -s https://api.observerprotocol.org/api/v1/health | jq .
```
Expected: `{"status": "ok", ...}`

**Test 2: Chain verify — Lightning (bad auth, confirms endpoint responds)**
```bash
curl -s -X POST https://api.observerprotocol.org/v1/chain/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer bad_key" \
  -d '{"receipt_reference":"test","chain":"lightning","chain_specific":{}}' | jq .
```
Expected: `{"error": "unauthorized"}` with 401

**Test 3: Chain verify — Unsupported chain (confirms adapter dispatch)**
```bash
curl -s -X POST https://api.observerprotocol.org/v1/chain/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_test_demo_integrator_001_a1b2c3d4e5f6" \
  -d '{"receipt_reference":"test","chain":"cardano","chain_specific":{}}' | jq .
```
Expected: `{"error": "unsupported_chain", "detail": "... Supported: ['tron', 'lightning', 'stacks']"}`

**Test 4: Extension register — reserved prefix (confirms namespace guardrails)**
```bash
curl -s -X POST https://api.observerprotocol.org/v1/vac/extensions/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_test_demo_integrator_001_a1b2c3d4e5f6" \
  -d '{"extension_id":"op_core_v1","display_name":"Test","issuer":{"did":"did:web:test"},"schema":{"type":"object"}}' | jq .
```
Expected: `{"error": "reserved_prefix", ...}` with 403

**Test 5: Audit endpoint — bad auth**
```bash
curl -s -X POST https://api.observerprotocol.org/v1/audit/verified-event \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer bad_key" \
  -d '{}' | jq .
```
Expected: `{"error": "unauthorized"}` with 401

**Test 6: Dashboard still works**
- Open https://app.agenticterminal.io
- Confirm the dashboard loads and displays existing verified events
- No new events should appear (we haven't written any yet)

---

## Rollback (if needed)

If anything goes wrong:

```bash
# 1. Restore previous api-server-v2.py (the router mount is the only change)
# The try/except means the old code works even if the new files are present

# 2. If migration needs rollback:
ssh futurebit@<server>
cd /media/nvme/observer-protocol/migrations
python3 015_integrator_registry_and_settlement.py --rollback
```

**Rollback drops:** `vac_extension_registry`, `chain_verifications`, `integrator_registry` tables, and removes `extension_id` column from `partner_attestations`. No existing data affected — these are all new tables.

---

## Post-deploy

- [ ] Add entry to DEPLOYMENT-LOG.md:
  ```
  | 2026-04-25 | 015_integrator_registry_and_settlement.py | claude | agentic_terminal_db | Integrator registry + chain verifications + VAC extension registry. ChainAdapter (Tron/Lightning/Stacks). 4 new endpoints. |
  ```
- [ ] Monitor `audit_coverage_rollup` for first 24 hours for soft-failure rate on dual-write
- [ ] Verify no unexpected errors in `journalctl -u observer-api.service -f`
