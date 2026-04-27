# Sandbox Environment

**Live at:** [sandbox.observerprotocol.org](https://sandbox.observerprotocol.org)
**Interactive docs:** [sandbox.observerprotocol.org/docs/](https://sandbox.observerprotocol.org/docs/)

The sandbox is a developer-isolated environment for integration testing. It has its own database, signing keys, and fixture data — completely separate from production.

## What the sandbox provides

- **`POST /v1/verify`** — Full 8-step verification orchestration with deterministic outcomes
- **Fixture agents** — Pre-seeded agents covering all verdict paths (approved, soft-rejected, denied)
- **Policy simulator** — Hardcoded trust-threshold check (deterministic for testing)
- **Reseedable state** — Reset to a known clean state between test runs
- **Same API shape** — Request/response formats match production
- **Interactive API docs** — Swagger UI at `/docs/` for exploring and testing endpoints in the browser

## Getting access

Email **[dev@observerprotocol.org](mailto:dev@observerprotocol.org)** with:
- Your name and organization
- What you're building
- Which chain(s) you're integrating with

We'll issue a sandbox API key within 24 hours.

## Fixture data

The sandbox comes pre-seeded with test entities:

### Integrator

| Field | Value |
|-------|-------|
| `integrator_id` | `integrator_001` |
| `display_name` | Example AI Inference Platform |
| `trust_threshold` | 50 |

### Agents

| Agent | DID | Trust Score | Has Delegation | Status |
|-------|-----|-------------|----------------|--------|
| Bob's Agent | `did:web:observerprotocol.org:agents:agent_demo_bob_001` | 72 | Yes ($50/tx, 7 days) | Active |
| Carol's Agent | `did:web:observerprotocol.org:agents:agent_demo_carol_001` | 65 | Yes (revoked) | Revoked |
| Dan's Agent | `did:web:observerprotocol.org:agents:agent_demo_dan_001` | 30 | Yes | Low trust |
| Alice's Research Agent | (cold-start) | 0 | No | Unregistered |

### Test scenarios

| Scenario | Input | Expected verdict |
|----------|-------|------------------|
| Pre-verified agent, within scope | Bob, $20, ai_inference_credits | `approved` with receipt |
| Cold-start agent, no DID | Alice (email), any transaction | `soft_rejected: agent_not_verified` |
| Revoked delegation | Carol, any transaction | `denied: delegation_revoked` |
| Low trust score | Dan, any transaction | `denied: trust_threshold_not_met` |
| Over spending limit | Bob, $100 (limit is $50) | `soft_rejected: delegation_insufficient_scope` |

## Sandbox vs production

| Aspect | Sandbox | Production |
|--------|---------|------------|
| Database | `at_verify_sandbox` (isolated) | `agentic_terminal_db` |
| Signing keys | Sandbox-only Ed25519 keypairs | Production keys |
| Policy engine | Hardcoded simulator | Real policy engine (Spec 3.5) |
| Counterparty checks | Delegation-scope only | Delegation-scope + org-level acceptance |
| Chain verification | Via production `/v1/chain/verify` | Direct |
| Audit trail | Local sandbox DB | Production `verified_events` + `agent_activity_credentials` |

## The sandbox → production bridge

When the sandbox issues an `approved` verdict, it calls production endpoints in the background:
1. `POST /v1/chain/verify` — verify the transaction on-chain
2. `POST /v1/audit/verified-event` — write to the production audit trail

This bridge is the canonical pattern for how developer environments talk to OP production infrastructure. The same pattern applies when you build your own integration.

## Resetting

Sandbox state can be reset to the initial fixture data. Contact us to trigger a reset, or use the seed script if you're running a local sandbox instance.
