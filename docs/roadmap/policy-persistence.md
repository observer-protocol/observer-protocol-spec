# Policy Persistence — Roadmap Note

**Status:** localStorage (demo-grade)
**Target:** Server-side persistence in `sovereign_policies` table
**Priority:** Required before production; not required for Anchorage demo

## Current State

Level 3 policies persist to the browser's `localStorage`. This is sufficient for the demo but has known limitations:

- **No multi-device sync** — a policy saved on desktop is not available on mobile
- **No recovery** — clearing browser data loses the policy
- **No audit trail** — no server-side record of policy changes over time
- **No backup** — the policy and its associated delegation credential exist only in the browser

## Production Target

Migrate to server-side persistence in the AT dashboard database:

```sql
CREATE TABLE sovereign_policies (
  id SERIAL PRIMARY KEY,
  policy_id VARCHAR(100) UNIQUE NOT NULL,
  user_id VARCHAR(100) NOT NULL,
  policy_json JSONB NOT NULL,
  policy_hash VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

The `policy_hash` (SHA-256 of canonical JSON) is the only value that crosses the protocol boundary — it appears in receipts via `authorization.policy_version_hash`. Policy content stays AT-side; the hash provides verifiability without exposing private configuration.

## What Stays Client-Side

The delegation credential's private key and signing operation remain client-side (browser). Server-side persistence is for the policy document only, not the signing key.

## Post-Approval Discovery Prompt for Level 3

**Status:** Built (shipped 2026-04-28)

After a successful Level 1 approval, the success screen displays a dismissible soft prompt: *"Want to reduce friction next time? Configure your delegation policy →"* — linking to `/sovereign/policy`. Models the trust-progression pattern from Phoenix/Strike where sophistication features appear at the moment users are most receptive. Dismissal persists in localStorage.
