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

## Post-Approval Discovery Prompt for Level 3 (UX Enhancement)

**Status:** Not built
**Priority:** Post-Anchorage product roadmap

After a successful Level 1 approval, the success screen displays a dismissible soft prompt inviting the user to refine their delegation model for future transactions. Example copy: *"Want to reduce friction next time? Set up a broader policy →"*

Models the trust-progression pattern used by mature consumer crypto wallets (Phoenix, Strike, Wallet of Satoshi) where security and sophistication features are surfaced at the moment users are most receptive — never on first interaction. The user has just experienced the one-tap approval flow and understands the value; this is when they're most likely to explore Level 2/3 options.

Currently the success screen shows a backup nudge on 2nd+ visits. The Level 3 discovery prompt would appear alongside or replace the backup nudge once the user has completed multiple Level 1 approvals, signaling readiness for delegation sophistication.
