# REPO_MAP.md — observer-protocol

## Canonical Purpose

This repository contains the **canonical source code for the Observer Protocol (OP)** — the trust and verification layer for the agentic economy. It owns the protocol specification, the API server that validates credentials and resolves DIDs, the canonical JSON schemas for W3C Verifiable Credentials, and the database migrations that define the attestation and verification substrate. This is the source-of-truth for all OP protocol behavior, credential formats, and verification logic.

## What Lives Here

- **API server code** (`api/`) — FastAPI application with endpoints for credential verification, DID resolution, attestation caching, and trust scoring
- **Canonical schemas** (`schemas/`) — W3C JSON Schema definitions for KYB attestations, delegation credentials, revocation status lists, and audit trails
- **Database migrations** (`migrations/`) — PostgreSQL schema evolution (001-007, with 007 adding migration tracking per §13.6)
- **Locked spec documents** (`docs/Spec-*.md`) — Version-locked protocol specifications (Spec 3.1, 3.2, 3.3, 3.4)
- **DID resolver** (`api/did_resolver.py`) — did:web resolution with multicodec-aware Ed25519 key extraction
- **VC verification** (`api/vc_verification.py`) — Ed25519 signature verification, schema validation, canonicalization
- **Test fixtures** (`test-fixtures/`) — Test issuer keypairs, credentials for E2E testing (production keys live in `secrets/`)
- **Demo utilities** (`demo/`) — OWS demo agent registration scripts

## What Does NOT Live Here

- **Website code and publishable artifacts** — Lives in `observer-protocol-website` (Netlify deployment)
- **AT Enterprise dashboard code** — Lives in `agentic-terminal-db` (Next.js frontend, separate concerns)
- **Sovereign-specific UI** — Not a separate product; will render as constrained Enterprise view
- **Production secrets** — `secrets/` directory exists but is gitignored; actual keys managed separately

## What Deploys From Here, To Where

| Component | Deployment Target | Notes |
|-----------|------------------|-------|
| `api/api-server-v2.py` | `observer-api.service` (systemd) | Runs on FutureBit node, port 8000 |
| `schemas/*` | Copied to `observer-protocol-website` → Netlify | Published at observerprotocol.org/schemas/* |
| `migrations/*` | Applied to `agentic_terminal_db` | Via migration runner or manual apply |
| `docs/*.md` | Referenced in documentation | Not auto-deployed; human reference |

**Service name:** `observer-api.service`  
**Deployment URL:** `https://api.observerprotocol.org` (via Cloudflare tunnel)  
**Local development:** `http://localhost:8000`

## How to Verify You Are in the Right Repo

**1. Expected `git remote -v` output:**
```
origin	https://github.com/observer-protocol/observer-protocol-spec.git (fetch)
origin	https://github.com/observer-protocol/observer-protocol-spec.git (push)
```

**2. Expected path pattern:**
```
/media/nvme/observer-protocol
```

**3. Distinguishing file/directory:**
- `api/did_resolver.py` — DID resolution logic unique to OP
- `schemas/kyb-attestation/v1.json` — Canonical KYB schema
- `migrations/007_create_schema_migrations_table.py` — Migration tracking per v0.4

## Known Siblings

| Sibling | What Distinguishes It |
|---------|----------------------|
| `agentic-terminal-db` | AT Enterprise dashboard (Next.js frontend) — consumes OP API, different repo entirely |
| `observer-protocol-website` | Netlify-hosted website — publishes schemas copied FROM this repo, not source-of-truth |
| `agenticterminal-dashboard` | Alternative dashboard workspace — verify which is canonical before editing |

**Critical confusion to avoid:** The API server that actually runs on port 8000 is THIS repo (`/media/nvme/observer-protocol`), not `agentic-terminal-db`. During Phase 3, work was mistakenly done in `agentic-terminal-db` expecting it to affect the running API — it did not. Always verify `git remote -v` matches `observer-protocol/observer-protocol-spec.git` before API work.

---

**Last updated:** April 22, 2026 per Build Principles v0.4 §13.11