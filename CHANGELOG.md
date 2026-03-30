# Changelog

All notable changes to Observer Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-03-30

### Documentation
- Published comprehensive whitepaper v1.3.1 covering DID/VC architecture
- Documented W3C standards compliance (`did:web`, VC/VP formats)
- Added detailed protocol architecture and economic model sections
- Clarified OP/AT separation of concerns

## [1.1.0] - 2026-03-30

### Added (DID/VC Rebuild)
- **W3C Decentralized Identifiers (`did:web`)** — All principals (agents, organizations, OP itself) now use `did:web` DIDs
- **DID Document resolution** — `/.well-known/did.json`, `/agents/{id}/did.json`, `/orgs/{id}/did.json` endpoints
- **Key rotation support** — Update keys without changing DID, preserving attestation history
- **Historical key verification** — Verify VCs signed with rotated keys

- **W3C Verifiable Credentials (VCs)** — All attestations issued as VCs with Ed25519Signature2020 proofs
- **W3C Verifiable Presentations (VPs)** — Agent-carried portable evidence bundles (VACs)
- **Selective disclosure** — Agents present contextually relevant VC subsets
- **Stateless VP verification** — `POST /vp/verify` requires no DB lookup

- **Option C: Agent as Evidence Carrier** — DB is cache only, VP is authoritative record
- **Organization hierarchy** — `OrgMembershipCredential` VCs for org→agent relationships
- **KYB provider integration** — Verify credentials from any `did:web` KYB provider
- **Trusted issuers registry** — Pre-approved KYB provider DID list

### Changed
- **Identity model** — Replaced `public_key_hash` with `did:web` DIDs
- **Attestation format** — Summary-stats VACs replaced with W3C VC/VP
- **API endpoints** — New DID resolution and VP verification endpoints
- **Database schema** — Migrations 003 (DID columns) and 004 (VP cache)

### Migration Notes
- Agents registered before v1.1 without stored public keys require re-registration to receive DIDs
- Existing attestations remain valid and will be migrated to VC format

## [1.0.0] - 2026-02-22

### Added (Initial Release)
- **Observer Protocol mainnet launch** — First publicly verifiable agent payment infrastructure
- **Agent registration** — Public key-based agent identity
- **Attestation framework** — Six-level trust scoping (0-5)
- **Multi-rail support** — x402/USDC Level 3, Lightning L402 Level 1-2, Nostr zaps Level 2
- **Organizational attestations** — Enterprise identity and KYB integration
- **Webhook delivery** — Real-time attestation event notifications
- **First A2A payment** — Cryptographically verified agent-to-agent payment (Vicky → Maxi)

### Technical
- FastAPI-based API server
- PostgreSQL database for attestation storage
- Ed25519 cryptographic signatures
- Cloudflare tunnel for public API access

---

## Future Releases

### [1.2.0] - Planned
- Lightning/L402 Level 3 automated preimage validation
- OpenTimestamps Bitcoin anchoring
- `DelegationCredential` for full org→employee→agent hierarchy
- Multi-stakeholder technical steering committee

### [2.0.0] - Future Directions
- ZK-SNARK selective disclosure
- Federation protocol for multi-instance OP deployments
- `did:btc` support for high-assurance anchoring
- HD key derivation standard for enterprise agents
