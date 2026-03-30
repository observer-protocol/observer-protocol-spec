# Observer Protocol: Portable Evidence Infrastructure for the AI Agent Economy

**Version 1.3.1 — March 30, 2026**

Boyd Cohen, Ph.D. — Co-Founder
Maxi (Agent #0001) — Co-Founder
Josep Sanjuas, Ph.D. — Technical Advisor
Leopoldo Bebchuk — Head of Product & Developer Relations

*observerprotocol.org | github.com/observer-protocol | api.observerprotocol.org/docs*

---

> **Implementation status:** Observer Protocol v1.1 is live on mainnet as of March 30, 2026. The protocol has completed a full architectural rebuild to W3C Decentralized Identifier (DID) and Verifiable Credential (VC) standards. All agents, organizations, and the protocol itself are now identified by `did:web` DIDs. All attestations are issued as W3C Verifiable Credentials. Agent evidence is carried as W3C Verifiable Presentations. This document reflects the current production architecture.

---

## Abstract

The rapid proliferation of autonomous AI agents — McKinsey projects agentic commerce will orchestrate $5 trillion in global transaction volume by 2030 — has outpaced the infrastructure required to verify their economic activity. Agents that complete hundreds of tasks on one platform start at zero on another. Verification history is siloed. Trust decisions are platform-dependent.

Catalini, Hui, and Wu (2026) formalize this structural crisis in "Some Simple Economics of AGI," identifying the collision between an exponentially decaying Cost to Automate and a biologically bottlenecked Cost to Verify as the defining tension of the agentic economy. Left unmanaged, this asymmetry produces what they term the Hollow Economy: explosive nominal output but decaying human agency and trust.

Our solution, Observer Protocol, is open evidence infrastructure: it collects, verifies, and issues cryptographically signed attestations of AI agent economic activity — making that evidence portable across platforms and payment rails as composable W3C Verifiable Credentials carried in Verifiable Presentations. Observer Protocol does not produce trust scores or make trust judgments. It provides verified evidence that counterparties, platforms, and third-party systems compose into their own context-appropriate trust decisions.

The protocol reached mainnet on February 22, 2026, and completed its v1.1 architectural rebuild to W3C DID/VC standards on March 30, 2026.

---

> **Key design principle:** Verifiable Attestation Certificates (VACs) are the primary protocol output. A VAC is a W3C Verifiable Presentation — a portable bundle of composable, cryptographically signed Verifiable Credentials. Platforms, marketplaces, and counterparties compose VAC evidence with their own observations to produce context-appropriate trust decisions. Observer Protocol makes no claim about what those decisions should be.

---

## 1. Problem Statement

### 1.1 The Verification Bottleneck

The agentic economy faces a structural coordination failure. As Catalini et al. (2026) demonstrate, the binding constraint on growth in an economy of abundant AI execution is not intelligence but human verification bandwidth — the scarce capacity to validate outcomes, audit behavior, and underwrite responsibility.

Three forces compound this constraint:

**The Missing Junior Loop.** Traditional apprenticeship pathways collapse as AI absorbs entry-level tasks. The pipeline that produces future verifiers is eroding precisely when verification is most needed.

**The Codifier's Curse.** Domain experts who encode their knowledge into AI training data accelerate their own displacement, converting scarce experience into abundant execution without preserving verification capacity.

**The Trojan Horse Externality.** When agent capabilities outpace oversight, deploying unverified systems becomes privately rational — introducing systemic risk through misaligned output that silently violates unmeasured intent.

### 1.2 The Trust Bootstrap Problem

Today's agent economy exhibits a pattern repeatedly identified by agents themselves:

> *"Payment requires acceptance. Acceptance requires trust. Trust requires a track record. A track record requires completed payments. It is a chicken-and-egg that every new agent faces."*

**Platform lock-in.** Evidence earned on Platform A has no portability to Platform B.

**Time-based proxies.** "Joined 6 months ago" and "500 followers" are trivially gameable and unable to distinguish new agents from bad actors.

**Self-reported metadata.** Without cryptographic verification, capabilities and history are declared rather than proven.

### 1.3 The KYA Gap

Know Your Agent (KYA) implementations from Visa, Sumsub, Beltic, Vouched, Skyfire, and others focus on two point-in-time problems: identity verification ("Who deployed this agent?") and payment authorization ("Did the human intend this transaction?"). Neither addresses the longitudinal evidence gap: portable, cryptographically verified economic history that accumulates over time and that third parties can compose into their own trust decisions.

### 1.4 A Founding Architectural Principle: Verify the Verifiable, Leave the Rest to Others

Whether a cryptographic signature is valid, whether an evidence hash matches an on-chain transaction, whether an attestation was created by the claimed agent, whether an organizational credential was signed by the claimed issuer — all of those are cryptographically verifiable. They are technical questions with deterministic answers.

Whether a given payment history is sufficient grounds to grant platform access, whether a particular KYB provider meets a relying party's compliance standards, or whether 50 Lightning micropayments constitute adequate evidence for a $50,000 procurement decision — these are contextual questions whose answers vary by relying party, jurisdiction, risk tolerance, and use case.

This principle applies consistently: subjective trust scores should be calculated separately from cryptographic proof. Reputation graphs should live in agents, organizations, or service providers — not protocols. KYB provider credibility is the relying party's determination, not a cryptographic protocol's. Scope level thresholds must be set by relying parties, not the protocol. In every case, a protocol should provide only the cryptographic evidence. Others provide the judgment.

For example: OP verifies that a payment preimage produces the claimed payment hash — a cryptographic fact with a deterministic answer. OP does not verify that the goods or services were delivered as agreed — a contextual judgment that varies by use case, jurisdiction, and the parties involved. The first is a protocol responsibility. The second is not.

---

## 2. Protocol Architecture

### 2.1 The OP/AT Architectural Separation

**Observer Protocol (OP)** is the core evidence infrastructure: open-source, permissionless, rail-agnostic. It handles attestation receipt and validation, Verifiable Credential issuance, organizational registry, and protocol API access. OP makes no trust judgments and is designed as neutral, composable infrastructure.

**Agentic Terminal (AT)** is the intelligence and IAM layer built on top of OP. AT provides dashboards, self-custody identity management (Sovereign), and operates its own scoring model (AT-ARS-1.0) built from OP evidence combined with other signals AT chooses to incorporate. AT's scoring is AT's product — not part of the OP protocol. OP's neutrality is not compromised by AT's commercial intelligence layer.

### 2.2 Identity Layer — W3C Decentralized Identifiers

Every principal in Observer Protocol — organizations, users, and agents — is identified by a W3C Decentralized Identifier using the `did:web` method. This replaces the previous `public_key_hash` identity model as of v1.1.

A `did:web` DID resolves to a DID Document served over HTTPS, containing the principal's public keys and verification methods. No blockchain dependency. No central registry. Resolution requires only HTTPS access to the hosting domain.

**DID structure by principal type:**

| Principal | DID format | Resolution URL |
|---|---|---|
| Observer Protocol (issuer) | `did:web:observerprotocol.org` | `https://observerprotocol.org/.well-known/did.json` |
| Agent | `did:web:observerprotocol.org:agents:{agent_id}` | `https://observerprotocol.org/agents/{agent_id}/did.json` |
| Organization | `did:web:observerprotocol.org:orgs:{org_id}` | `https://observerprotocol.org/orgs/{org_id}/did.json` |

All DID Documents use `Ed25519VerificationKey2020` with `publicKeyMultibase` encoding (base58btc, prefix `z`), per the W3C DID specification.

**Key rotation** is solved natively by `did:web`: updating the DID Document at the resolution URL changes the active public key without changing the DID string. An agent's attestation history is permanently bound to their DID, not their key material. Key compromise no longer means history loss.

**Key history and historical verification.** When an agent rotates keys, OP retains all historical `verificationMethod` entries in the DID Document, annotated with the period during which each key was active. This allows verifiers to confirm that a VC signed with a previous key was valid at the time of signing — the key was active when the attestation was issued, even if it has since been rotated out. Verifiers checking a historical VC resolve the agent's DID Document, find the key that was active at `issuanceDate`, and verify the signature against that key. Active keys are distinguished from historical keys by the presence of a `revoked` timestamp in the `verificationMethod` entry.

**Principal hierarchy.** The organizational attestation framework accommodates a full enterprise identity hierarchy: organization → employee → agent. In v1, this hierarchy is expressed through flat `OrgMembershipCredential` VCs establishing direct org→agent membership. Full delegation chain credentials (org → manager → agent) are a v1.1 deliverable.

### 2.3 Organizational Attestation Framework

Observer Protocol v1.0 introduced organizational identity — enabling enterprises to establish verified organizational context and issue attestations on behalf of their agents. An organizational attestation answers a question individual agent attestations cannot: whose agent is this?

**KYB Provider Attestations — Provider-Agnostic by Design.** Organizations can include KYB verification credentials from any provider of their choosing — MoonPay, Stripe, Sumsub, or any other issuer with a publicly resolvable DID. Observer Protocol records which KYB provider was used and verifies that the credential is cryptographically authentic — that it was genuinely signed by the claimed provider's DID. OP makes no judgment about whether that provider is credible or acceptable. That determination belongs to the relying party.

OP maintains a `trusted_issuers` registry of KYB provider DIDs whose signatures OP will verify. Registry membership does not constitute endorsement — it means OP will check the cryptographic signature. Any provider with a resolvable `did:web` DID can be added.

Credentials from issuers not in the `trusted_issuers` registry are still cryptographically verified — the signature is checked — but the verification response includes `issuer_trusted: false`. Relying parties decide whether to accept credentials from issuers outside the registry. OP rejects only credentials whose signatures are cryptographically invalid, regardless of registry status.

**KYB Credential Verification.** OP verifies KYB credential authenticity by resolving the KYB provider's DID Document and validating the cryptographic signature in the credential. OP is not agnostic about authenticity. It is agnostic about acceptability.

### 2.4 Attestation Layer — W3C Verifiable Credentials

Every economic event is recorded as a W3C Verifiable Credential — the atomic unit of Observer Protocol. Each VC is issued by OP (`did:web:observerprotocol.org`) using an Ed25519Signature2020 proof, and carries:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://observerprotocol.org/context/v1"
  ],
  "type": ["VerifiableCredential", "AgentAttestationCredential"],
  "id": "https://observerprotocol.org/credentials/{credential_id}",
  "issuer": "did:web:observerprotocol.org",
  "issuanceDate": "{iso8601_timestamp}",
  "expirationDate": "{iso8601_timestamp}",
  "credentialSubject": {
    "id": "did:web:observerprotocol.org:agents:{agent_id}",
    "rail": "lightning",
    "scope_level": 2,
    "counterparty_did": "did:web:observerprotocol.org:agents:{counterparty_id}",
    "evidence_hash": "sha256:{hash}",
    "timestamp": "{iso8601_timestamp}"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "{iso8601_timestamp}",
    "verificationMethod": "did:web:observerprotocol.org#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "{multibase_encoded_signature}"
  }
}
```

**VC types issued by OP:**

| VC type | Issuer | Description |
|---|---|---|
| `AgentAttestationCredential` | OP | One per verified economic event. Core evidence unit. |
| `OrgMembershipCredential` | Organization DID | Establishes agent belongs to org. Answers "whose agent is this?" |
| `KYBCredential` | KYB provider DID | Org-level credential. OP verifies authenticity only. |
| `PermissionCredential` | Granting principal DID | Scoped permission grants. |

**Dual Co-Signing.** After a successful transaction, both parties are encouraged to sign the attestation, preventing either party from tampering with the record. A dual-signed attestation carries full evidential weight. A single-party attestation remains valid but carries a reduced weight signal.

### 2.5 Attestation Scoping — Six Trust Levels

Not all attestations carry equal verification weight. Observer Protocol introduces attestation scoping — a six-level framework providing consistent confidence signals:

| Level | Name | Description | Current status |
|---|---|---|---|
| 0 | Revoked | No attestation / revoked | — |
| 1 | Self-attested | Agent's own claims | Live |
| 2 | Counterparty attested | Signed by transaction counterparty | Live |
| 3 | Partner attested | Signed by registered OP partner | Live |
| 4 | Organization attested | Signed by registered organization with KYB | Live |
| 5 | OP verified | Directly verified by Observer Protocol | Live (x402) |

The `scope_level` field is embedded in every `AgentAttestationCredential` as part of `credentialSubject`. Relying parties set their own minimum scope thresholds — OP does not.

### 2.6 VAC — W3C Verifiable Presentation

A Verifiable Attestation Certificate (VAC) is a W3C Verifiable Presentation — a signed bundle of Verifiable Credentials assembled by the agent and carried with them across platforms and payment rails.

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiablePresentation"],
  "id": "urn:uuid:{presentation_id}",
  "holder": "did:web:observerprotocol.org:agents:{agent_id}",
  "verifiableCredential": [
    { "/* AgentAttestationCredential — Lightning payment */" : null },
    { "/* AgentAttestationCredential — x402 payment */" : null },
    { "/* OrgMembershipCredential — org context */" : null },
    { "/* KYBCredential — MoonPay KYB */" : null }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "{iso8601_timestamp}",
    "verificationMethod": "did:web:observerprotocol.org:agents:{agent_id}#key-1",
    "proofPurpose": "authentication",
    "proofValue": "{agent_signature_over_VP}"
  }
}
```

**The agent is the carrier.** OP issues individual VCs; the agent assembles them into a VP and signs it. The agent carries the VP and presents it to counterparties and platforms directly — no query to OP required for verification. Any verifier with HTTPS access can verify a presented VP by resolving the relevant DIDs.

**Selective disclosure.** The `verifiableCredential` array contains only the VCs relevant to the current context. An agent presenting to a Lightning-native counterparty presents their Lightning attestations. An agent presenting to an enterprise platform presents their org membership and KYB credentials. The agent holds the full set; they present contextually relevant subsets.

**DB as cache.** OP's database stores individual VCs as a cache and index for convenience. It is not the authoritative record. The agent's VP is the authoritative record. `POST /vp/verify` requires no DB lookup — verification is purely cryptographic via DID resolution.

**Evidential vs Operational VACs.** An expired VC retains its full evidential value as historical record — it proves the event occurred. Operational VCs (permissions, active authorizations) expire and must be re-issued.

**VP expiration.** VPs do not have an independent expiration date. A VP is valid as long as its embedded VCs are valid and the VP signature itself is valid. When an agent's VCs expire or new attestations are added, the agent should assemble and sign a fresh VP incorporating the updated VC set. OP recommends that active agents refresh their VP at least weekly to ensure counterparties and platforms receive a current evidence picture. `POST /vp/submit` updates the cached VP at any time.

### 2.7 The Shared State Problem — Solved by Agent-Carried VP

Observer Protocol is open-source infrastructure. Any organization can run their own OP instance. This creates a fundamental tension: the network effect argument only holds if participants contribute to and read from the same shared evidence pool.

The solution — confirmed in v1.1 — is **Option C: Agent as Evidence Carrier**. VCs contain the agent's full signed attestation history. The database becomes a cache, not the authoritative record. An agent carries their complete evidence. Any OP instance verifies a presented VP without having previously seen those attestations — the evidence is self-contained and cryptographically signed.

Under Option C, an agent on Instance A presents their full VP to Instance B. Instance B verifies signatures on each embedded VC by resolving the issuer's DID Document. Instance B can cache the result. The agent owns their evidence. Portability is genuinely self-sovereign.

This aligns directly with the W3C Verifiable Presentation model and is live in production as of v1.1.

---

## 3. Technical Design

### 3.1 Cryptographic Primitives

- **Ed25519** for all key pairs, attestation signatures, VC proofs, and VP proofs — speed, small sizes, side-channel resistance, and native alignment with W3C DID/VC specification.
- **SHA-256** for evidence hashing and content addressing.
- **HMAC-SHA256** for API authentication tokens and webhook payload signing.
- **base58btc multibase** (`z` prefix) for all public key encoding in DID Documents per W3C specification.

The choice of Ed25519 means no key changes were required during the DID migration — existing Ed25519 key material was carried forward into the new DID Documents.

### 3.2 API Specification

**Base URL:** `https://api.observerprotocol.org`

**DID Resolution endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/did.json` | OP's own DID Document |
| GET | `/agents/{agent_id}/did.json` | Agent DID Document |
| GET | `/orgs/{org_id}/did.json` | Organization DID Document |

**Agent endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/observer/register-agent` | Register agent — returns DID + DID Document |
| PUT | `/agents/{agent_id}/keys` | Key rotation — updates DID Document, DID unchanged |
| GET | `/agents/{agent_id}/verify` | Verify agent identity |

**VAC / VP endpoints:**

| Method | Path | Description |
|---|---|---|
| GET | `/vac/{agent_id}` | Get cached VP for agent |
| POST | `/vac/{agent_id}/refresh` | Force VP refresh |
| POST | `/vac/{agent_id}/present` | Agent submits signed VP |
| POST | `/vp/verify` | Verify a VP cryptographically — no DB lookup |
| POST | `/vp/submit` | Submit VP for caching (strongly recommended) |
| POST | `/vp/reconstruct` | Reconstruct VP from cached VCs (recovery) |

**Organization endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/observer/register-org` | Register organization — returns DID |
| GET | `/observer/orgs/{org_id}` | Get organization details |
| POST | `/observer/orgs/{org_id}/revoke` | Revoke organization |

**Attestation endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/attestations` | Submit attestation |
| GET | `/vac/{agent_id}/attestations` | Get agent attestations |

*Full documentation: api.observerprotocol.org/docs*

### 3.3 Multi-Rail Support — Current Verification Status

| Rail | Verification level | Status |
|---|---|---|
| x402 / USDC on Base | Level 3 — on-chain verified | Operational |
| Lightning / L402 | Level 1-2 | Automated preimage validation in development |
| Nostr zaps | Level 2 | Zap receipt verification live |
| Traditional rails | Level 1-2 | No cryptographic settlement layer |
| AP2-compatible | Planned | OP provides longitudinal evidence layer |

### 3.4 Webhook Delivery

Real-time webhook delivery: at-least-once semantics, HMAC-SHA256 payload signing, exponential backoff retry, endpoint health monitoring.

**Events:** `attestation.created`, `attestation.verified`, `vac.issued`, `agent.registered`, `organization.verified`, `did.registered`, `did.rotated`, `vc.issued`, `vp.submitted`.

---

## 4. The Agentic Evidence Stack

Observer Protocol occupies the Evidence & Credential layer — providing composable, verified evidence that layers above use to make trust decisions. OP does not make those decisions.

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│  Marketplaces and platforms compose OP evidence + their own  │
│  observations into trust decisions                           │
├─────────────────────────────────────────────────────────────┤
│                   IAM / INTELLIGENCE LAYER                   │
│  AT scoring model, self-custody IAM, analytics               │
│  (Agentic Terminal / Sovereign)                              │
├─────────────────────────────────────────────────────────────┤
│                   ORCHESTRATION LAYER                        │
│  Agent-to-agent communication & coordination                 │
│  (Google A2A, Anthropic MCP, OpenClaw)                       │
├─────────────────────────────────────────────────────────────┤
│                PAYMENT AUTHORIZATION LAYER                   │
│  "Did the human intend this transaction?"                    │
│  (Google AP2, Coinbase x402, Lightning L402)                 │
├─────────────────────────────────────────────────────────────┤
│           ★ EVIDENCE & CREDENTIAL LAYER (OP)                 │
│  "What has this agent verifiably done?" / "Whose agent?"     │
│  W3C VCs · W3C VPs · DID-based identity · Cross-rail        │
├─────────────────────────────────────────────────────────────┤
│                   IDENTITY LAYER (KYA / KYB)                 │
│  (MoonPay KYB, Sumsub, Beltic, Vouched, Skyfire)             │
├─────────────────────────────────────────────────────────────┤
│                     SETTLEMENT LAYER                         │
│  (Lightning Network, Base/USDC, ACH, SWIFT, Sui)             │
└─────────────────────────────────────────────────────────────┘
```

Identity (KYA) answers *who*. Payment authorization (AP2) answers *what was intended*. Observer Protocol answers *what actually happened, verifiably, over time, and on whose authority*. VACs (W3C VPs) are the portable evidence mechanism — each verified interaction builds an evidence record that any relying party can compose into their own trust framework.

---

## 5. Economic Model

### 5.1 Evidence Portability as a Network Effect

Without Observer Protocol: evidence accumulated on one platform has no value on another. The cost of the 100th interaction on a new platform is identical to the 1st.

With Observer Protocol: a platform onboarding an agent with 150 cross-rail, cross-platform attestations can make a more informed access decision than one onboarding an agent with zero history — not because OP told them to trust the agent, but because OP gave them composable evidence to evaluate.

This creates a positive-sum network effect: the more agents and platforms that contribute to and consume OP evidence, the richer the evidence available for every trust decision across the ecosystem. This network effect is realized under Option C (agent-as-VP-carrier) — live as of v1.1.

### 5.2 The Evidence Moat

**Temporal:** Verified evidence histories cannot be manufactured overnight. Six months of cross-rail attestation history represents real signal. The economic cost of manufacturing a credible history scales with its depth, providing practical deterrence proportional to the value of the credential sought.

**Compositional:** Cross-platform, cross-rail evidence is more valuable than single-platform evidence.

**Architectural:** By providing evidence rather than trust judgments, OP becomes more valuable as the ecosystem of intelligence layers grows — each new consumer of OP evidence increases the incentive for agents to build attestation history.

### 5.3 Open Protocol, Sustainable Ecosystem

Observer Protocol is free for agents to register and submit attestations. Value-added services — AT's intelligence platform, institutional tooling, enterprise integrations — are built on top.

The sustainability model is honest about two scenarios: commercial enterprise demand drives accelerated development and finances OP infrastructure through AT's commercial revenue. If enterprise adoption is slower than expected, OP is developed and maintained as a community open-source project. The protocol's open-source foundation means neither scenario results in OP disappearing; the development pace varies.

---

## 6. Implementation Status

Observer Protocol v1.1 is live on mainnet as of March 30, 2026.

**What is live:**
- W3C DID (`did:web`) identity for all principals — agents, organizations, OP itself
- W3C Verifiable Credential issuance for all attestation types
- W3C Verifiable Presentation as the portable VAC format
- Agent-as-carrier (Option C) — VP is the authoritative record, DB is cache
- `POST /vp/verify` — stateless VP verification via DID resolution, no DB lookup
- Key rotation via `PUT /agents/{id}/keys` — DID unchanged, history preserved
- x402/USDC Level 3 verification operational
- Organizational registry with KYB provider credential verification
- Trusted issuers registry for KYB provider DID validation
- Webhook delivery for all credential lifecycle events

**In active development:**
- Lightning/L402 automated preimage validation (Level 3)
- OpenTimestamps Bitcoin anchoring for tamper-resistant timestamps
- `DelegationCredential` for full org→employee→agent hierarchy chains (v1.1)

**Known limitations:**
- Lightning attestations operate at Level 1-2 pending preimage validation
- Traditional rail attestations limited to Level 1-2
- Agents registered before v1.1 without stored public keys require re-registration to receive a DID

---

## 7. Integration Guide

### 7.1 For Agent Developers

1. Generate an Ed25519 key pair. Store the private key securely.
2. Register with Observer Protocol via `POST /observer/register-agent`. Returns your `agent_did` and DID Document.
3. Submit attestations after economic events via `POST /attestations`.
4. Request your VP via `GET /vac/{agent_id}` or generate it locally from your VCs.
5. Submit your VP via `POST /vp/submit` — this is your backup and cache.
6. Present your VP (or a contextually relevant subset) to counterparties and platforms directly.
7. Rotate keys at any time via `PUT /agents/{agent_id}/keys` — your DID and history are preserved.

### 7.2 For Platform Operators

Platform operators receive composable VP evidence and determine what it means for their own trust decisions.

**At onboarding:** Call `POST /vp/verify` with the agent's presented VP. Returns per-VC verification results with no OP DB lookup required — purely cryptographic.

**At task assignment:** Use attestation evidence — rail coverage, scope levels, counterparty diversity, time distribution — as inputs to your own agent-matching logic.

**At payment:** Set minimum evidence requirements for different transaction value tiers. OP provides the evidence; you set the thresholds.

### 7.3 For Organizations

1. Complete KYB verification through a KYB provider with a resolvable `did:web` DID.
2. Register the organization via `POST /observer/register-org`. Returns your `org_did`.
3. Register agents as members of the organization — they receive `OrgMembershipCredential` VCs.
4. Issue organizational attestations on behalf of agents.
5. Agents inherit organizational context — "whose agent is this?" becomes cryptographically answerable.

### 7.4 Use Cases

**Agentic marketplaces:** A marketplace calls `POST /vp/verify` on an agent's presented VP, verifies the embedded VCs, and combines that evidence with its own platform observations to produce a marketplace-specific trust score. OP provides the cross-platform evidence layer; the marketplace provides context-specific scoring.

**Autonomous trading agents:** Cryptographic proof of payment history across rails, carried as a portable VP that persists across platforms.

**Multi-agent workflows:** Agents delegating to other agents call `POST /vp/verify` on counterparty VPs as one input to delegation decisions.

**Enterprise procurement:** Organizations call `POST /vp/verify` as part of KYA due diligence, accessing verified economic history alongside organizational attestations and KYB-anchored credentials.

---

## 8. Roadmap

Detailed roadmap and implementation status are tracked in the GitHub repository at github.com/observer-protocol. This whitepaper focuses on the protocol's design principles and architecture rather than development timelines.

**Near-term (v1.1):**
- Lightning/L402 Level 3 automated preimage validation
- OpenTimestamps Bitcoin anchoring for tamper-resistant timestamps
- `DelegationCredential` for full organizational hierarchy chains
- Multi-stakeholder technical steering committee (governance milestone)

**Future directions:**
- ZK-SNARK selective disclosure for privacy-preserving VP presentation
- Federation protocol for multi-instance OP deployments
- `did:btc` support for high-assurance principal anchoring
- HD key derivation standard for enterprise agent deployments

---

## 9. References

Catalini, C., Hui, X., and Wu, J. (2026). "Some Simple Economics of AGI." MIT Sloan. arXiv:2602.20946.

Catalini, C. and Gans, J. S. (2020). "Some Simple Economics of the Blockchain." Communications of the ACM, 63(7), 80-90.

Catalini, C. and Tucker, C. E. (2018). "Antitrust and Costless Verification." SSRN.

Google Cloud. (2025). "Announcing Agent Payments Protocol (AP2)." Google Cloud Blog.

Lightning Labs. (2026). "AI Agent Tools for Native Bitcoin Lightning Payments." github.com/lightninglabs.

McKinsey & Company. (2025). Agentic Commerce Market Projections. McKinsey Global Institute.

Cohen, B. (2025). Bitcoin Singularity.

Rodriguez Garzon, S. et al. (2025). "AI Agents with Decentralized Identifiers and Verifiable Credentials." arXiv:2511.02841v2.

W3C. (2022). Decentralized Identifiers (DIDs) v1.0. w3.org/TR/did-core/.

W3C. (2022). Verifiable Credentials Data Model v1.1. w3.org/TR/vc-data-model/.

---

## Appendix A: Glossary

**AgentAttestationCredential:** A W3C Verifiable Credential recording one verified economic event. The atomic unit of Observer Protocol evidence.

**Attestation:** A cryptographically signed Verifiable Credential recording an agent's completed economic activity.

**Attestation Scoping:** The six-level framework (0–5) specifying verification confidence for each attestation.

**Agentic Terminal (AT):** The intelligence and IAM layer built on Observer Protocol. AT operates its own scoring model — AT products, not OP protocol outputs.

**Composability:** The design property of VPs whereby individual VC components can be selectively presented to different relying parties for different contexts.

**DID (Decentralized Identifier):** W3C standard for self-sovereign, cryptographically verifiable identifiers. OP uses `did:web` for all principals.

**DID Document:** A JSON document served at a well-known URL containing a principal's public keys and verification methods. Updated for key rotation without changing the DID string.

**Evidence Layer:** The architectural role of Observer Protocol — collecting, verifying, and issuing signed evidence of agent economic activity without making trust judgments.

**KYA / KYB:** Know Your Agent / Know Your Business — verification paradigms for agents and organizations respectively.

**OrgMembershipCredential:** A VC issued by an organization's DID establishing that an agent is a member of that organization.

**Trusted Issuers Registry:** OP's pre-approved list of KYB provider DIDs whose signatures OP will verify. Registry membership does not constitute endorsement of the provider.

**VAC (Verifiable Attestation Certificate):** A W3C Verifiable Presentation — a portable bundle of composable, cryptographically signed VCs. The primary output of Observer Protocol. Carried by the agent, not stored by OP.

**VC (Verifiable Credential):** A W3C standard cryptographically signed credential issued by one DID about another DID. Each attestation in OP is a VC.

**VP (Verifiable Presentation):** A W3C standard signed bundle of VCs presented for a specific context. The W3C equivalent of a VAC. Agent-signed; contains subset of VCs relevant to the presentation context.

---

## Appendix B: Current and Planned Technical Extensions

### B.1 x402 / Stripe — HTTP-Native Agent Payments

Level 3 verification operational. Base blockchain integration via viem, USDC transfer event parsing, amount/address matching. Stripe production integration live. Attestations issued as `AgentAttestationCredential` VCs with `rail: "x402"`.

### B.2 Lightning / lnget — Native Lightning Reporting

Agent #0001 operates a sovereign Lightning node with L402 endpoint. Attestations at Level 1-2. Automated preimage validation in active development — highest priority infrastructure item.

### B.3 Corpo / x402 — Enterprise Standards Collaboration

Peter Vessenes proposed a three-layer reference architecture: x402 (payment rail) → Observer Protocol (evidence and credential layer) → Corpo (enterprise identity standards). OP occupies the trust evidence layer between payment execution and enterprise identity systems.

### B.4 OWS / MoonPay — KYB Credential Integration Pilot

The Open Wallet Standard (OWS) registration combined with MoonPay KYB verification is the first technical pilot for processing external KYB credentials within the organizational attestation framework. MoonPay's `did:web:moonpay.com` DID is in OP's trusted issuers registry. The pilot validates: how KYB credentials are ingested as W3C VCs, how provider signatures are verified against published DID Documents, and how KYB provenance is embedded into organizational VPs.

OP makes no claim that MoonPay is a preferred or superior KYB provider. The pilot demonstrates the technical integration pattern that any KYB provider with a resolvable `did:web` DID can implement.

### B.5 Nostr — Decentralized Social Verification

Nostr zap verification live. Zap receipts serve as cryptographic evidence for attestations at Level 2, providing a decentralized social verification layer without platform dependency.

### B.6 Sui — Move Language Integration

Inbound interest from Sui. Technical scoping for Move-native attestation verification in progress.

---

*Observer Protocol v1.3.1 — March 30, 2026*
*observerprotocol.org | hello@observerprotocol.org*
*License: CC BY 4.0*
