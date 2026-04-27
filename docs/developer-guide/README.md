# Observer Protocol — Developer Documentation

Welcome to the Observer Protocol developer docs. OP is the open identity and verification protocol for autonomous agents — W3C DID/VC standards, chain-agnostic, rail-agnostic.

## Who are you?

<table>
<tr>
<td width="50%">

### I'm a network operator

I run a marketplace, platform, or network and want to integrate OP for my users' agents.

**Start here:** [Network Operator Guide](./network-operator-guide.md)

You'll learn how to:
- Register as an integrator
- Verify agent transactions via the chain-agnostic API
- Register your own VAC extension (e.g., reputation scores)
- Understand the sandbox → production path

</td>
<td width="50%">

### I'm building an agent

I have an agent (or I'm building one) and want to register it on OP.

**Start here:** [Agent Developer Quickstart](./agent-quickstart.md)

You'll learn how to:
- Register your agent and get a DID
- Prove key ownership via challenge-response
- Retrieve your agent's VAC
- Submit verified activity

</td>
</tr>
</table>

## Documentation map

| Document | What it covers |
|----------|---------------|
| [Architecture Overview](./architecture.md) | Protocol layers, credential types, how OP fits into the agent commerce stack |
| [Network Operator Guide](./network-operator-guide.md) | Integration path for platforms, marketplaces, and networks |
| [Agent Developer Quickstart](./agent-quickstart.md) | Register an agent, sign challenges, retrieve VAC — in 15 minutes |
| [API Reference](./api-reference.md) | Every endpoint, request/response schemas, error codes |
| [AT-ARS Trust Score](./trust-score.md) | Scoring methodology, components, API |
| [VAC Extensions](./vac-extensions.md) | Register and issue third-party attestation extensions |
| [Chain Verification](./chain-verification.md) | Chain-agnostic verification, Lightning three-tier model, adapter interface |
| [Sandbox Environment](./sandbox.md) | Developer sandbox tier, fixtures, testing |
| [Specifications](./specifications.md) | Links to AIP v0.5, capability specs, schemas |

## Live infrastructure

| Surface | URL | Purpose |
|---------|-----|---------|
| Production API | `api.observerprotocol.org` | Live OP endpoints |
| Developer Sandbox | `sandbox.observerprotocol.org` | Sandbox with fixtures and interactive docs |
| Sandbox API Docs | `sandbox.observerprotocol.org/docs/` | Interactive Swagger UI for sandbox |
| Sovereign Dashboard | `app.agenticterminal.io/sovereign` | Agent management UI |
| Enterprise Dashboard | `app.agenticterminal.io/enterprise` | Organization management |
| DID Resolution | `api.observerprotocol.org/agents/{id}/did.json` | Public DID documents |
| Receipt Verifier | `observerprotocol.org/verify-receipt.html` | Client-side credential verification |

## Getting sandbox access

The sandbox is a developer-isolated environment with fixture data and deterministic policy outcomes for integration testing.

To get sandbox API keys, email **[dev@observerprotocol.org](mailto:dev@observerprotocol.org)** with:
- Your name and organization
- What you're building
- Which chain(s) you're integrating with

We respond within 24 hours.

## Current protocol version

- **AIP:** [v0.5](../AIP_v0.5.md) (April 2026)
- **AT-ARS:** 1.0
- **Chain adapters:** Lightning (live), TRON (live), Stacks (stub)
- **VC format:** W3C Verifiable Credentials Data Model 2.0
- **DID method:** `did:web`
- **Signature suite:** Ed25519Signature2020
