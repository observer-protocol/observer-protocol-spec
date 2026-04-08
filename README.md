# Observer Protocol

Multi-chain payment attestation protocol for autonomous agents.

## Overview

Observer Protocol enables agents to verify and attest payments across multiple blockchain networks. Each "rail" provides verification for a specific blockchain or payment system.

## Multi-Rail Status

| Rail | Status | Description |
|------|--------|-------------|
| Bitcoin | 🚧 In Development | Bitcoin on-chain and Lightning Network payments |
| Ethereum | 🚧 In Development | ETH and ERC-20 token transfers |
| **Solana** | ✅ **Live** | **SOL and SPL token transfers (USDC, USDT, etc.)** |
| Base | 📅 Planned | Base L2 payments |

## Quick Start
### Clone and setup
```bash
git clone https://github.com/observer-protocol/observer-protocol-spec/
cd observer-protocol
pip install -r api/requirements.txt
```

### Install PostgreSQL
PostgreSQL is a required component of the OP Server

Download the installer from:
https://www.postgresql.org/download/

After installation, access the PostgreSQL server via PgAdmin and create a new database called "observer_protocol"


# Set the database URL as an environment variable
Powershell
```powershell
$Env:DATABASE_URL="postgresql://user:pass@localhost/observer_protocol"
```

Bash
```bash
export DATABASE_URL="postgresql://user:pass@localhost/observer_protocol"
```

# Start API
python api/main.py


## API Endpoints

### Health Check
```bash
curl http://localhost:8000/health
```

### Register Agent
```bash
curl -X POST http://localhost:8000/observer/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "public_key": "base58-ed25519-pubkey",
    "solana_address": "solana-wallet-address"
  }'
```

### Attest Payment
```bash
curl -X POST http://localhost:8000/observer/solana-attest \
  -H "Content-Type: application/json" \
  -d '{
    "tx_signature": "solana-tx-signature",
    "sender_address": "sender-wallet",
    "recipient_address": "recipient-wallet",
    "amount_lamports": 1000000,
    "mint": "SOL",
    "agent_id": "my-agent",
    "signature": "ed25519-signature"
  }'
```

## Directory Structure

```
observer-protocol/
├── api/
│   ├── main.py              # FastAPI application
│   └── requirements.txt     # Python dependencies
├── core/
│   └── observer-client.mjs  # JavaScript SDK
├── rails/
│   └── solana/
│       ├── solana_verify.py     # Core verification logic
│       ├── test_solana_verify.py # Test suite
│       └── README.md            # Rail documentation
└── README.md                # This file
```

## Supported Chains

### Solana ✅ Live

The Solana rail supports:
- **SOL transfers** via System Program
- **SPL token transfers** (USDC, USDT, any SPL token)
- **Ed25519 signature verification**
- **Human-readable amounts** with proper decimals

See [rails/solana/README.md](rails/solana/README.md) for detailed documentation.

## SDK

### JavaScript

```javascript
import ObserverClient from './core/observer-client.mjs';

const client = new ObserverClient({
  baseUrl: 'http://localhost:8000',
  agentId: 'my-agent',
  publicKey: 'base58-pubkey'
});

// Register with Solana address
await client.registerWithSolana({ solanaAddress: 'HN7cAB...' });

// Attest a payment
const receipt = await client.attestSolanaPaymentWithSignature({
  txSignature: '5Uf...',
  senderAddress: 'HN7cAB...',
  recipientAddress: '9xQ7...',
  amountLamports: 1000000,
  mint: 'SOL',
  signature: 'base58-sig'
});
```

## Development

### Running Tests

```bash
cd rails/solana
python test_solana_verify.py
```

### Database Setup

```bash
# Create database
sudo -u postgres createdb observer_protocol

# Tables are auto-created on API startup
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `HELIUS_API_KEY` | No | Helius API key for Solana RPC |

## License

MIT

---

## Agentic Identity Protocol (AIP) v0.3.1

**The credential layer for sovereign agents.**

AIP provides cryptographic identity, delegation, and verification infrastructure for economically autonomous AI agents.

### What's AIP?

AIP (Agentic Identity Protocol) enables:
- **DID-based identity** — W3C `did:web` standard for agent identity
- **KYB attestation** — Verifiable Credentials for organization verification
- **Hierarchical delegation** — Organizations delegate authority to agents with scoped constraints
- **Cross-rail verification** — Proof of payment across Lightning, Solana, EVM, and more
- **Portable reputation** — Credentials travel with the agent, not the platform

### Key Documents

| Document | Description |
|----------|-------------|
| [AIP-IMPLEMENTATION.md](./AIP-IMPLEMENTATION.md) | Full technical implementation guide |
| [AIP-SUMMARY.md](./AIP-SUMMARY.md) | Quick reference for developers |
| [AIP-TYPE-REGISTRY.md](./AIP-TYPE-REGISTRY.md) | Governed enumerated values |
| [spec/AIP-v0.3.1.md](./spec/AIP-v0.3.1.md) | Formal specification |

### Core Components

```python
# Issue KYB VC
POST /aip/credentials/kyb

# Issue Delegation Credential
POST /aip/credentials/delegation

# Verify delegation chain
GET /aip/chain/verify/{agent_id}

# Query Type Registry
GET /aip/type-registry/allowed_counterparty_types
```

### Architectural Principles

1. **did:web ONLY** — No fallback methods (Section 9.2)
2. **Eager verification** — Full chain verified at query time (Section 9.3)
3. **Minimal remediation** — Structure only; AT provides content (Section 9.1)
4. **PR-governed registry** — Type extensions via spec repo (Section 9.5)

**Status:** ✅ Implemented — All 23 tests passing

**Sign-off:** Leo Bebchuk (Head of Product & Developer Relations)
