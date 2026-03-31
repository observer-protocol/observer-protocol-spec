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

```bash
# Clone and setup
cd observer-protocol
pip install -r api/requirements.txt

# Set database URL
export DATABASE_URL="postgresql://user:pass@localhost/observer_protocol"

# Start API
python api/main.py
```

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
