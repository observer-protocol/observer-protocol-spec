# Solana Rail for Observer Protocol

[![Status](https://img.shields.io/badge/status-active-success)](https://observer-protocol.io)
[![Solana](https://img.shields.io/badge/Solana-mainnet-purple)](https://solana.com)

Payment verification rail for Solana blockchain transactions.

## Overview

The Solana rail enables Observer Protocol agents to attest payments on the Solana blockchain. It supports:

- **SOL transfers** via System Program
- **SPL token transfers** (USDC, USDT, and any SPL token)
- **Ed25519 signature verification** for agent authentication
- **Human-readable amounts** with proper decimal handling

## Quick Start

### 1. Install Dependencies

```bash
pip install -r api/requirements.txt
```

### 2. Set Environment Variables

```bash
export DATABASE_URL="postgresql://user:pass@localhost/observer_protocol"
export HELIUS_API_KEY="your-helius-api-key"  # Optional, for better RPC
```

### 3. Start API Server

```bash
cd api
python main.py
```

### 4. Register an Agent

```bash
curl -X POST http://localhost:8000/observer/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "public_key": "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH",
    "solana_address": "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
  }'
```

### 5. Attest a Payment

```bash
# Sign canonical payload first: `${txSignature}:${sender}:${recipient}:${amount}:${mint}`
# Then submit attestation:

curl -X POST http://localhost:8000/observer/solana-attest \
  -H "Content-Type: application/json" \
  -d '{
    "tx_signature": "5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ",
    "sender_address": "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH",
    "recipient_address": "9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs",
    "amount_lamports": 1000000,
    "mint": "SOL",
    "agent_id": "my-agent",
    "signature": "base58-encoded-ed25519-signature"
  }'
```

## API Reference

### POST /observer/register

Register a new agent or update existing agent.

**Request Body:**
```json
{
  "agent_id": "string (required)",
  "public_key": "string - Ed25519 public key (base58) (required)",
  "solana_address": "string - Solana wallet address (optional)"
}
```

**Response:**
```json
{
  "agent_id": "my-agent",
  "public_key": "HN7cAB...",
  "solana_address": "HN7cAB...",
  "reputation_score": 0,
  "created_at": "2024-01-01T00:00:00Z",
  "last_seen": null
}
```

### POST /observer/solana-attest

Attest a Solana payment transaction.

**Request Body:**
```json
{
  "tx_signature": "string - Solana transaction signature (required)",
  "sender_address": "string - Sender wallet address (required)",
  "recipient_address": "string - Recipient wallet address (required)",
  "amount_lamports": "integer - Amount in lamports/units (required)",
  "mint": "string - 'SOL', 'USDC', 'USDT', or mint address (default: SOL)",
  "agent_id": "string - Agent ID (required)",
  "signature": "string - Ed25519 signature over canonical payload (required)"
}
```

**Canonical Payload Format:**
```
${txSignature}:${senderAddress}:${recipientAddress}:${amountLamports}:${mint}
```

**Example:**
```
5Ufgap...:HN7cAB...:9xQ7dG...:1000000:SOL
```

**Response:**
```json
{
  "attestation_id": "abc123...",
  "verified": true,
  "protocol": "solana",
  "amount": 1000000,
  "amount_human": 0.001,
  "token": "SOL",
  "token_symbol": "SOL",
  "tx_signature": "5Ufgap...",
  "timestamp": "2024-01-01T00:00:00Z",
  "reputation_delta": 10
}
```

**Error Codes:**
- `404` - Agent not found
- `400` - Invalid signature or transaction not finalized
- `409` - Transaction already attested

### GET /observer/agent/{agent_id}

Get agent information including reputation score.

**Response:**
```json
{
  "agent_id": "my-agent",
  "public_key": "HN7cAB...",
  "solana_address": "HN7cAB...",
  "reputation_score": 10,
  "created_at": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-01T00:00:00Z"
}
```

### GET /observer/attestations/{agent_id}

Get attestations for an agent.

**Query Parameters:**
- `limit` - Maximum number of attestations (default: 100)

**Response:**
```json
{
  "agent_id": "my-agent",
  "count": 1,
  "attestations": [
    {
      "attestation_id": "abc123...",
      "protocol": "solana",
      "tx_signature": "5Ufgap...",
      "verified": true,
      "amount": 1000000,
      "token": "SOL",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

## SDK Usage

### JavaScript/Node.js

```javascript
import ObserverClient, { createCanonicalPayload } from './core/observer-client.mjs';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

const client = new ObserverClient({
  baseUrl: 'http://localhost:8000',
  agentId: 'my-agent',
  publicKey: 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH'
});

// Register agent
await client.registerWithSolana({
  solanaAddress: 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH'
});

// Create and sign payload
const payload = createCanonicalPayload({
  txSignature: '5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ',
  senderAddress: 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH',
  recipientAddress: '9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs',
  amountLamports: 1000000,
  mint: 'SOL'
});

const signature = bs58.encode(
  nacl.sign.detached(
    Buffer.from(payload),
    bs58.decode(privateKey)
  )
);

// Attest payment
const receipt = await client.attestSolanaPaymentWithSignature({
  txSignature: '5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ',
  senderAddress: 'HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH',
  recipientAddress: '9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs',
  amountLamports: 1000000,
  mint: 'SOL',
  signature
});

console.log('Attestation receipt:', receipt);
```

## Supported Tokens

| Token | Mint Address | Decimals |
|-------|-------------|----------|
| SOL | Native | 9 |
| USDC | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | 6 |
| USDT | `Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB` | 6 |

Custom SPL tokens are supported by providing the full mint address.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      API Layer                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  POST /observer/solana-attest                         │  │
│  │  - Verify agent signature                             │  │
│  │  - Check for duplicates                               │  │
│  │  - Call verify_solana_transaction()                   │  │
│  │  - Store attestation                                  │  │
│  │  - Update reputation                                  │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                Solana Verification Core                      │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  solana_verify.py                                     │  │
│  │  - fetch_transaction() - RPC calls                    │  │
│  │  - parse_system_transfer() - SOL transfers            │  │
│  │  - parse_spl_transfer() - SPL tokens                  │  │
│  │  - verify_solana_transaction() - Main logic           │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                   RPC Endpoints                              │
│  - Helius (primary): https://mainnet.helius-rpc.com          │
│  - Solana Labs (fallback): https://api.mainnet-beta.solana.com│
└─────────────────────────────────────────────────────────────┘
```

## Testing

Run the test suite:

```bash
cd rails/solana
python test_solana_verify.py
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `HELIUS_API_KEY` | No | - | Helius API key for RPC access |

## Database Schema

### agent_keys
```sql
CREATE TABLE agent_keys (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(64) UNIQUE NOT NULL,
    public_key VARCHAR(128) NOT NULL,
    solana_address VARCHAR(64),
    reputation_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE
);
```

### attestations
```sql
CREATE TABLE attestations (
    id SERIAL PRIMARY KEY,
    attestation_id VARCHAR(64) UNIQUE NOT NULL,
    agent_id VARCHAR(64) NOT NULL REFERENCES agent_keys(agent_id),
    protocol VARCHAR(32) NOT NULL,
    tx_signature VARCHAR(128) NOT NULL,
    sender_address VARCHAR(64) NOT NULL,
    recipient_address VARCHAR(64) NOT NULL,
    amount_lamports BIGINT NOT NULL,
    token_mint VARCHAR(64) NOT NULL,
    verified BOOLEAN NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## License

MIT
