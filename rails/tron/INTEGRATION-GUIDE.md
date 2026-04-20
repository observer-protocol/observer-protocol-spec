# TRON Rail — Observer Protocol Integration

Complete TRON rail integration with counterparty-signed receipt architecture for the Observer Protocol.

## Features

- **TRON Address Derivation**: secp256k1 → Keccak256 → Base58Check with T prefix
- **TronGrid API Integration**: Full TRC-20 transaction verification
- **Receipt VCs**: W3C Verifiable Credentials for TRON transactions
- **AIP Type Registry**: `tron` and `tron:trc20` rail types
- **VAC Extensions**: Store verified receipts in agent credentials
- **Counterparty Signing**: Ed25519Signature2020 proof support

## Installation

```bash
# From observer-protocol directory
cd rails/tron
npm install  # if dependencies needed
```

## Configuration

Environment variables:

```bash
# Required for TronGrid API
export TRONGRID_API_KEY="your-api-key-here"

# Required for OP signing
export OP_DID="did:op:observerprotocol"
export OP_SIGNING_KEY="64-char-hex-private-key"

# Optional - network selection (mainnet, shasta, nile)
export TRON_NETWORK="shasta"  # default: mainnet
```

Get a free TronGrid API key at: https://www.trongrid.io/

## Quick Start

```javascript
import { TronRail } from './index.mjs';

// Initialize
const tron = new TronRail({
  apiKey: process.env.TRONGRID_API_KEY,
  network: 'shasta',  // Use shasta testnet for development
  minConfirmations: 1 // Lower for testnet
});

// Create a receipt
const receipt = await tron.createReceipt({
  issuer_did: 'did:op:agent-sender',
  subject_did: 'did:op:agent-recipient',
  rail: 'tron:trc20',
  asset: 'USDT',
  amount: '1000000',  // 1 USDT (6 decimals)
  tron_tx_hash: 'a1b2c3d4e5f6...',  // 64 hex chars
  timestamp: '2026-04-13T14:00:00Z',
  sender_address: 'TJ...',
  recipient_address: 'TJ...',
  token_contract: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
  org_affiliation: 'Example Corp'
});

// Verify the receipt
const result = await tron.verifyReceipt(receipt);
console.log('Verified:', result.verified);
console.log('Confirmations:', result.details.confirmations);
```

## API Reference

### TronRail

Main class for TRON rail operations.

#### Constructor Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | `TRONGRID_API_KEY` | TronGrid API key |
| `network` | string | `'mainnet'` | Network: mainnet, shasta, nile |
| `opDid` | string | `OP_DID` | Observer Protocol DID |
| `signingKey` | string | null | Ed25519 private key for signing |
| `minConfirmations` | number | 19 | Minimum block confirmations |
| `maxAgeHours` | number | 168 | Maximum receipt age (7 days) |
| `timeout` | number | 30000 | API request timeout (ms) |

#### Methods

##### `createReceipt(data, options)`

Create a new TRON transaction receipt.

**Parameters:**
- `data` (Object): Receipt data
  - `issuer_did` (string): DID of issuing agent
  - `subject_did` (string): DID of subject (counterparty)
  - `rail` (string): `'tron'`, `'tron:trc20'`, or `'tron:native'`
  - `asset` (string): Asset identifier (TRX, USDT, USDC, etc.)
  - `amount` (string): Amount in smallest unit
  - `tron_tx_hash` (string): 64-character hex transaction hash
  - `timestamp` (string): ISO 8601 timestamp
  - `sender_address` (string, optional): TRON address of sender
  - `recipient_address` (string, optional): TRON address of recipient
  - `token_contract` (string, optional): TRC-20 contract address
  - `org_affiliation` (string, optional): Organization name
  - `network` (string, optional): mainnet, shasta, nile

- `options` (Object):
  - `sign` (boolean): Auto-sign with configured key

**Returns:** `Promise<Object>` - Receipt VC

##### `verifyReceipt(receipt, options)`

Verify a receipt against TronGrid and validate signature.

**Returns:** `Promise<Object>`
```javascript
{
  verified: boolean,
  tronGridVerified: boolean,
  signatureValid: boolean | null,
  error: string | null,
  details: {
    credentialSubject: Object,
    tronGrid: Object,
    confirmations: number,
    ageHours: number
  }
}
```

##### `submitReceipt(receipt, recipientEndpoint, recipientDid)`

Send receipt to another agent's registered endpoint.

##### `handleIncomingReceipt(receipt, recipientAgentId)`

Process and store an incoming receipt.

##### `toVACExtension(receipt, verificationResult)`

Convert receipt to VAC extension format.

##### `deriveAddress(publicKey, isTestnet)`

Derive TRON address from secp256k1 public key.

### TronGridClient

Low-level TronGrid API client.

```javascript
import { TronGridClient } from './index.mjs';

const client = new TronGridClient({ apiKey, network });

// Get account
const account = await client.getAccount('T...');

// Get transaction
const tx = await client.getTransaction('a1b2c3...');

// Verify TRC-20 transfer
const verified = await client.verifyTRC20Transfer(
  txHash,
  expectedFrom,
  expectedTo,
  expectedAmount,
  tokenContract
);

// Get contract events
const events = await client.getContractEvents(contract, {
  eventName: 'Transfer',
  limit: 100
});
```

## TRON Receipt VC Schema

The `tron_receipt_v1` credential type:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://observerprotocol.org/context/tron-receipt/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:...",
  "type": ["VerifiableCredential", "TronTransactionReceipt"],
  "issuer": "did:op:sender-agent",
  "issuanceDate": "2026-04-13T14:00:00Z",
  "expirationDate": "2026-04-20T14:00:00Z",
  "credentialSubject": {
    "id": "did:op:recipient-agent",
    "rail": "tron:trc20",
    "asset": "USDT",
    "amount": "1000000",
    "tronTxHash": "a1b2c3d4e5f6...",
    "timestamp": "2026-04-13T14:00:00Z",
    "senderAddress": "TJ...",
    "recipientAddress": "TJ...",
    "tokenContract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
    "orgAffiliation": "Example Corp",
    "confirmations": 20,
    "network": "mainnet"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-13T14:00:01Z",
    "verificationMethod": "did:op:sender-agent#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58..."
  }
}
```

## AIP Type Registry

TRON rail types:

| Type | Description | Use Case |
|------|-------------|----------|
| `tron` | Generic TRON rail | General reference |
| `tron:native` | Native TRX transfers | Direct TRX payments |
| `tron:trc20` | TRC-20 token transfers | USDT, USDC, etc. |

## VAC Extension Format

Receipts are stored in VAC credentials as:

```json
{
  "type": "tron_receipt_v1",
  "receiptId": "urn:uuid:...",
  "issuerDid": "did:op:sender",
  "rail": "tron:trc20",
  "asset": "USDT",
  "amount": "1000000",
  "tronTxHash": "a1b2c3...",
  "timestamp": "2026-04-13T14:00:00Z",
  "orgAffiliation": "Example Corp",
  "verified": true,
  "tronGridVerified": true,
  "issuedAt": "2026-04-13T14:00:00Z",
  "expiresAt": "2026-04-20T14:00:00Z"
}
```

## Testing

### Shasta Testnet

Use Shasta testnet for development:

```javascript
const tron = new TronRail({
  apiKey: 'your-key',
  network: 'shasta',
  minConfirmations: 1  // Lower for testnet
});
```

Shasta testnet tokens:
- Test USDT: Contact TronGrid for faucet
- Test TRX: Use Shasta faucet

### Common TRC-20 Contracts (Mainnet)

| Token | Contract Address |
|-------|-----------------|
| USDT | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` |
| USDC | `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` |
| TUSD | `TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4` |
| USDD | `TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn` |

## Integration with Agentic Terminal

### Register Agent with TRON Rail

```javascript
// Add to agent registration
const agentData = {
  agent_id: 'my-agent',
  public_key: 'ed25519-pub-key',
  chains: ['bitcoin', 'tron'],
  tron_address: tron.deriveAddress(publicKey)
};
```

### Update DID Document

```json
{
  "service": [
    {
      "id": "did:op:my-agent#tron",
      "type": "TronRail",
      "serviceEndpoint": "https://api.observerprotocol.org/agents/my-agent/tron"
    }
  ]
}
```

## Trust Score Integration

TRON receipts contribute to AT Trust Scores:

- **Volume**: Total verified TRON transaction volume
- **Counterparty Diversity**: Unique agents transacted with
- **Recency**: Time since last verified transaction
- **A2A Ratio**: Agent-to-agent vs external transactions
- **Org-Verified Ratio**: Transactions with org-affiliated counterparties

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TRON Rail Module                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  tron-core   │  │tron-receipt  │  │tron-verifica-│      │
│  │  (addresses  │──│  -vc         │──│   tion       │      │
│  │   & TronGrid)│  │ (sign/verify)│  │  (endpoint)  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│          │                  │                  │            │
│          └──────────────────┼──────────────────┘            │
│                             ▼                               │
│                    ┌────────────────┐                       │
│                    │   TronRail     │                       │
│                    │  (main class)  │                       │
│                    └────────────────┘                       │
│                             │                               │
└─────────────────────────────┼───────────────────────────────┘
                              ▼
                    ┌────────────────┐
                    │  Observer      │
                    │  Protocol      │
                    │  Core          │
                    └────────────────┘
```

## Security Considerations

1. **API Key Security**: Store TRONGRID_API_KEY securely
2. **Signature Verification**: Always verify Ed25519 signatures
3. **Confirmation Depth**: Require 19+ confirmations for mainnet
4. **Receipt Expiration**: Receipts expire after 7 days
5. **DID Resolution**: Verify issuer DIDs before accepting receipts

## License

MIT — Observer Protocol
