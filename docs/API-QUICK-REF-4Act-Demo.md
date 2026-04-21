# Observer Protocol — API Quick Reference
## 4-Act TRON Demo

**Base URL:** `http://localhost:8000` (local) / `https://api.observerprotocol.org` (production)  
**Version:** v1  
**Content-Type:** `application/json`  
**Last Updated:** April 20, 2026

---

## 🔑 Authentication

Most endpoints do not require authentication for read operations. Write operations (receipt submission) require a valid Ed25519 signature in the VC proof.

### Required Headers
```bash
Content-Type: application/json
Accept: application/json
```

### Optional Headers
```bash
X-Request-ID: unique-request-id        # For request tracing
X-API-Key: your-api-key               # If using authenticated endpoints
```

---

## 📡 Endpoint 1: Get Agent Information

```
GET /api/v1/agents/{agent_id}
```

Retrieve agent details including DID, public key, and registration status.

### URL Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | Yes | 32-character hex agent ID |

### Response (200 OK)
```json
{
  "agent_id": "d13cdfceaa8f895afe56dc902179d279",
  "agent_did": "did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279",
  "public_key": "ed25519-pub-key-base58",
  "created_at": "2026-04-20T10:00:00Z",
  "chains": ["tron", "solana"],
  "metadata": {
    "org_affiliation": "Observer Protocol"
  }
}
```

### Error Responses
| Status | Code | Description |
|--------|------|-------------|
| 404 | `AGENT_NOT_FOUND` | Agent ID does not exist |
| 400 | `INVALID_AGENT_ID` | Malformed agent ID |

### Example Curl
```bash
curl -X GET "http://localhost:8000/api/v1/agents/d13cdfceaa8f895afe56dc902179d279" \
  -H "Accept: application/json"
```

---

## 📡 Endpoint 2: Submit TRON Receipt

```
POST /api/v1/tron/receipts/submit
```

Submit a signed `tron_receipt_v1` Verifiable Credential for verification and storage.

### Request Body
```json
{
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://observerprotocol.org/context/tron-receipt/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "urn:uuid:unique-receipt-id",
    "type": ["VerifiableCredential", "TronTransactionReceipt"],
    "issuer": {
      "id": "did:web:observerprotocol.org:agents:{SENDER_ID}"
    },
    "issuanceDate": "2026-04-20T14:30:00Z",
    "expirationDate": "2026-04-27T14:30:00Z",
    "credentialSubject": {
      "id": "did:web:observerprotocol.org:agents:{RECIPIENT_ID}",
      "agentId": "{RECIPIENT_ID}",
      "rail": "tron:trc20",
      "asset": "USDT",
      "amount": "1000000",
      "transactionHash": "64-char-hex-tx-hash",
      "timestamp": "2026-04-20T14:28:45Z",
      "senderAddress": "T...",
      "recipientAddress": "T...",
      "tokenContract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
      "network": "mainnet",
      "confirmations": 19
    },
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2026-04-20T14:30:01Z",
      "verificationMethod": "did:web:observerprotocol.org:agents:{SENDER_ID}#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    }
  }
}
```

### Required VC Fields
| Field | Type | Description |
|-------|------|-------------|
| `@context` | array | Must include W3C VC and Ed25519 contexts |
| `id` | string | Unique UUID for this receipt |
| `type` | array | `["VerifiableCredential", "TronTransactionReceipt"]` |
| `issuer.id` | string | DID of the issuing agent |
| `issuanceDate` | string | ISO 8601 timestamp |
| `credentialSubject.id` | string | DID of the recipient agent |
| `credentialSubject.agentId` | string | Raw agent ID (32 hex chars) |
| `credentialSubject.rail` | string | `tron`, `tron:trc20`, or `tron:native` |
| `credentialSubject.asset` | string | Asset code (USDT, USDC, TRX) |
| `credentialSubject.amount` | string | Amount in smallest unit |
| `credentialSubject.transactionHash` | string | 64-char hex TRON tx hash |
| `credentialSubject.network` | string | `mainnet`, `shasta`, or `nile` |
| `proof.type` | string | `Ed25519Signature2020` |
| `proof.verificationMethod` | string | DID URL of signing key |
| `proof.proofValue` | string | Base58-encoded signature |

### Response (200 OK)
```json
{
  "success": true,
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "vc_id": "urn:uuid:unique-receipt-id",
  "verified": true,
  "error": null
}
```

### Response (Already Exists)
```json
{
  "success": true,
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "vc_id": "urn:uuid:unique-receipt-id",
  "verified": true,
  "error": null
}
```

### Error Responses
| Status | Code | Description |
|--------|------|-------------|
| 400 | `INVALID_VC` | Malformed VC structure |
| 400 | `MISSING_VC_ID` | VC missing `id` field |
| 400 | `VERIFICATION_FAILED` | TronGrid or signature verification failed |
| 400 | `SIGNATURE_INVALID` | Ed25519 signature does not verify |
| 400 | `TRANSACTION_NOT_FOUND` | TX hash not found on TronGrid |
| 400 | `INSUFFICIENT_CONFIRMATIONS` | Transaction below minimum confirmations |
| 500 | `INTERNAL_ERROR` | Server error during processing |

### Example Curl
```bash
curl -X POST "http://localhost:8000/api/v1/tron/receipts/submit" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d @receipt-vc.json
```

### Example with Inline JSON
```bash
curl -X POST "http://localhost:8000/api/v1/tron/receipts/submit" \
  -H "Content-Type: application/json" \
  -d '{
    "vc": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://observerprotocol.org/context/tron-receipt/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": "urn:uuid:tron-demo-001",
      "type": ["VerifiableCredential", "TronTransactionReceipt"],
      "issuer": {"id": "did:web:observerprotocol.org:agents:sender123"},
      "issuanceDate": "2026-04-20T14:30:00Z",
      "expirationDate": "2026-04-27T14:30:00Z",
      "credentialSubject": {
        "id": "did:web:observerprotocol.org:agents:recipient456",
        "agentId": "recipient456",
        "rail": "tron:trc20",
        "asset": "USDT",
        "amount": "1000000",
        "transactionHash": "eb52108c9785a83d5ff381d6d5086dec4745d80dbaa1435b816c0f358754a006",
        "timestamp": "2026-04-20T14:28:45Z",
        "senderAddress": "TRh7rZZehnWXZ2X9eiwsWGGMWE8CdGgSP4",
        "recipientAddress": "TW6usPjgS1p3SNqqad6FgSCu1fEeTD4My3",
        "tokenContract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "network": "mainnet",
        "confirmations": 19
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2026-04-20T14:30:01Z",
        "verificationMethod": "did:web:observerprotocol.org:agents:sender123#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z58..."
      }
    }
  }'
```

---

## 📡 Endpoint 3: Get TRON Trust Score

```
GET /api/v1/trust/tron/score/{agent_id}
```

Retrieve the TRON-specific trust score for an agent, including all component scores.

### URL Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | Yes | Agent ID (with or without `did:op:` prefix) |

### Response (200 OK)
```json
{
  "agent_id": "9539cf2f0b3c3c6e2ee882a479aec6b9",
  "trust_score": 42.5,
  "receipt_count": 2,
  "unique_counterparties": 1,
  "total_trx_volume": "0",
  "total_stablecoin_volume": "2000000",
  "org_affiliated_count": 0,
  "last_activity": "2026-04-20T14:30:00Z",
  "components": {
    "volume_score": 15.0,
    "counterparty_score": 10.0,
    "recency_score": 17.5
  }
}
```

### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Agent identifier |
| `trust_score` | float | Composite trust score (0-100) |
| `receipt_count` | int | Number of verified TRON receipts |
| `unique_counterparties` | int | Number of distinct trading partners |
| `total_trx_volume` | string | Total TRX volume in sun (smallest unit) |
| `total_stablecoin_volume` | string | Total USDT/USDC volume (6 decimals) |
| `org_affiliated_count` | int | Transactions with org-affiliated partners |
| `last_activity` | string | ISO 8601 timestamp of last receipt |
| `components` | object | Breakdown of score components |

### Score Components
| Component | Weight | Description |
|-----------|--------|-------------|
| `volume_score` | ~35% | Based on total transaction volume |
| `counterparty_score` | ~25% | Based on unique counterparties |
| `recency_score` | ~40% | Based on activity freshness |

### Error Responses
| Status | Code | Description |
|--------|------|-------------|
| 404 | `AGENT_NOT_FOUND` | Agent ID not found |
| 400 | `INVALID_AGENT_ID` | Malformed agent ID |

### Example Curl
```bash
curl -X GET "http://localhost:8000/api/v1/trust/tron/score/9539cf2f0b3c3c6e2ee882a479aec6b9" \
  -H "Accept: application/json"
```

### Example with DID prefix
```bash
curl -X GET "http://localhost:8000/api/v1/trust/tron/score/did:op:9539cf2f0b3c3c6e2ee882a479aec6b9" \
  -H "Accept: application/json"
```

---

## 📡 Endpoint 4: Get Transaction Details

```
GET /api/v1/transactions/{tx_hash}/details
```

Retrieve full transaction details including linked VC receipt when available.

### URL Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tx_hash` | string | Yes | 64-character hex TRON transaction hash |

### Response (200 OK)
```json
{
  "transaction": {
    "tx_hash": "eb52108c9785a83d5ff381d6d5086dec4745d80dbaa1435b816c0f358754a006",
    "direction": "incoming",
    "amount": "1000000",
    "asset": "USDT",
    "counterparty_address": "TRh7rZZehnWXZ2X9eiwsWGGMWE8CdGgSP4",
    "network": "mainnet",
    "rail": "tron:trc20",
    "confirmations": 19,
    "block_number": 65432100,
    "timestamp": "2026-04-20T14:28:45Z",
    "metadata": {
      "has_vc": true,
      "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
      "sender_org": "Observer Protocol Demo"
    }
  },
  "verifiable_credential": {
    "present": true,
    "vc_id": "urn:uuid:tron-receipt-demo-001",
    "verified": true,
    "issuer_did": "did:web:observerprotocol.org:agents:d13cdfceaa8f895afe56dc902179d279"
  },
  "explorers": {
    "tronscan": "https://tronscan.org/#/transaction/eb52108c9785a83d5ff381d6d5086dec4745d80dbaa1435b816c0f358754a006"
  }
}
```

### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `transaction` | object | Core transaction details |
| `verifiable_credential` | object | VC receipt information (if present) |
| `explorers` | object | Links to block explorers |

### Transaction Fields
| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | string | Transaction hash |
| `direction` | string | `incoming` or `outgoing` |
| `amount` | string | Amount in smallest unit |
| `asset` | string | Asset code |
| `counterparty_address` | string | Other party's TRON address |
| `network` | string | TRON network |
| `rail` | string | Payment rail type |
| `confirmations` | int | Block confirmations |
| `block_number` | int | Block height |
| `timestamp` | string | Transaction timestamp |
| `metadata` | object | Additional metadata including VC link |

### Error Responses
| Status | Code | Description |
|--------|------|-------------|
| 404 | `TRANSACTION_NOT_FOUND` | TX hash not found in database |
| 400 | `INVALID_TX_HASH` | Malformed transaction hash |

### Example Curl
```bash
curl -X GET "http://localhost:8000/api/v1/transactions/eb52108c9785a83d5ff381d6d5086dec4745d80dbaa1435b816c0f358754a006/details" \
  -H "Accept: application/json"
```

---

## 🔗 Additional Endpoints

### Get Agent's TRON Receipts
```
GET /api/v1/tron/receipts/{agent_id}
```
List all TRON receipts for an agent.

### Get TRON Leaderboard
```
GET /api/v1/trust/tron/leaderboard?limit=10&offset=0&min_receipts=1
```
Get ranked list of agents by TRON trust score.

### Health Check
```
GET /health
```
Check API server status.

---

## 🛠️ Common Payload Patterns

### Creating a Receipt VC
```javascript
const receiptVC = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://observerprotocol.org/context/tron-receipt/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": `urn:uuid:tron-${Date.now()}`,
  "type": ["VerifiableCredential", "TronTransactionReceipt"],
  "issuer": { "id": senderDID },
  "issuanceDate": new Date().toISOString(),
  "expirationDate": new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  "credentialSubject": {
    "id": recipientDID,
    "agentId": recipientAgentId,
    "rail": "tron:trc20",
    "asset": "USDT",
    "amount": "1000000",  // 1 USDT
    "transactionHash": txHash,
    "timestamp": txTimestamp,
    "senderAddress": senderTronAddress,
    "recipientAddress": recipientTronAddress,
    "tokenContract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
    "network": "mainnet",
    "confirmations": 19
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": new Date().toISOString(),
    "verificationMethod": `${senderDID}#key-1`,
    "proofPurpose": "assertionMethod",
    "proofValue": signEd25519(canonicalize(receiptVC), privateKey)
  }
};
```

---

## 📊 HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request — Invalid parameters |
| 404 | Not Found — Resource doesn't exist |
| 429 | Rate Limited — Too many requests |
| 500 | Internal Server Error |
| 502 | Bad Gateway — Upstream service error |
| 503 | Service Unavailable — Maintenance |

---

## 🆘 Support

- **API Documentation:** https://observerprotocol.org/docs/api
- **Bug Reports:** https://github.com/observer-protocol/issues
- **Support Email:** support@observerprotocol.org

---

*Quick Reference v1.0 — Observer Protocol Engineering*
