# Observer Protocol — 4-Act TRON Demo Runbook
## For: Sam (BD Engineer) | Audience: Enterprise Stakeholders

**Document Version:** 1.0  
**Date:** April 20, 2026  
**Purpose:** Complete step-by-step guide for executing the 4-Act TRON Demo  
**Prerequisites:** Access to Observer Protocol API, TronGrid API key, funded TRON wallet

---

## 📋 PRE-DEMO CHECKLIST

### Environment Setup
- [ ] API server is running (`curl http://localhost:8000/health` returns 200)
- [ ] TronGrid API key is configured (`echo $TRONGRID_API_KEY` returns valid key)
- [ ] OP signing key is available (`echo $OP_SIGNING_KEY` returns 64-char hex)
- [ ] Demo agents are registered in OP database
- [ ] Network connectivity to TronGrid API (test with ping)

### Wallet Funding Verification
```bash
# Verify sender wallet has sufficient USDT-TRC20 balance
curl -X GET "https://api.trongrid.io/v1/accounts/{SENDER_ADDRESS}/tokens" \
  -H "Accept: application/json" \
  -H "TRON-PRO-API-KEY: $TRONGRID_API_KEY"

# Expected: Response shows USDT balance >= 1.00 (6 decimals = 1000000)
```

### Agent Pre-Registration Check
```bash
# Verify Agent A (Sender) exists
curl http://localhost:8000/api/v1/agents/{AGENT_A_ID}

# Verify Agent B (Recipient) exists
curl http://localhost:8000/api/v1/agents/{AGENT_B_ID}
```

### TRON Network Selection
| Network | Use Case | Confirmation Time |
|---------|----------|-------------------|
| `mainnet` | Production demos | ~60 seconds (19 blocks) |
| `shasta` | Development/testing | ~15 seconds (1 block) |
| `nile` | Staging | ~30 seconds (3 blocks) |

**Recommendation:** Use `shasta` testnet for rehearsal, `mainnet` for stakeholder demos.

---

## 🎭 THE 4-ACT DEMO SCRIPT

### ACT I: SETUP — "The Actors Enter"
**Duration:** 2 minutes  
**Narrator Talking Points:**
> "Today we're demonstrating how Observer Protocol enables trustless verification of TRON transactions between autonomous agents. We have two agents: Alice the Buyer and Bob the Merchant. Both are registered in the OP network with verifiable DIDs."

**Demo Actions:**
1. Show Agent A DID Document:
```bash
curl http://localhost:8000/agents/{AGENT_A_ID}/did.json
```

2. Show Agent B DID Document:
```bash
curl http://localhost:8000/agents/{AGENT_B_ID}/did.json
```

3. Display current trust scores:
```bash
curl http://localhost:8000/api/v1/trust/tron/score/{AGENT_A_ID}
curl http://localhost:8000/api/v1/trust/tron/score/{AGENT_B_ID}
```

**Success Criteria:**
- Both DIDs resolve successfully
- Trust scores are displayed (may be 0 for new agents)
- No API errors in responses

---

### ACT II: TRANSACTION — "The Exchange"
**Duration:** 3 minutes  
**Narrator Talking Points:**
> "Alice initiates a USDT transfer to Bob on the TRON network. This is a standard TRC-20 transfer, but watch what happens next — the transaction is about to become cryptographically verifiable."

**Demo Actions:**
1. Execute TRON transfer via TronLink or programmatically:
```javascript
// Using TronWeb
const tx = await tronWeb.trx.sendToken(
  "RECIPIENT_ADDRESS",
  1000000,  // 1 USDT (6 decimals)
  "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  // USDT contract
);
console.log("Transaction Hash:", tx.transaction.txID);
```

2. Capture the transaction hash (64 hex characters)
3. Monitor confirmations:
```bash
curl -X GET "https://api.trongrid.io/v1/transactions/{TX_HASH}/events" \
  -H "TRON-PRO-API-KEY: $TRONGRID_API_KEY"
```

**Success Criteria:**
- Transaction submitted successfully
- Transaction hash received (64 hex chars)
- Confirmations >= 1 (shasta) or >= 19 (mainnet)

---

### ACT III: ATTESTATION — "The Receipt"
**Duration:** 4 minutes  
**Narrator Talking Points:**
> "Now the magic happens. Bob's agent creates a cryptographically signed receipt — a W3C Verifiable Credential that attests to this payment. This receipt is signed with Ed25519 and includes the full transaction details. Anyone can verify it without trusting Bob."

**Demo Actions:**
1. Create the receipt VC:
```bash
curl -X POST http://localhost:8000/api/v1/tron/receipts/submit \
  -H "Content-Type: application/json" \
  -d '{
    "vc": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://observerprotocol.org/context/tron-receipt/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": "urn:uuid:tron-demo-receipt-'$(date +%s)'",
      "type": ["VerifiableCredential", "TronTransactionReceipt"],
      "issuer": {
        "id": "did:web:observerprotocol.org:agents:{AGENT_A_ID}"
      },
      "issuanceDate": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "expirationDate": "'$(date -u -d "+7 days" +%Y-%m-%dT%H:%M:%SZ)'",
      "credentialSubject": {
        "id": "did:web:observerprotocol.org:agents:{AGENT_B_ID}",
        "agentId": "{AGENT_B_ID}",
        "rail": "tron:trc20",
        "asset": "USDT",
        "amount": "1000000",
        "transactionHash": "{TX_HASH}",
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
        "senderAddress": "{SENDER_TRON_ADDRESS}",
        "recipientAddress": "{RECIPIENT_TRON_ADDRESS}",
        "tokenContract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "network": "{NETWORK}",
        "confirmations": 19
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
        "verificationMethod": "did:web:observerprotocol.org:agents:{AGENT_A_ID}#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z{SIGNATURE_BASE58}"
      }
    }
  }'
```

**Expected Output:**
```json
{
  "success": true,
  "receipt_id": "uuid-string",
  "vc_id": "urn:uuid:tron-demo-receipt-...",
  "verified": true,
  "error": null
}
```

**Success Criteria:**
- API returns `verified: true`
- Receipt ID is generated
- TronGrid verification passes
- Signature verification passes

---

### ACT IV: VERIFICATION — "The Trust Score"
**Duration:** 3 minutes  
**Narrator Talking Points:**
> "The receipt is now stored immutably. Let's see how this affects Bob's trust score. Observer Protocol calculates trust based on verified transaction volume, counterparty diversity, and receipt age. Bob's score just increased based on real economic activity."

**Demo Actions:**
1. Query updated trust score:
```bash
curl http://localhost:8000/api/v1/trust/tron/score/{AGENT_B_ID}
```

2. View transaction details:
```bash
curl http://localhost:8000/api/v1/transactions/{TX_HASH}/details
```

3. Show leaderboard position:
```bash
curl http://localhost:8000/api/v1/trust/tron/leaderboard?limit=10
```

**Expected Output:**
```json
{
  "agent_id": "{AGENT_B_ID}",
  "trust_score": 42.5,
  "receipt_count": 1,
  "unique_counterparties": 1,
  "total_trx_volume": "0",
  "total_stablecoin_volume": "1000000",
  "org_affiliated_count": 0,
  "last_activity": "2026-04-20T14:00:00Z",
  "components": {
    "volume_score": 15.0,
    "counterparty_score": 10.0,
    "recency_score": 17.5
  }
}
```

**Success Criteria:**
- Trust score > 0 (increased from baseline)
- Receipt count incremented
- Transaction details show VC link
- Leaderboard shows agent

---

## 🔧 EXACT CURL COMMANDS REFERENCE

### 1. Get Agent Information
```bash
curl -X GET "http://localhost:8000/api/v1/agents/{agent_id}" \
  -H "Accept: application/json"
```

### 2. Submit TRON Receipt
```bash
curl -X POST "http://localhost:8000/api/v1/tron/receipts/submit" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d @receipt-vc.json
```

### 3. Get TRON Trust Score
```bash
curl -X GET "http://localhost:8000/api/v1/trust/tron/score/{agent_id}" \
  -H "Accept: application/json"
```

### 4. Get Transaction Details
```bash
curl -X GET "http://localhost:8000/api/v1/transactions/{tx_hash}/details" \
  -H "Accept: application/json"
```

---

## 🛠️ TROUBLESHOOTING GUIDE

### Common Failure Modes

#### Issue: "Verification failed: Transaction not found on TronGrid"
**Cause:** Transaction hash invalid or not yet indexed  
**Fix:**
- Wait 30 seconds for TronGrid indexing
- Verify hash on Tronscan: `https://tronscan.org/#/transaction/{TX_HASH}`
- Ensure correct network (mainnet vs shasta)

#### Issue: "VC signature verification failed"
**Cause:** Invalid Ed25519 signature or wrong signing key  
**Fix:**
- Verify signing key matches agent DID
- Check `verificationMethod` in proof matches agent's key ID
- Ensure no modifications to VC after signing

#### Issue: "Agent not found"
**Cause:** Agent ID doesn't exist in database  
**Fix:**
- Check agent registration: `curl /api/v1/agents/{id}`
- Verify agent_id format (32 hex characters)
- Strip `did:op:` prefix if present in API call

#### Issue: "Duplicate receipt"
**Cause:** VC ID already exists in database  
**Fix:**
- Generate new UUID for VC `id` field
- Use timestamp-based unique IDs: `urn:uuid:tron-$(date +%s)`

#### Issue: "Insufficient confirmations"
**Cause:** Transaction hasn't reached minimum block depth  
**Fix:**
- Wait for more blocks (mainnet: 19, shasta: 1)
- Check current block height vs transaction block
- Adjust `minConfirmations` config if needed

#### Issue: API returns 500/502 errors
**Cause:** Server or database connection issues  
**Fix:**
- Check API health: `curl /health`
- Verify DATABASE_URL environment variable
- Check PostgreSQL connection
- Review API logs: `tail -f /var/log/op-api.log`

#### Issue: TronGrid rate limiting (429 errors)
**Cause:** Too many requests to TronGrid API  
**Fix:**
- Verify TRONGRID_API_KEY is set
- Implement request backoff
- Consider TronGrid paid plan for higher limits

---

## ✅ POST-DEMO VERIFICATION STEPS

### Immediate Verification (Within 5 minutes)
1. **Database Check:**
```sql
SELECT * FROM tron_receipts 
WHERE tron_tx_hash = '{TX_HASH}' 
AND verified = TRUE;
```

2. **API Verification:**
```bash
curl http://localhost:8000/api/v1/tron/receipts/{AGENT_B_ID}
```

3. **Trust Score Updated:**
```bash
curl http://localhost:8000/api/v1/trust/tron/score/{AGENT_B_ID} | jq '.receipt_count'
```

### Long-term Verification (Within 24 hours)
1. Verify Tronscan still shows transaction
2. Check VC has not expired
3. Confirm trust score persistence in leaderboard

### Demo Reset (For next session)
```bash
# Optional: Clean up demo receipts for fresh run
psql $DATABASE_URL -c "DELETE FROM tron_receipts WHERE tron_tx_hash = '{TX_HASH}';"
```

---

## 📊 EXPECTED OUTPUTS SUMMARY

| Stage | Expected Result | Verification Command |
|-------|-----------------|---------------------|
| Act I | Agent DIDs resolve | `GET /agents/{id}` |
| Act II | TX hash received | Tronscan URL |
| Act III | `verified: true` | `POST /tron/receipts/submit` |
| Act IV | Trust score > 0 | `GET /trust/tron/score/{id}` |

---

## 🚀 QUICK START FOR SAM

```bash
# 1. Set environment
export TRONGRID_API_KEY="your-key-here"
export OP_BASE="http://localhost:8000"

# 2. Verify setup
curl $OP_BASE/health

# 3. Run Act I
curl $OP_BASE/api/v1/agents/{AGENT_A_ID}

# 4. Execute transaction (manual or scripted)
# ... capture TX_HASH ...

# 5. Run Act III
curl -X POST $OP_BASE/api/v1/tron/receipts/submit -d @receipt.json

# 6. Run Act IV
curl $OP_BASE/api/v1/trust/tron/score/{AGENT_B_ID}

# Done! 🎉
```

---

*Document maintained by Observer Protocol Engineering*  
*Last updated: April 20, 2026*
