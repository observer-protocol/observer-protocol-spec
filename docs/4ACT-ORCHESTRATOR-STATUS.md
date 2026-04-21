# 4-Act Orchestrator Status

**Last Updated:** 2026-04-21
**Status:** INCOMPLETE - Mock broadcast disabled

## What This Is

The 4-act demo orchestrator (`scripts/4act-demo-orchestrator.mjs`) was designed to demonstrate a complete TRON-based settlement flow:

1. **Act 1:** Agent Identity (DID resolution)
2. **Act 2:** Service Discovery (capability negotiation)
3. **Act 3:** Payment Execution (TRON USDT transfer) ← **BROADCAST NOT IMPLEMENTED**
4. **Act 4:** Receipt & Verification (VC generation and submission)

## Current State

### What Works

- **Act 1 (Identity):** Real DID resolution via `did:web` + PostgreSQL agent registry
- **Act 2 (Discovery):** Real capability negotiation via Observer Protocol API
- **Act 4 (Receipt):** Real VC submission to `/api/v1/tron/receipts/submit` endpoint (when given a valid tx hash)

### What's Disabled

- **Act 3 (Broadcast):** Throws explicit error instead of generating fake transaction hashes
  
  ```javascript
  throw new Error(
    "Real TronWeb broadcast not implemented. " +
    "Spec 2 orchestrator is incomplete - the broadcast step requires " +
    "integration with the working TronWeb pattern from Spec 1's validation script. " +
    "Until implemented, the 4-act orchestrator cannot execute live demos."
  );
  ```

### Why It's Disabled

The orchestrator contained **mock transaction generation** that:
- Generated random 64-character hex strings as "transaction hashes"
- Printed fake TronScan URLs
- Returned synthetic success responses
- Never actually broadcast to TRON mainnet

This created **data integrity issues** — synthetic transaction hashes were being passed through the receipt/verification pipeline as if they were real, contaminating the database with unverifiable records.

## What Was Removed

| Pattern | Location | Replacement |
|---------|----------|-------------|
| Random tx hash generation | Act 2, lines 244-247 | Explicit error throw |
| Random block number | Act 2, line 255 | Removed (never reached) |
| Random Ed25519 signature | Act 4, lines 322-324 | Placeholder comment |
| `SKIP_LIVE_TX` env flag | CONFIG section | Removed entirely |
| Mock fallback on cancellation | Act 2, user prompt | Returns `{cancelled: true}` |

## What's Needed to Make It Real

To complete the orchestrator, port the **working TronWeb pattern from Spec 1's validation script** (`scripts/validate_mainnet.mjs`):

1. **TronWeb initialization** with private key from secure storage
2. **USDT contract integration** (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`)
3. **`triggerSmartContract()` call** for `transfer()` function
4. **`sendRawTransaction()` broadcast** with proper error handling
5. **Transaction confirmation polling** via `getTransactionInfo()`
6. **Real tx hash extraction** from broadcast response

Reference implementation: See Spec 1 validation script which successfully broadcast real mainnet transactions.

## When to Revisit

This orchestrator should be revisited **only when**:
- A real demo for an external party is actually scheduled
- The TronWeb broadcast integration has been properly implemented and tested
- Database cleanup procedures are in place for any failed test transactions

## Current Usage

The orchestrator can still be used in **Act 4-only mode** against existing real transactions:

```bash
# Generate receipt for an already-broadcast tx
node scripts/4act-demo-orchestrator.mjs \
  --act4-only \
  --tx-hash=<real-tx-hash-from-tronscan>
```

This path is functional because it skips the broadcast step entirely.

## Related Files

- `scripts/4act-demo-orchestrator.mjs` - This orchestrator (modified)
- `scripts/validate_mainnet.mjs` - Working TronWeb reference implementation
- `rails/tron/` - TronWeb integration library
- `docs/VAC-CHAIN-DEPENDENCIES.md` - Related architectural documentation

---

*This document exists to prevent future confusion about the orchestrator's capabilities. Do not attempt live demos without first implementing real broadcast functionality.*
