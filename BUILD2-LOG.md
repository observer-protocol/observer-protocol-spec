# Observer Protocol Build 2: MoonPay KYB Integration

**Build Date:** 2026-03-24  
**Status:** ✅ Complete  
**Location:** `/media/nvme/observer-protocol/`

## Overview

MoonPay is now the first registered Trusted KYB Provider in the Observer Protocol organizational attestation framework. Organizations can register with KYB verification from MoonPay, and this verification is stamped on their org registration and all agent VACs issued under the organization.

## What Was Built

### 1. Database Migration (`api/migrations/002_moonpay_kyb.sql`)

**New Table: `trusted_kyb_providers`**
```sql
- provider_id (varchar, primary key)
- provider_name (e.g., "MoonPay")
- provider_domain (e.g., "moonpay.com")
- provider_public_key_hash (secp256k1 for signature verification)
- api_endpoint (OP calls this to verify KYB status)
- status (active / suspended)
- registered_at
- notes
```

**Updated Table: `organizations`**
```sql
- kyb_status (pending / verified / rejected / expired)
- kyb_provider_id (FK to trusted_kyb_providers)
- kyb_reference
- kyb_verified_at
- kyb_expires_at
- kyb_last_checked_at
- kyb_response_data (JSONB)
```

**Updated Table: `agent_keys`**
```sql
- org_id (FK to organizations)
```

### 2. MoonPay Seeded as Provider_001

MoonPay is automatically seeded as the founding Trusted KYB Provider on database initialization:
- **Provider ID:** `provider_001`
- **Name:** MoonPay
- **Domain:** moonpay.com
- **Status:** Active

### 3. New API Endpoints

#### KYB Provider Endpoints
```
GET  /observer/kyb-providers              → List all trusted KYB providers
GET  /observer/kyb-providers/{id}         → Get provider details
```

#### Organization Endpoints (with KYB)
```
POST /observer/register-org               → Register org with optional KYB
GET  /observer/orgs/{org_id}              → Get organization info
GET  /observer/orgs/{org_id}/kyb-status   → Check KYB status
POST /observer/orgs/{org_id}/verify-kyb   → Trigger KYB verification pull
```

#### Updated Agent Endpoints
```
POST /observer/register                   → Now accepts org_id
GET  /observer/agent/{agent_id}           → Returns org_id if set
```

#### Updated Attestation Endpoint
```
POST /observer/solana-attest              → Returns VAC with KYB extensions
```

### 4. Mock MoonPay Server (`api/mock_moonpay.py`)

A mock implementation of the MoonPay KYB verification endpoint for development:
```
GET /kyb/verify/{reference}               → Returns KYB verification result
```

Mock responses:
```json
{
  "reference": "moonpay_kyb_ref_abc123",
  "verified": true,
  "entity_name": "Mastercard International",
  "verified_at": "2026-03-24T00:00:00Z"
}
```

## API Examples

### Register Organization with KYB
```bash
curl -X POST http://localhost:8000/observer/register-org \
  -H "Content-Type: application/json" \
  -d '{
    "org_name": "Mastercard International",
    "domain": "mastercard.com",
    "public_key": "02a1b2c3...",
    "kyb_provider": "moonpay",
    "kyb_reference": "moonpay_kyb_ref_abc123"
  }'
```

Response:
```json
{
  "org_id": "org_a1b2c3d4e5f6",
  "org_name": "Mastercard International",
  "domain": "mastercard.com",
  "public_key": "02a1b2c3...",
  "kyb_status": "verified",
  "kyb_provider": "provider_001",
  "kyb_verified_at": "2026-03-24T13:30:00Z",
  "created_at": "2026-03-24T13:30:00Z"
}
```

### Register Agent with Organization
```bash
curl -X POST http://localhost:8000/observer/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "public_key": "HN7cAB...",
    "solana_address": "HN7cAB...",
    "org_id": "org_a1b2c3d4e5f6"
  }'
```

### Get KYB Status
```bash
curl http://localhost:8000/observer/orgs/org_a1b2c3d4e5f6/kyb-status
```

Response:
```json
{
  "org_id": "org_a1b2c3d4e5f6",
  "org_name": "Mastercard International",
  "kyb_status": "verified",
  "kyb_provider": "provider_001",
  "kyb_verified_at": "2026-03-24T13:30:00Z",
  "kyb_expires_at": null,
  "kyb_reference": "moonpay_kyb_ref_abc123"
}
```

### Attestation with KYB Extensions (VAC)
```bash
curl -X POST http://localhost:8000/observer/solana-attest \
  -H "Content-Type: application/json" \
  -d '{
    "tx_signature": "5Uf...",
    "sender_address": "HN7cAB...",
    "recipient_address": "9xQ7...",
    "amount_lamports": 1000000,
    "mint": "SOL",
    "agent_id": "agent-001",
    "signature": "base58-sig"
  }'
```

Response includes:
```json
{
  "attestation_id": "abc123...",
  "verified": true,
  "protocol": "solana",
  "amount": 1000000,
  ...
  "extensions": [{
    "type": "organizational_delegation",
    "org_id": "org_a1b2c3d4e5f6",
    "org_name": "Mastercard International",
    "kyb_verified": true,
    "kyb_status": "verified",
    "kyb_provider": "MoonPay",
    "kyb_provider_id": "provider_001",
    "kyb_verified_at": "2026-03-24T13:30:00Z"
  }]
}
```

## Files Created/Modified

| File | Description |
|------|-------------|
| `api/main.py` | Updated with KYB integration (540+ lines added) |
| `api/migrations/002_moonpay_kyb.sql` | Database migration for KYB tables |
| `api/mock_moonpay.py` | Mock MoonPay KYB server for testing |
| `api/test_build2_kyb.py` | Comprehensive test suite |
| `api/requirements.txt` | Added httpx dependency |
| `BUILD2-LOG.md` | This file |

## Running the System

### 1. Start the Main API
```bash
cd /media/nvme/observer-protocol/api
export DATABASE_URL="postgresql://observer:observer@localhost/observer_protocol"
python main.py
```

### 2. (Optional) Start Mock MoonPay Server
```bash
cd /media/nvme/observer-protocol/api
python mock_moonpay.py
```

### 3. Run Tests
```bash
cd /media/nvme/observer-protocol/api
python test_build2_kyb.py
```

## Test Results

All tests passing:
- ✅ Health Check
- ✅ List KYB Providers (MoonPay present)
- ✅ Get KYB Provider (MoonPay details)
- ✅ Register Organization with KYB
- ✅ Register Organization without KYB
- ✅ Get Organization
- ✅ Get KYB Status
- ✅ Trigger KYB Verification
- ✅ Register Agent with Org
- ✅ Get Agent
- ✅ Mock MoonPay Logic

## Database Schema

### trusted_kyb_providers
| Column | Type | Notes |
|--------|------|-------|
| provider_id | VARCHAR(32) | PK, e.g., 'provider_001' |
| provider_name | VARCHAR(128) | e.g., 'MoonPay' |
| provider_domain | VARCHAR(128) | e.g., 'moonpay.com' |
| provider_public_key_hash | VARCHAR(64) | secp256k1 hash |
| api_endpoint | VARCHAR(256) | Verification endpoint |
| status | VARCHAR(16) | active/suspended |
| registered_at | TIMESTAMP | Auto-set |
| notes | TEXT | Description |

### organizations
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL | PK |
| org_id | VARCHAR(32) | Unique, generated from domain |
| org_name | VARCHAR(128) | Display name |
| domain | VARCHAR(128) | Unique, verified domain |
| public_key | VARCHAR(128) | secp256k1 public key |
| kyb_status | VARCHAR(16) | pending/verified/rejected/expired |
| kyb_provider_id | VARCHAR(32) | FK to trusted_kyb_providers |
| kyb_reference | VARCHAR(128) | Provider reference ID |
| kyb_verified_at | TIMESTAMP | When KYB was verified |
| kyb_expires_at | TIMESTAMP | Expiration (optional) |
| kyb_last_checked_at | TIMESTAMP | Last verification check |
| kyb_response_data | JSONB | Raw provider response |
| created_at | TIMESTAMP | Auto-set |
| updated_at | TIMESTAMP | Auto-updated |

### agent_keys
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL | PK |
| agent_id | VARCHAR(64) | Unique identifier |
| public_key | VARCHAR(128) | Ed25519 public key |
| solana_address | VARCHAR(64) | Optional Solana wallet |
| org_id | VARCHAR(32) | FK to organizations (NEW) |
| reputation_score | INTEGER | Default 0 |
| created_at | TIMESTAMP | Auto-set |
| last_seen | TIMESTAMP | Last activity |

## Architecture Notes

### KYB Verification Flow
1. Organization registers with `kyb_provider` and `kyb_reference`
2. API normalizes provider name ("moonpay" → "provider_001")
3. API calls `verify_kyb_with_provider()` 
4. For MoonPay, uses mock (or real API in production)
5. Result stored in `organizations` table
6. All agent VACs include org's KYB status in extensions

### VAC Extension Format
```json
{
  "extensions": [{
    "type": "organizational_delegation",
    "org_id": "org_abc123",
    "org_name": "Organization Name",
    "kyb_verified": true,
    "kyb_status": "verified",
    "kyb_provider": "MoonPay",
    "kyb_provider_id": "provider_001",
    "kyb_verified_at": "2026-03-24T00:00:00Z"
  }]
}
```

## Future Enhancements

1. **Real MoonPay API Integration**: Replace mock with actual MoonPay endpoint
2. **Additional KYB Providers**: Add more providers to the registry
3. **KYB Expiration Handling**: Automated re-verification for expired KYB
4. **Webhook Support**: Real-time KYB status updates from providers
5. **KYB Document Storage**: IPFS integration for KYB documentation

## Build Notes

- All database tables stored on NVMe (`/media/nvme/`)
- Backward compatible with existing agent registrations
- Mock server can run independently on port 8001
- Full test coverage for all new endpoints
- No breaking changes to existing API

## References

- Observer Protocol Specification: Build 2a, 2b, 2c, 2d
- MoonPay: https://www.moonpay.com
- Build 1: Organization Registry (Phase 1)
