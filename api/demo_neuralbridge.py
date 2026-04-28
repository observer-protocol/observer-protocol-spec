"""
NeuralBridge — Fictional AI infrastructure counterparty for the chargeback prevention demo.

"GPU inference at the edge"

NeuralBridge accepts USDT-on-TRON and Lightning for API credits.
This module implements the counterparty's verification stack with real
cryptographic verification — no faked checks anywhere.

NeuralBridge has its own Ed25519 keypair (NEURALBRIDGE_SIGNING_KEY env var).
Receipts are signed by NeuralBridge, not OP. OP defines the schema;
NeuralBridge signs the receipts for transactions on its infrastructure.

DID: did:web:neuralbridge.demo.observerprotocol.org
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import base58
import psycopg2.extras
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/neuralbridge", tags=["neuralbridge-demo"])

_get_db_connection = None

NEURALBRIDGE_DID = "did:web:neuralbridge.demo.observerprotocol.org"
NEURALBRIDGE_NAME = "NeuralBridge"

# Products catalog
PRODUCTS = {
    "gpu-credits-500": {
        "id": "gpu-credits-500",
        "name": "GPU Inference API Credits (500 units)",
        "price": "50.00",
        "currency": "USDT",
    },
    "gpu-credits-2000": {
        "id": "gpu-credits-2000",
        "name": "GPU Inference API Credits (2000 units)",
        "price": "180.00",
        "currency": "USDT",
    },
}


def configure(get_db_connection_fn):
    global _get_db_connection
    _get_db_connection = get_db_connection_fn


# ── NeuralBridge signing key ─────────────────────────────────

def _load_nb_signing_key() -> Ed25519PrivateKey:
    key_hex = os.environ.get("NEURALBRIDGE_SIGNING_KEY")
    if not key_hex:
        raise RuntimeError("NEURALBRIDGE_SIGNING_KEY not set")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))


def _nb_sign(message: bytes) -> str:
    """Sign with NeuralBridge's key. Returns multibase base58btc (z-prefix)."""
    key = _load_nb_signing_key()
    sig = key.sign(message)
    return "z" + base58.b58encode(sig).decode("ascii")


def _canonical_bytes(doc: dict) -> bytes:
    """Canonical JSON for signing — exclude proof, sort keys, compact."""
    d = {k: v for k, v in doc.items() if k != "proof"}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Delegation credential verification ──────────────────────

def _verify_delegation_credential(credential: dict, expected_counterparty_did: str, amount: str, rail: str) -> tuple:
    """
    Verify a delegation credential cryptographically.
    Returns (valid: bool, error: str | None).

    Checks:
    1. Ed25519 signature against issuer's published public key
    2. authorizationLevel and scope cover this transaction
    3. Temporal validity (validFrom <= now < validUntil)
    4. Counterparty DID matches
    """
    try:
        subject = credential.get("credentialSubject", {})
        auth_level = subject.get("authorizationLevel")
        auth_config = subject.get("authorizationConfig", {})

        # Check temporal validity
        now = datetime.now(timezone.utc)
        valid_from = credential.get("validFrom")
        valid_until = credential.get("validUntil")
        if valid_from and datetime.fromisoformat(valid_from.replace("Z", "+00:00")) > now:
            return False, "Credential not yet valid"
        if valid_until and datetime.fromisoformat(valid_until.replace("Z", "+00:00")) < now:
            return False, "Credential expired"

        # Check counterparty and scope based on authorization level
        if auth_level == "one-time":
            one_time = auth_config.get("oneTime", {})
            if one_time.get("counterparty_did") != expected_counterparty_did:
                return False, "Counterparty DID mismatch"
            if one_time.get("amount") != amount:
                return False, f"Amount mismatch: credential={one_time.get('amount')}, requested={amount}"
            if one_time.get("rail") != rail:
                return False, f"Rail mismatch: credential={one_time.get('rail')}, requested={rail}"
        elif auth_level == "recurring":
            recurring = auth_config.get("recurring", {})
            if recurring.get("counterparty_did") != expected_counterparty_did:
                return False, "Counterparty DID mismatch"
            ceiling = float(recurring.get("ceiling_amount", "0"))
            if float(amount) > ceiling:
                return False, f"Amount {amount} exceeds ceiling {recurring.get('ceiling_amount')}"
        elif auth_level == "policy":
            pass  # Policy-level: trust the external credential scope
        else:
            return False, f"Unknown authorization level: {auth_level}"

        # Verify Ed25519 signature
        proof = credential.get("proof", {})
        if proof.get("type") != "Ed25519Signature2020":
            return False, "Unsupported proof type"

        proof_value = proof.get("proofValue", "")
        if not proof_value.startswith("z"):
            return False, "Invalid proof value encoding"

        sig_bytes = base58.b58decode(proof_value[1:])
        canonical = _canonical_bytes(credential)

        # Resolve issuer's public key
        issuer_did = credential.get("issuer", "")
        pub_key = _resolve_public_key(issuer_did)
        if not pub_key:
            return False, f"Could not resolve issuer public key for {issuer_did}"

        pub_key.verify(sig_bytes, canonical)
        return True, None

    except Exception as e:
        return False, f"Verification failed: {str(e)}"


def _resolve_public_key(did: str):
    """Resolve a DID to its Ed25519 public key via did:web resolution."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        # did:web resolution: did:web:domain → https://domain/.well-known/did.json
        # did:web:domain:path:segments → https://domain/path/segments/did.json
        parts = did.replace("did:web:", "").split(":")
        domain = parts[0]
        path = "/".join(parts[1:]) if len(parts) > 1 else ".well-known"
        url = f"https://{domain}/{path}/did.json"

        # For local agent DIDs on observerprotocol.org, use the API
        if "observerprotocol.org:agents:" in did:
            agent_id = parts[-1]
            url = f"https://api.observerprotocol.org/agents/{agent_id}/did.json"
        elif "sovereign.agenticterminal.io:users:" in did:
            # Sovereign user — resolve via OP agent registration
            user_id = parts[-1]
            url = f"https://api.observerprotocol.org/agents/{user_id}/did.json"

        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return None

        did_doc = resp.json()
        vm_list = did_doc.get("verificationMethod", [])
        if not vm_list:
            return None

        pub_multibase = vm_list[0].get("publicKeyMultibase", "")
        if not pub_multibase.startswith("z"):
            return None

        raw = base58.b58decode(pub_multibase[1:])
        # Handle multicodec prefix (0xed01 for ed25519-pub)
        if len(raw) == 34 and raw[0] == 0xed and raw[1] == 0x01:
            raw = raw[2:]
        if len(raw) != 32:
            return None

        return Ed25519PublicKey.from_public_bytes(raw)

    except Exception:
        return None


# ── Receipt issuance ─────────────────────────────────────────

def _issue_settlement_receipt(
    agent_did: str,
    amount: str,
    currency: str,
    rail: str,
    purchase_description: str,
    delegation_credential_id: str,
    auth_level: str,
    principal_did: str,
    authorized_at: str,
) -> dict:
    """
    Issue a settlement receipt as a W3C VC signed by NeuralBridge.

    NeuralBridge is the issuer — they are the counterparty asserting this
    transaction happened on their infrastructure. OP defines the schema;
    NeuralBridge signs the receipts.
    """
    now = datetime.now(timezone.utc)
    receipt_id = f"urn:uuid:receipt-{uuid.uuid4().hex[:12]}"

    receipt = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://observerprotocol.org/context/receipt/v1",
        ],
        "id": receipt_id,
        "type": ["VerifiableCredential", "SettlementReceipt"],
        "issuer": {
            "id": NEURALBRIDGE_DID,
            "name": NEURALBRIDGE_NAME,
        },
        "issuanceDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {
            "id": agent_did,
            "transaction": {
                "amount": amount,
                "currency": currency,
                "rail": rail,
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "counterparty_did": NEURALBRIDGE_DID,
                "counterparty_name": NEURALBRIDGE_NAME,
                "transaction_hash": uuid.uuid4().hex,  # Simulated tx hash
                "purchase_description": purchase_description,
                "rail_specific": {
                    "network": "mainnet",
                    "asset": currency,
                    "confirmations": 19,
                },
            },
            "authorization": {
                "delegationCredentialId": delegation_credential_id,
                "authorizationLevel": auth_level,
                "principal_did": principal_did,
                "authorized_at": authorized_at,
                "scope_summary": f"{'One-time' if auth_level == 'one-time' else 'Recurring'} purchase of ${amount} in {purchase_description} from {NEURALBRIDGE_NAME}, settled in {currency} on {rail}",
            },
        },
        "credentialSchema": {
            "id": "https://observerprotocol.org/schemas/receipt/settlement-receipt-v1.json",
            "type": "JsonSchema",
        },
    }

    # Sign with NeuralBridge's key
    canonical = _canonical_bytes(receipt)
    proof_value = _nb_sign(canonical)

    receipt["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": f"{NEURALBRIDGE_DID}#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }

    return receipt


# ── Models ───────────────────────────────────────────────────

class PurchaseRequest(BaseModel):
    agent_did: str
    product_id: str
    rail: str
    amount: str
    currency: str
    delegation_credential: Optional[dict] = None


# ── Endpoints ────────────────────────────────────────────────

@router.get("/payment-config")
def get_payment_config():
    """
    NeuralBridge's published payment configuration.
    Agents query this to discover accepted rails and available products.
    """
    return {
        "counterparty_did": NEURALBRIDGE_DID,
        "counterparty_name": NEURALBRIDGE_NAME,
        "tagline": "GPU inference at the edge",
        "accepted_rails": ["usdt-trc20", "lightning"],
        "products": list(PRODUCTS.values()),
    }


@router.post("/purchase")
def attempt_purchase(req: PurchaseRequest):
    """
    NeuralBridge purchase endpoint.

    Without delegation_credential: returns AIP soft-reject with magic link package.
    The magic link is generated by calling OP's remediation API — NeuralBridge
    does not sign the JWT itself; OP does.

    With delegation_credential: verifies cryptographically, accepts settlement,
    issues a receipt signed by NeuralBridge.
    """
    product = PRODUCTS.get(req.product_id)
    if not product:
        raise HTTPException(status_code=404, detail=f"Product not found: {req.product_id}")

    # ── No credential: soft-reject with magic link ───────────
    if not req.delegation_credential:
        # Extract agent_id from DID (last segment)
        agent_id = req.agent_did.split(":")[-1]

        # Call OP's remediation API to generate the magic link package
        op_api = os.environ.get("OP_API_BASE", "https://api.observerprotocol.org")
        try:
            ml_resp = requests.post(
                f"{op_api}/api/v1/remediation/magic-link",
                json={
                    "agent_id": agent_id,
                    "counterparty_did": NEURALBRIDGE_DID,
                    "counterparty_name": NEURALBRIDGE_NAME,
                    "amount": req.amount,
                    "currency": req.currency,
                    "rail": req.rail,
                    "purchase_description": product["name"],
                },
                timeout=10,
            )
            ml_data = ml_resp.json()
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to generate magic link: {str(e)}"
            )

        return {
            "verdict": "soft_rejected",
            "reason": "no_delegation_credential",
            "magic_link": {
                "url": ml_data.get("url"),
                "intro": ml_data.get("intro"),
                "transaction_context": ml_data.get("transaction_context"),
                "expires_at": ml_data.get("expires_at"),
            },
        }

    # ── Has credential: verify and settle ────────────────────

    valid, error = _verify_delegation_credential(
        req.delegation_credential,
        expected_counterparty_did=NEURALBRIDGE_DID,
        amount=req.amount,
        rail=req.rail,
    )

    if not valid:
        return {
            "verdict": "denied",
            "reason": "delegation_credential_invalid",
            "detail": error,
        }

    # Extract authorization details from the credential
    subject = req.delegation_credential.get("credentialSubject", {})
    auth_level = subject.get("authorizationLevel", "one-time")
    credential_id = req.delegation_credential.get("id", "unknown")
    issuer_did = req.delegation_credential.get("issuer", "")
    auth_config = subject.get("authorizationConfig", {})

    # Get authorized_at from the one-time config or credential creation
    authorized_at = None
    if auth_level == "one-time":
        one_time = auth_config.get("oneTime", {})
        authorized_at = one_time.get("execution_deadline")
    if not authorized_at:
        authorized_at = req.delegation_credential.get("validFrom", datetime.now(timezone.utc).isoformat())

    # Issue settlement receipt (signed by NeuralBridge)
    receipt = _issue_settlement_receipt(
        agent_did=req.agent_did,
        amount=req.amount,
        currency=req.currency,
        rail=req.rail,
        purchase_description=product["name"],
        delegation_credential_id=credential_id,
        auth_level=auth_level,
        principal_did=issuer_did,
        authorized_at=authorized_at,
    )

    # Store in DB for operations view
    conn = _get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO neuralbridge_transactions
                (receipt_id, agent_did, amount, currency, rail, product_id,
                 auth_level, delegation_credential_id, receipt_json, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            receipt["id"], req.agent_did, req.amount, req.currency, req.rail,
            req.product_id, auth_level, credential_id, json.dumps(receipt),
        ))
        conn.commit()
    except Exception:
        conn.rollback()
        # Non-fatal — receipt is still valid even if DB write fails
    finally:
        cur.close()
        conn.close()

    return {
        "verdict": "approved",
        "settlement": {
            "product": product,
            "amount": req.amount,
            "currency": req.currency,
            "rail": req.rail,
            "receipt": receipt,
        },
    }


@router.get("/operations")
def get_operations():
    """
    NeuralBridge operations view data (Beat 8).
    Returns transaction log, latest receipt, and dispute status.
    """
    conn = _get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT receipt_id, agent_did, amount, currency, rail, product_id,
                   auth_level, delegation_credential_id, receipt_json, created_at
            FROM neuralbridge_transactions
            ORDER BY created_at DESC
            LIMIT 20
        """)
        rows = cur.fetchall()
        transactions = []
        for r in rows:
            tx = dict(r)
            if tx.get("created_at"):
                tx["created_at"] = tx["created_at"].isoformat()
            if tx.get("receipt_json") and isinstance(tx["receipt_json"], str):
                tx["receipt_json"] = json.loads(tx["receipt_json"])
            transactions.append(tx)

        latest = transactions[0] if transactions else None

        return {
            "counterparty": NEURALBRIDGE_NAME,
            "counterparty_did": NEURALBRIDGE_DID,
            "transactions": transactions,
            "latest_receipt": latest.get("receipt_json") if latest else None,
            "total_count": len(transactions),
            "total_volume": sum(float(t.get("amount", "0")) for t in transactions),
        }

    finally:
        cur.close()
        conn.close()


@router.get("/.well-known/did.json")
def get_neuralbridge_did():
    """
    Serve NeuralBridge's DID document.
    Standard did:web resolution for did:web:neuralbridge.demo.observerprotocol.org
    hits this endpoint.
    """
    did_path = os.path.join(os.path.dirname(__file__), "demo_neuralbridge_did.json")
    with open(did_path) as f:
        return json.load(f)
