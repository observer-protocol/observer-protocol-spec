"""
x402 Rail Adapter - Observer Protocol

Verifies x402-mediated payments through dual verification:
  1. Primary: Coinbase facilitator verification endpoint
  2. Secondary: Direct Base RPC verification of USDC transfer on-chain

Issues X402PaymentCredential W3C VCs signed by OP's Ed25519 key.

The x402 protocol flow:
  - Client sends request to x402-protected resource
  - Server returns 402 with payment requirements (PaymentRequirements header)
  - Client pays via x402 facilitator (Coinbase)
  - Facilitator settles USDC on Base and returns payment proof
  - Client retries request with payment proof
  - Server verifies payment via facilitator and serves resource

OP's role: observe the settlement, verify both facilitator attestation
and on-chain transfer, issue a W3C VC attesting to the verified payment.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

import requests

# ── Constants ────────────────────────────────────────────────

# Base mainnet
BASE_CHAIN_ID = "eip155:8453"
BASE_RPC_URL = "https://mainnet.base.org"

# Base Sepolia testnet
BASE_SEPOLIA_CHAIN_ID = "eip155:84532"
BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org"

# USDC contract addresses
USDC_BASE_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

# Coinbase x402 facilitator (multiple known endpoints)
COINBASE_FACILITATOR_URL = "https://x402.org/facilitator"
COINBASE_FACILITATOR_FALLBACKS = [
    "https://x402.org/facilitator",
    "https://x402.coinbase.com",
    "https://api.x402.org/verify",
]

# ERC-20 Transfer event topic
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


# ── Facilitator Verification ─────────────────────────────────

def verify_via_facilitator(
    payment_payload: dict,
    facilitator_url: str = None,
) -> Tuple[bool, Optional[dict], Optional[str]]:
    """
    Verify an x402 payment via the Coinbase facilitator endpoint.

    Primary verification path. Tries multiple known facilitator URLs.
    The facilitator confirms the payment was settled and returns details.

    Returns: (verified, details, error)
    """
    urls_to_try = []
    if facilitator_url:
        urls_to_try.append(facilitator_url)
    urls_to_try.extend(COINBASE_FACILITATOR_FALLBACKS)

    last_error = None
    for url in urls_to_try:
        try:
            # Try both /verify suffix and bare URL
            for endpoint in [f"{url}/verify", url]:
                try:
                    resp = requests.post(
                        endpoint,
                        json=payment_payload,
                        headers={"Content-Type": "application/json"},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return True, data, None
                    last_error = f"Facilitator {endpoint} returned {resp.status_code}"
                except requests.exceptions.ConnectionError:
                    last_error = f"Could not connect to {endpoint}"
                    continue
                except Exception as e:
                    last_error = str(e)
                    continue
        except Exception as e:
            last_error = str(e)

    return False, None, f"All facilitator endpoints failed. Last: {last_error}"


# ── On-Chain Verification (Base RPC) ─────────────────────────

def verify_onchain(
    tx_hash: str,
    expected_amount: str,
    expected_recipient: Optional[str] = None,
    network: str = "mainnet",
) -> Tuple[bool, Optional[dict], Optional[str]]:
    """
    Verify USDC transfer on Base via direct RPC query.

    Secondary verification - ground truth layer. If the facilitator
    says "verified" but on-chain settlement isn't visible, OP surfaces
    the discrepancy in the credential.

    Returns: (verified, details, error)
    """
    rpc_url = BASE_SEPOLIA_RPC_URL if network == "sepolia" else BASE_RPC_URL
    usdc_contract = USDC_BASE_SEPOLIA if network == "sepolia" else USDC_BASE_MAINNET

    try:
        # Get transaction receipt
        receipt_resp = requests.post(rpc_url, json={
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
        }, timeout=10)

        receipt_data = receipt_resp.json()
        receipt = receipt_data.get("result")
        if not receipt:
            return False, None, "Transaction receipt not found on-chain"

        # Check transaction succeeded
        if receipt.get("status") != "0x1":
            return False, None, "Transaction reverted on-chain"

        # Look for USDC Transfer event in logs
        confirmations = 0
        transfer_found = False
        transfer_details = {}

        for log in receipt.get("logs", []):
            if (log.get("address", "").lower() == usdc_contract.lower()
                    and len(log.get("topics", [])) >= 3
                    and log["topics"][0] == TRANSFER_TOPIC):
                transfer_found = True
                # Decode amount from data field
                raw_amount = int(log["data"], 16) if log.get("data") else 0
                from_addr = "0x" + log["topics"][1][-40:]
                to_addr = "0x" + log["topics"][2][-40:]
                transfer_details = {
                    "from": from_addr,
                    "to": to_addr,
                    "amount": str(raw_amount),
                    "contract": log["address"],
                }
                break

        if not transfer_found:
            return False, None, "No USDC Transfer event found in transaction logs"

        # Verify amount matches (if expected)
        if expected_amount and transfer_details.get("amount") != expected_amount:
            return False, transfer_details, (
                f"Amount mismatch: on-chain={transfer_details['amount']}, "
                f"expected={expected_amount}"
            )

        # Verify recipient (if expected)
        if expected_recipient:
            if transfer_details.get("to", "").lower() != expected_recipient.lower():
                return False, transfer_details, "Recipient mismatch"

        # Get current block for confirmation count
        block_resp = requests.post(rpc_url, json={
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 2,
        }, timeout=10)
        current_block = int(block_resp.json().get("result", "0x0"), 16)
        tx_block = int(receipt.get("blockNumber", "0x0"), 16)
        confirmations = current_block - tx_block

        transfer_details["confirmations"] = confirmations
        transfer_details["block_number"] = tx_block

        return True, transfer_details, None

    except Exception as e:
        return False, None, f"On-chain verification failed: {str(e)}"


# ── Credential Issuance ──────────────────────────────────────

def issue_x402_credential(
    agent_did: str,
    agent_id: str,
    counterparty: str,
    payment_scheme: str,
    network: str,
    asset_address: str,
    asset_symbol: str,
    amount: str,
    resource_uri: str,
    facilitator: str,
    settlement_tx_hash: str,
    payment_payload: dict,
    facilitator_verified: bool,
    onchain_verified: bool,
    onchain_confirmations: int = 0,
    discrepancy: bool = False,
) -> dict:
    """
    Issue an X402PaymentCredential W3C VC signed by OP.

    Requires vc_issuer module for Ed25519 signing.
    """
    from vc_issuer import issue_vc

    # Hash the payment payload for non-repudiation
    payload_canonical = json.dumps(payment_payload, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_canonical.encode()).hexdigest()

    claims = {
        "counterparty": counterparty,
        "paymentScheme": payment_scheme,
        "network": network,
        "asset": {
            "address": asset_address,
            "symbol": asset_symbol,
        },
        "amount": amount,
        "resource": resource_uri,
        "facilitator": facilitator,
        "settlementTxHash": settlement_tx_hash,
        "paymentPayloadHash": payload_hash,
        "verification": {
            "facilitator_verified": facilitator_verified,
            "onchain_verified": onchain_verified,
            "onchain_confirmations": onchain_confirmations,
            "discrepancy": discrepancy,
        },
        "agentId": agent_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    vc = issue_vc(
        subject_did=agent_did,
        credential_type="X402PaymentCredential",
        claims=claims,
        expiration_days=30,
    )

    return vc


# ── Full Verification Pipeline ───────────────────────────────

def verify_and_attest(
    agent_did: str,
    agent_id: str,
    counterparty: str,
    payment_scheme: str,
    network: str,
    asset_address: str,
    asset_symbol: str,
    amount: str,
    resource_uri: str,
    facilitator_url: str,
    settlement_tx_hash: str,
    payment_payload: dict,
) -> dict:
    """
    Full x402 verification pipeline: facilitator + on-chain, then issue VC.

    Returns the issued X402PaymentCredential or raises on total failure.
    """
    # Step 1: Facilitator verification (primary)
    fac_verified, fac_details, fac_error = verify_via_facilitator(
        payment_payload, facilitator_url
    )

    # Step 2: On-chain verification (secondary / ground truth)
    chain_network = "sepolia" if ("84532" in network or "sepolia" in network) else "mainnet"
    onchain_verified, onchain_details, onchain_error = verify_onchain(
        settlement_tx_hash, amount, network=chain_network
    )

    # Determine discrepancy
    discrepancy = fac_verified != onchain_verified

    # At least one verification must pass
    if not fac_verified and not onchain_verified:
        raise ValueError(
            f"Both verifications failed. "
            f"Facilitator: {fac_error}. On-chain: {onchain_error}"
        )

    confirmations = 0
    if onchain_details:
        confirmations = onchain_details.get("confirmations", 0)

    # Issue credential
    vc = issue_x402_credential(
        agent_did=agent_did,
        agent_id=agent_id,
        counterparty=counterparty,
        payment_scheme=payment_scheme,
        network=network,
        asset_address=asset_address,
        asset_symbol=asset_symbol,
        amount=amount,
        resource_uri=resource_uri,
        facilitator=facilitator_url,
        settlement_tx_hash=settlement_tx_hash,
        payment_payload=payment_payload,
        facilitator_verified=fac_verified,
        onchain_verified=onchain_verified,
        onchain_confirmations=confirmations,
        discrepancy=discrepancy,
    )

    return {
        "credential": vc,
        "verification": {
            "facilitator_verified": fac_verified,
            "facilitator_error": fac_error,
            "onchain_verified": onchain_verified,
            "onchain_error": onchain_error,
            "onchain_confirmations": confirmations,
            "discrepancy": discrepancy,
        },
    }
