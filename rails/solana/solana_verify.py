#!/usr/bin/env python3
"""
Solana Transaction Verification Module for Observer Protocol
Provides Ed25519 verification and transaction parsing for Solana payments
"""

import os
import json
import hashlib
import base64
from typing import Optional, Dict, Any
import requests
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Constants
HELIUS_RPC_URL = "https://mainnet.helius-rpc.com/?api-key={}"
FALLBACK_RPC_URL = "https://api.mainnet-beta.solana.com"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# Token metadata
TOKEN_METADATA = {
    "SOL": {"decimals": 9, "symbol": "SOL", "mint": None},
    "USDC": {"decimals": 6, "symbol": "USDC", "mint": USDC_MINT},
    "USDT": {"decimals": 6, "symbol": "USDT", "mint": USDT_MINT},
}


def get_helius_api_key() -> Optional[str]:
    """Get Helius API key from environment"""
    return os.environ.get("HELIUS_API_KEY")


def solana_address_to_pubkey_hash(address: str) -> str:
    """
    Convert Solana base58 address to SHA256 pubkey hash
    
    Args:
        address: Solana base58-encoded address (32-44 chars)
        
    Returns:
        sha256:hexdigest format string
    """
    # Decode base58 address to bytes
    pubkey_bytes = base58.b58decode(address)
    
    # SHA256 hash
    sha256_hash = hashlib.sha256(pubkey_bytes).hexdigest()
    
    return f"sha256:{sha256_hash}"


def fetch_transaction(tx_signature: str, max_retries: int = 2) -> dict:
    """
    Fetch transaction from Solana mainnet via Helius or fallback RPC
    
    Args:
        tx_signature: Transaction signature (base58)
        max_retries: Number of retry attempts
        
    Returns:
        Transaction data dict
        
    Raises:
        ValueError: If transaction not found or not finalized
        ConnectionError: If all RPC endpoints fail
    """
    helius_key = get_helius_api_key()
    
    rpc_urls = []
    if helius_key:
        rpc_urls.append(HELIUS_RPC_URL.format(helius_key))
    rpc_urls.append(FALLBACK_RPC_URL)
    
    last_error = None
    
    for rpc_url in rpc_urls:
        for attempt in range(max_retries):
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getTransaction",
                    "params": [
                        tx_signature,
                        {
                            "encoding": "jsonParsed",
                            "maxSupportedTransactionVersion": 0,
                            "commitment": "finalized"
                        }
                    ]
                }
                
                response = requests.post(
                    rpc_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                
                if "error" in data:
                    error_msg = data["error"].get("message", "Unknown RPC error")
                    if "not found" in error_msg.lower():
                        raise ValueError(f"Transaction not found: {tx_signature}")
                    raise ConnectionError(f"RPC error: {error_msg}")
                
                result = data.get("result")
                if result is None:
                    raise ValueError(f"Transaction not found: {tx_signature}")
                
                # Check confirmation status
                meta = result.get("meta", {})
                confirmation_status = result.get("confirmationStatus") or meta.get("confirmationStatus")
                
                if confirmation_status != "finalized":
                    raise ValueError(f"Transaction not finalized. Status: {confirmation_status}")
                
                if meta.get("err"):
                    raise ValueError(f"Transaction failed on-chain: {meta['err']}")
                
                return result
                
            except (requests.RequestException, ValueError) as e:
                last_error = e
                if attempt < max_retries - 1:
                    continue
    
    raise ConnectionError(f"All RPC endpoints failed. Last error: {last_error}")


def parse_system_transfer(tx_data: dict, expected_sender: str, expected_recipient: str) -> tuple:
    """
    Parse SOL transfer from system program instructions
    
    Returns:
        (actual_amount_lamports: int, is_valid: bool)
    """
    transaction = tx_data.get("transaction", {})
    message = transaction.get("message", {})
    instructions = message.get("instructions", [])
    account_keys = message.get("accountKeys", [])
    
    # Get sender from first account key (fee payer)
    if not account_keys:
        return 0, False
    
    actual_sender = account_keys[0].get("pubkey") if isinstance(account_keys[0], dict) else account_keys[0]
    
    if actual_sender != expected_sender:
        return 0, False
    
    # Look for system transfer instruction
    for ix in instructions:
        program_id = ix.get("programId")
        if program_id != SYSTEM_PROGRAM_ID:
            continue
            
        parsed = ix.get("parsed", {})
        if parsed.get("type") != "transfer":
            continue
            
        info = parsed.get("info", {})
        source = info.get("source")
        destination = info.get("destination")
        lamports = info.get("lamports", 0)
        
        if source == expected_sender and destination == expected_recipient:
            return lamports, True
    
    return 0, False


def parse_spl_transfer(tx_data: dict, expected_sender: str, expected_recipient: str, mint: str) -> tuple:
    """
    Parse SPL token transfer from token balances
    
    Returns:
        (actual_amount_units: int, decimals: int, is_valid: bool)
    """
    meta = tx_data.get("meta", {})
    pre_balances = meta.get("preTokenBalances", [])
    post_balances = meta.get("postTokenBalances", [])
    
    # Find decimals from mint
    decimals = 6  # Default for USDC/USDT
    for balance in post_balances:
        if balance.get("mint") == mint:
            decimals = balance.get("uiTokenAmount", {}).get("decimals", 6)
            break
    
    # Calculate recipient delta
    recipient_pre = 0
    recipient_post = 0
    
    for balance in pre_balances:
        if balance.get("mint") == mint:
            owner = balance.get("owner")
            if owner == expected_recipient:
                recipient_pre = int(balance.get("uiTokenAmount", {}).get("amount", 0))
    
    for balance in post_balances:
        if balance.get("mint") == mint:
            owner = balance.get("owner")
            if owner == expected_recipient:
                recipient_post = int(balance.get("uiTokenAmount", {}).get("amount", 0))
    
    # Check sender delta
    sender_pre = 0
    sender_post = 0
    
    for balance in pre_balances:
        if balance.get("mint") == mint:
            owner = balance.get("owner")
            if owner == expected_sender:
                sender_pre = int(balance.get("uiTokenAmount", {}).get("amount", 0))
    
    for balance in post_balances:
        if balance.get("mint") == mint:
            owner = balance.get("owner")
            if owner == expected_sender:
                sender_post = int(balance.get("uiTokenAmount", {}).get("amount", 0))
    
    # Verify transfer occurred
    if recipient_post > recipient_pre and sender_pre > sender_post:
        delta = recipient_post - recipient_pre
        return delta, decimals, True
    
    return 0, decimals, False


def verify_solana_transaction(
    tx_signature: str,
    sender_address: str,
    recipient_address: str,
    amount_lamports: int,
    mint: str = "SOL"
) -> dict:
    """
    Verify a Solana transaction matches expected parameters
    
    Args:
        tx_signature: Transaction signature
        sender_address: Expected sender wallet address
        recipient_address: Expected recipient wallet address
        amount_lamports: Expected amount (lamports for SOL, units for SPL)
        mint: "SOL", "USDC", "USDT", or full mint address for SPL tokens
        
    Returns:
        Verification result dict with fields:
        - verified: bool
        - actual_amount: int
        - actual_amount_human: float
        - token: str
        - token_symbol: str
        - token_decimals: int
        - error: str or None
    """
    try:
        # Fetch transaction
        tx_data = fetch_transaction(tx_signature)
        
        # Get token metadata
        token_upper = mint.upper()
        if token_upper in TOKEN_METADATA:
            token_info = TOKEN_METADATA[token_upper]
            decimals = token_info["decimals"]
            symbol = token_info["symbol"]
            mint_address = token_info["mint"]
        else:
            # Custom SPL token
            decimals = 6  # Assume 6 decimals for unknown tokens
            symbol = mint[:4] + "..." if len(mint) > 8 else mint
            mint_address = mint
        
        # Parse based on token type
        if mint.upper() == "SOL":
            actual_amount, is_valid = parse_system_transfer(
                tx_data, sender_address, recipient_address
            )
            
            if not is_valid:
                return {
                    "verified": False,
                    "actual_amount": 0,
                    "actual_amount_human": 0.0,
                    "token": "SOL",
                    "token_symbol": "SOL",
                    "token_decimals": 9,
                    "error": "Sender/recipient mismatch or no valid transfer instruction found"
                }
            
            # Allow small tolerance for fees/changes
            tolerance = 1000  # 0.000001 SOL tolerance
            if abs(actual_amount - amount_lamports) > tolerance:
                return {
                    "verified": False,
                    "actual_amount": actual_amount,
                    "actual_amount_human": actual_amount / 1e9,
                    "token": "SOL",
                    "token_symbol": "SOL",
                    "token_decimals": 9,
                    "error": f"Amount mismatch: expected {amount_lamports}, got {actual_amount}"
                }
            
            return {
                "verified": True,
                "actual_amount": actual_amount,
                "actual_amount_human": actual_amount / 1e9,
                "token": "SOL",
                "token_symbol": "SOL",
                "token_decimals": 9,
                "error": None
            }
        
        else:
            # SPL token transfer
            actual_amount, decimals, is_valid = parse_spl_transfer(
                tx_data, sender_address, recipient_address, mint_address or mint
            )
            
            if not is_valid:
                return {
                    "verified": False,
                    "actual_amount": 0,
                    "actual_amount_human": 0.0,
                    "token": mint,
                    "token_symbol": symbol,
                    "token_decimals": decimals,
                    "error": "Token transfer not found or sender/recipient mismatch"
                }
            
            # Verify amount (exact match for SPL)
            if actual_amount != amount_lamports:
                return {
                    "verified": False,
                    "actual_amount": actual_amount,
                    "actual_amount_human": actual_amount / (10 ** decimals),
                    "token": mint,
                    "token_symbol": symbol,
                    "token_decimals": decimals,
                    "error": f"Amount mismatch: expected {amount_lamports}, got {actual_amount}"
                }
            
            return {
                "verified": True,
                "actual_amount": actual_amount,
                "actual_amount_human": actual_amount / (10 ** decimals),
                "token": mint,
                "token_symbol": symbol,
                "token_decimals": decimals,
                "error": None
            }
    
    except ValueError as e:
        return {
            "verified": False,
            "actual_amount": 0,
            "actual_amount_human": 0.0,
            "token": mint,
            "token_symbol": TOKEN_METADATA.get(mint.upper(), {}).get("symbol", mint),
            "token_decimals": TOKEN_METADATA.get(mint.upper(), {}).get("decimals", 6),
            "error": str(e)
        }
    
    except Exception as e:
        return {
            "verified": False,
            "actual_amount": 0,
            "actual_amount_human": 0.0,
            "token": mint,
            "token_symbol": TOKEN_METADATA.get(mint.upper(), {}).get("symbol", mint),
            "token_decimals": TOKEN_METADATA.get(mint.upper(), {}).get("decimals", 6),
            "error": f"Unexpected error: {str(e)}"
        }


def verify_agent_signature(
    agent_pubkey: str,
    message: str,
    signature_b58: str
) -> bool:
    """
    Verify an agent's Ed25519 signature
    
    Args:
        agent_pubkey: Agent's Ed25519 public key (base58)
        message: Message that was signed
        signature_b58: Base58-encoded signature
        
    Returns:
        True if signature is valid
    """
    try:
        # Decode public key and signature
        pubkey_bytes = base58.b58decode(agent_pubkey)
        signature_bytes = base58.b58decode(signature_b58)
        message_bytes = message.encode('utf-8')
        
        # Reconstruct public key
        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        
        # Verify signature
        public_key.verify(signature_bytes, message_bytes)
        return True
    
    except InvalidSignature:
        return False
    except Exception:
        return False


if __name__ == "__main__":
    # Simple test
    print("Solana Verify Module - Run test_solana_verify.py for tests")
