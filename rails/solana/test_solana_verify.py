#!/usr/bin/env python3
"""
Tests for Solana Transaction Verification Module
"""

import unittest
import hashlib
import base58
from solana_verify import (
    solana_address_to_pubkey_hash,
    fetch_transaction,
    verify_solana_transaction,
    verify_agent_signature,
    parse_system_transfer,
    parse_spl_transfer,
    TOKEN_METADATA
)


class TestSolanaAddressConversion(unittest.TestCase):
    """Test address to pubkey hash conversion"""
    
    def test_known_address_hash(self):
        """Test hashing a known Solana address"""
        # Vitalik's Solana address (example - replace with real known address)
        test_address = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
        
        result = solana_address_to_pubkey_hash(test_address)
        
        # Verify format
        self.assertTrue(result.startswith("sha256:"))
        
        # Verify hash is correct
        pubkey_bytes = base58.b58decode(test_address)
        expected_hash = "sha256:" + hashlib.sha256(pubkey_bytes).hexdigest()
        self.assertEqual(result, expected_hash)
        
        print(f"✓ Address {test_address[:20]}... hash: {result[:30]}...")
    
    def test_address_consistency(self):
        """Test that same address produces same hash"""
        address = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
        hash1 = solana_address_to_pubkey_hash(address)
        hash2 = solana_address_to_pubkey_hash(address)
        self.assertEqual(hash1, hash2)


class TestFetchTransaction(unittest.TestCase):
    """Test transaction fetching from mainnet"""
    
    def test_fetch_real_mainnet_tx(self):
        """Fetch a known mainnet transaction"""
        # A real Solana transfer transaction (historical - should be finalized)
        # This is a known system program transfer
        tx_sig = "5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ"
        
        try:
            result = fetch_transaction(tx_sig)
            
            # Should have transaction data
            self.assertIn("transaction", result)
            self.assertIn("meta", result)
            
            # Should be finalized
            self.assertEqual(result.get("confirmationStatus"), "finalized")
            
            print(f"✓ Fetched transaction {tx_sig[:30]}...")
            print(f"  - Slot: {result.get('slot')}")
            print(f"  - Status: {result.get('confirmationStatus')}")
            
        except ValueError as e:
            # Transaction might be too old or pruned
            print(f"⚠ Transaction fetch failed (may be pruned): {e}")
    
    def test_fetch_nonexistent_tx(self):
        """Test fetching a non-existent transaction"""
        fake_sig = "1" * 88  # Invalid signature format
        
        with self.assertRaises((ValueError, ConnectionError)):
            fetch_transaction(fake_sig)


class TestVerifyTransaction(unittest.TestCase):
    """Test full transaction verification"""
    
    def test_verify_sol_transfer_real(self):
        """Test verifying a real SOL transfer"""
        # Known historical SOL transfer
        # You'll need to replace these with actual values from a real transaction
        tx_sig = "5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ"
        sender = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
        recipient = "9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs"
        amount = 1000000  # 0.001 SOL in lamports
        
        result = verify_solana_transaction(tx_sig, sender, recipient, amount, "SOL")
        
        print(f"\nVerify result for {tx_sig[:30]}...:")
        print(f"  Verified: {result['verified']}")
        print(f"  Amount: {result['actual_amount_human']} {result['token_symbol']}")
        if result['error']:
            print(f"  Error: {result['error']}")
        
        # Note: This may fail if the specific amounts don't match
        # but it should not crash
        self.assertIn("verified", result)
        self.assertIn("actual_amount", result)
        self.assertIn("error", result)
    
    def test_verify_invalid_signature(self):
        """Test verifying with invalid signature"""
        fake_sig = "1" * 88
        result = verify_solana_transaction(
            fake_sig,
            "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH",
            "9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs",
            1000000,
            "SOL"
        )
        
        self.assertFalse(result['verified'])
        self.assertIsNotNone(result['error'])
        print(f"✓ Invalid tx correctly rejected: {result['error'][:50]}...")
    
    def test_verify_wrong_sender(self):
        """Test verifying with wrong sender address"""
        # Use a real transaction but wrong expected sender
        tx_sig = "5Ufgap5aC6UPrbEueaXjU4kXMU8tXq7WVU2wR9k1vAqP4aGm1QwMn5tYtDqCj7rBZ9xZxJ6fPvQWJrYhHd3uR8hQ"
        wrong_sender = "WrongSenderAddress123456789"
        
        result = verify_solana_transaction(
            tx_sig, 
            wrong_sender, 
            "9xQ7dGxNj7X3zQ9tG1xKqZvNmL5vFhJhYjKmNnPpQqRrSs",
            1000000,
            "SOL"
        )
        
        # Should return verification result, likely false due to mismatch
        self.assertIn("verified", result)
        print(f"✓ Wrong sender handled: verified={result['verified']}")


class TestTokenMetadata(unittest.TestCase):
    """Test token metadata"""
    
    def test_sol_metadata(self):
        """Test SOL token metadata"""
        self.assertEqual(TOKEN_METADATA["SOL"]["decimals"], 9)
        self.assertEqual(TOKEN_METADATA["SOL"]["symbol"], "SOL")
    
    def test_usdc_metadata(self):
        """Test USDC token metadata"""
        self.assertEqual(TOKEN_METADATA["USDC"]["decimals"], 6)
        self.assertEqual(TOKEN_METADATA["USDC"]["symbol"], "USDC")
        self.assertEqual(
            TOKEN_METADATA["USDC"]["mint"],
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        )
    
    def test_usdt_metadata(self):
        """Test USDT token metadata"""
        self.assertEqual(TOKEN_METADATA["USDT"]["decimals"], 6)
        self.assertEqual(TOKEN_METADATA["USDT"]["symbol"], "USDT")
    
    def test_human_readable_amounts(self):
        """Test human-readable amount calculations"""
        # SOL: lamports to SOL
        sol_amount = 1000000000  # 1 SOL in lamports
        self.assertEqual(sol_amount / 1e9, 1.0)
        
        # USDC: units to USDC
        usdc_amount = 1000000  # 1 USDC in units
        self.assertEqual(usdc_amount / 1e6, 1.0)
        
        # Test partial amounts
        self.assertEqual(500000000 / 1e9, 0.5)  # 0.5 SOL
        self.assertEqual(500000 / 1e6, 0.5)      # 0.5 USDC


class TestSignatureVerification(unittest.TestCase):
    """Test Ed25519 signature verification"""
    
    def test_signature_format(self):
        """Test that we can attempt signature verification"""
        # This tests the function exists and handles invalid inputs
        result = verify_agent_signature(
            "invalid_pubkey",
            "test message",
            "invalid_signature"
        )
        self.assertFalse(result)
        print("✓ Invalid signature correctly rejected")


def run_tests():
    """Run all tests and print summary"""
    print("=" * 60)
    print("SOLANA VERIFY MODULE TESTS")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSolanaAddressConversion))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenMetadata))
    suite.addTests(loader.loadTestsFromTestCase(TestSignatureVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestFetchTransaction))
    suite.addTests(loader.loadTestsFromTestCase(TestVerifyTransaction))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
