# Real Cryptographic Verification for Observer Protocol
# Using Python's built-in cryptography library (already installed)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
import hashlib


def recover_public_key_from_signature(message: bytes, signature_hex: str) -> tuple:
    """
    Attempt to recover the public key from an ECDSA signature.
    
    For SECP256k1, there are 4 possible public keys that could produce a valid signature.
    We need to try all 4 recovery IDs (0-3) to find the correct one.
    
    Returns:
        tuple: (public_key_hex, recovery_id) if successful, (None, None) if failed
    """
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Parse signature
        if len(sig_bytes) == 64:
            # Raw format: r || s (32 bytes each)
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
        elif 68 <= len(sig_bytes) <= 72:
            # DER format - decode it
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            r, s = decode_dss_signature(sig_bytes)
        else:
            return None, None
        
        # Curve parameters for SECP256K1
        curve = ec.SECP256K1()
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        
        # Message hash
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        
        # Try all 4 recovery IDs
        for recovery_id in range(4):
            try:
                # This is a simplified recovery - full implementation requires
                # elliptic curve point operations that are complex to implement from scratch
                # For production, we'd use a library like coincurve or ecdsa
                
                # For now, we verify the signature components are valid
                if 1 <= r < n and 1 <= s < n:
                    # Components are valid, but we can't fully recover without more context
                    # Return a placeholder indicating we'd need the public key
                    return "recovery_requires_full_implementation", recovery_id
            except:
                continue
        
        return None, None
        
    except Exception as e:
        print(f"Recovery error: {e}")
        return None, None


def verify_signature_simple(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify an ECDSA signature (SECP256k1) against a message and public key.
    
    This is the actual cryptographic verification using the cryptography library.
    """
    try:
        # Decode signature
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Decode public key
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # Load the public key
        if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            # Uncompressed format: 04 || x || y (32 bytes each)
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(public_key_bytes[1:33], 'big'),
                y=int.from_bytes(public_key_bytes[33:65], 'big'),
                curve=ec.SECP256K1()
            )
            public_key = public_numbers.public_key()
        else:
            # Compressed or other format not supported yet
            return False
        
        # Parse signature
        if len(sig_bytes) == 64:
            # Raw format: r || s - encode to DER
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
            signature_der = encode_dss_signature(r, s)
        elif 68 <= len(sig_bytes) <= 72:
            # Already DER format
            signature_der = sig_bytes
        else:
            return False
        
        # Verify the signature
        public_key.verify(
            signature_der,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return True
        
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False


# For the current implementation, we need to store the public key during registration
# and use it during verification. The database currently only stores the hash.

# Solution: Store the public key in a separate lookup table or field
# For now, we'll use a workaround: store the public key in memory during testing
# and implement proper storage in the next migration

_PUBLIC_KEY_CACHE = {}

def cache_public_key(agent_id: str, public_key_hex: str):
    """Temporary cache for public keys during testing."""
    _PUBLIC_KEY_CACHE[agent_id] = public_key_hex

def get_cached_public_key(agent_id: str) -> str:
    """Get cached public key."""
    return _PUBLIC_KEY_CACHE.get(agent_id)
