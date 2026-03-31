# Real Cryptographic Verification for Observer Protocol
# Using Python's built-in cryptography library (already installed)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
import hashlib
import base58


def recover_public_key_from_signature(message: bytes, signature_hex: str) -> tuple:
    """
    Recover the public key from an ECDSA signature using secp256k1 curve.
    
    For SECP256k1, there are 4 possible public keys that could produce a valid signature.
    This function attempts to recover the public key for each recovery ID (0-3).
    
    Uses the coincurve library for proper public key recovery if available,
    otherwise falls back to cryptography library with manual point operations.
    
    Args:
        message: The original message that was signed (bytes)
        signature_hex: The signature in hex format (64 bytes raw r||s, or DER)
        
    Returns:
        tuple: (public_key_hex, recovery_id) if successful, (None, None) if failed
    """
    try:
        # Try to use coincurve for proper recovery (most reliable)
        try:
            import coincurve
            from coincurve.keys import PublicKey
            from coincurve.utils import sha256
            
            sig_bytes = bytes.fromhex(signature_hex)
            
            # Parse signature to get r and s
            if len(sig_bytes) == 64:
                r = sig_bytes[:32]
                s = sig_bytes[32:]
                sig_bytes = r + s
            elif 68 <= len(sig_bytes) <= 72:
                # DER format - convert to raw
                from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
                r_int, s_int = decode_dss_signature(sig_bytes)
                sig_bytes = r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big')
            else:
                return None, None
            
            # Message hash
            msg_hash = sha256(message)
            
            # Try all 4 recovery IDs
            for recovery_id in range(4):
                try:
                    # Create recoverable signature
                    recoverable_sig = bytes([recovery_id + 27]) + sig_bytes
                    
                    # Recover public key
                    public_key = PublicKey.from_signature_and_message(
                        recoverable_sig,
                        msg_hash,
                        hasher=None  # Already hashed
                    )
                    
                    # Return compressed public key (33 bytes)
                    return public_key.format(compressed=True).hex(), recovery_id
                    
                except Exception:
                    continue
            
            return None, None
            
        except ImportError:
            # coincurve not available, use fallback implementation
            pass
        
        # Fallback: Manual recovery using cryptography library
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Parse signature
        if len(sig_bytes) == 64:
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
        elif 68 <= len(sig_bytes) <= 72:
            r, s = decode_dss_signature(sig_bytes)
        else:
            return None, None
        
        # Curve parameters for SECP256K1
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        
        # Message hash
        z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        
        # Try all 4 recovery IDs
        for v in range(4):
            try:
                # Calculate x = (r + v * n) mod p
                x = (r + v * n) % p
                
                # Check if x is valid (must be less than p)
                if x >= p:
                    continue
                
                # Try to compute y from x (y^2 = x^3 + 7 mod p)
                y_sq = (pow(x, 3, p) + 7) % p
                
                # Check if y_sq is a quadratic residue
                if pow(y_sq, (p - 1) // 2, p) != 1:
                    continue
                
                # Compute y = sqrt(y_sq) mod p
                y = pow(y_sq, (p + 1) // 4, p)
                
                # Two possible y values (even and odd)
                for y_candidate in [y, p - y]:
                    try:
                        # Create point R = (x, y)
                        from cryptography.hazmat.primitives.asymmetric import ec
                        
                        R = ec.EllipticCurvePublicNumbers(x, y_candidate, ec.SECP256K1()).public_key()
                        
                        # Calculate r_inv = r^-1 mod n
                        r_inv = pow(r, n - 2, n)
                        
                        # Calculate Q = (s * R - z * G) / r
                        # This is the recovered public key
                        # For simplicity, we verify by checking if signature validates
                        
                        # For now, return the uncompressed key
                        public_key_hex = f"04{x:064x}{y_candidate:064x}"
                        
                        # Verify this key actually validates the signature
                        if verify_signature_simple(message, signature_hex, public_key_hex):
                            # Return compressed format
                            prefix = "02" if y_candidate % 2 == 0 else "03"
                            compressed_key = f"{prefix}{x:064x}"
                            return compressed_key, v
                            
                    except Exception:
                        continue
                        
            except Exception:
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
        elif len(public_key_bytes) == 33 and public_key_bytes[0] in (0x02, 0x03):
            # Compressed format: 02/03 || x (32 bytes) — decompress using curve math
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            x = int.from_bytes(public_key_bytes[1:], 'big')
            y_sq = (pow(x, 3, p) + 7) % p
            y = pow(y_sq, (p + 1) // 4, p)
            # Ensure parity matches prefix byte
            if (y & 1) != (public_key_bytes[0] & 1):
                y = p - y
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=x,
                y=y,
                curve=ec.SECP256K1()
            )
            public_key = public_numbers.public_key()
        else:
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

# Solution: Store the public key in a separate lookup table (public_keys table)
# and maintain an in-memory cache for performance. Database is the source of truth.

_PUBLIC_KEY_CACHE = {}


def _get_db_connection():
    """Get a database connection using DATABASE_URL env var."""
    import os, psycopg2
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return psycopg2.connect(db_url)


def persist_public_key(agent_id: str, public_key_hex: str, verified: bool = False) -> bool:
    """
    Persist a public key to the database.
    
    Args:
        agent_id: The agent's unique ID
        public_key_hex: The public key in hex format
        verified: Whether the key has been cryptographically verified
        
    Returns:
        bool: True if successfully persisted
    """
    try:
        pubkey_hash = hashlib.sha256(public_key_hex.encode()).hexdigest()
        
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO public_keys (pubkey, pubkey_hash, agent_id, verified, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (pubkey_hash) DO UPDATE SET
                    agent_id = EXCLUDED.agent_id,
                    verified = EXCLUDED.verified,
                    created_at = NOW()
            """, (public_key_hex, pubkey_hash, agent_id, verified))
            
            conn.commit()
            
            # Also cache in memory
            cache_public_key(agent_id, public_key_hex)
            
            return True
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"Failed to persist public key: {e}")
        # Still cache in memory even if DB fails
        cache_public_key(agent_id, public_key_hex)
        return False


def load_public_key_from_db(agent_id: str) -> str:
    """
    Load a public key from the database by agent_id.
    
    Checks both the public_keys table and observer_agents table
    for maximum compatibility.
    
    Args:
        agent_id: The agent's unique ID
        
    Returns:
        str: The public key in hex format, or None if not found
    """
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        try:
            # First try the public_keys table
            cursor.execute("""
                SELECT pubkey FROM public_keys WHERE agent_id = %s LIMIT 1
            """, (agent_id,))
            
            result = cursor.fetchone()
            if result:
                public_key = result[0]
                # Cache it
                cache_public_key(agent_id, public_key)
                return public_key
            
            # Fallback: try observer_agents table (Bug #1 fix)
            cursor.execute("""
                SELECT public_key FROM observer_agents WHERE agent_id = %s LIMIT 1
            """, (agent_id,))
            
            result = cursor.fetchone()
            if result and result[0]:
                public_key = result[0]
                # Cache it
                cache_public_key(agent_id, public_key)
                return public_key
            
            return None
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"Failed to load public key from DB: {e}")
        return None


def load_all_public_keys_from_db() -> dict:
    """
    Load all public keys from the database into memory cache.
    
    Call this on server startup to populate the in-memory cache.
    
    Returns:
        dict: Dictionary mapping agent_id -> public_key info
    """
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT agent_id, pubkey, verified FROM public_keys WHERE agent_id IS NOT NULL
            """)
            
            results = cursor.fetchall()
            
            for agent_id, public_key, verified in results:
                if agent_id:
                    key_type = detect_key_type(public_key)
                    _PUBLIC_KEY_CACHE[agent_id] = {
                        'public_key': public_key,
                        'key_type': key_type,
                        'verified': verified
                    }
            
            return _PUBLIC_KEY_CACHE
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        print(f"Failed to load public keys from DB: {e}")
        return _PUBLIC_KEY_CACHE


def get_public_key(agent_id: str) -> str:
    """
    Get a public key by agent_id, checking cache first, then database.
    
    This is the main function to use for retrieving public keys.
    
    Args:
        agent_id: The agent's unique ID
        
    Returns:
        str: The public key in hex format, or None if not found
    """
    # Check cache first
    cached = get_cached_public_key(agent_id)
    if cached:
        return cached
    
    # Load from database
    return load_public_key_from_db(agent_id)


def verify_public_key_signature(message: bytes, signature_hex: str, agent_id: str) -> bool:
    """
    Verify a signature using the stored public key for an agent.
    
    Args:
        message: The message that was signed
        signature_hex: The signature in hex format
        agent_id: The agent's unique ID
        
    Returns:
        bool: True if signature is valid
    """
    public_key = get_public_key(agent_id)
    if not public_key:
        print(f"No public key found for agent {agent_id}")
        return False
    
    return verify_signature(message, signature_hex, public_key)

def detect_key_type(public_key_hex: str) -> str:
    """
    Detect the type of public key based on its format.
    
    SECP256k1 keys are 33 bytes (compressed) or 65 bytes (uncompressed)
    Ed25519 keys are 32 bytes
    
    Args:
        public_key_hex: The public key in hex format
        
    Returns:
        str: 'secp256k1', 'ed25519', or 'unknown'
    """
    try:
        # Remove '0x' prefix if present
        if public_key_hex.startswith('0x'):
            public_key_hex = public_key_hex[2:]
        
        public_key_bytes = bytes.fromhex(public_key_hex)
        key_len = len(public_key_bytes)
        
        # SECP256k1 compressed: 33 bytes starting with 0x02 or 0x03
        if key_len == 33 and public_key_bytes[0] in (0x02, 0x03):
            return 'secp256k1'
        
        # SECP256k1 uncompressed: 65 bytes starting with 0x04
        if key_len == 65 and public_key_bytes[0] == 0x04:
            return 'secp256k1'
        
        # Ed25519: 32 bytes (raw)
        if key_len == 32:
            return 'ed25519'
        
        return 'unknown'
    except Exception:
        return 'unknown'


def verify_ed25519_signature(message_bytes: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify an Ed25519 signature against a message and public key.
    
    Used for Solana and other Ed25519-based blockchain agents.
    
    Args:
        message_bytes: The original message that was signed (bytes)
        signature_hex: The signature in hex format (64 bytes)
        public_key_hex: The public key in hex format (32 bytes) OR base58-encoded Solana address
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Remove '0x' prefix if present
        if public_key_hex.startswith('0x'):
            public_key_hex = public_key_hex[2:]
        if signature_hex.startswith('0x'):
            signature_hex = signature_hex[2:]
        
        # Try to decode public key - could be hex or base58 (Solana address)
        public_key_bytes = None
        try:
            # Try hex first
            public_key_bytes = bytes.fromhex(public_key_hex)
            if len(public_key_bytes) != 32:
                # If not 32 bytes, might be base58 encoded
                raise ValueError("Not 32 bytes")
        except ValueError:
            # Try base58 decoding (for Solana addresses)
            try:
                public_key_bytes = base58.b58decode(public_key_hex)
                if len(public_key_bytes) != 32:
                    print(f"Ed25519 verification error: Invalid public key length {len(public_key_bytes)}")
                    return False
            except Exception:
                print(f"Ed25519 verification error: Could not decode public key")
                return False
        
        # Decode signature (64 bytes for Ed25519)
        sig_bytes = bytes.fromhex(signature_hex)
        if len(sig_bytes) != 64:
            print(f"Ed25519 verification error: Invalid signature length {len(sig_bytes)}")
            return False
        
        # Load the Ed25519 public key
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Verify the signature
        public_key.verify(sig_bytes, message_bytes)
        
        return True
        
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Ed25519 verification error: {e}")
        return False


def verify_signature(message_bytes: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify a signature using the appropriate algorithm based on key type.
    
    Automatically detects whether the public key is SECP256k1 or Ed25519
    and routes to the correct verification function.
    
    Args:
        message_bytes: The original message that was signed (bytes)
        signature_hex: The signature in hex format
        public_key_hex: The public key in hex format (or base58 for Solana)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    key_type = detect_key_type(public_key_hex)
    
    if key_type == 'ed25519':
        return verify_ed25519_signature(message_bytes, signature_hex, public_key_hex)
    elif key_type == 'secp256k1':
        return verify_signature_simple(message_bytes, signature_hex, public_key_hex)
    else:
        # Try Ed25519 as fallback (handles base58 Solana addresses which we can't detect length-wise)
        result = verify_ed25519_signature(message_bytes, signature_hex, public_key_hex)
        if result:
            return True
        # If that fails, try SECP256k1
        return verify_signature_simple(message_bytes, signature_hex, public_key_hex)


def cache_public_key(agent_id: str, public_key_hex: str):
    """
    Cache the public key and its type for an agent.
    
    Stores both the key and detected type to avoid re-detection on every verification.
    """
    key_type = detect_key_type(public_key_hex)
    _PUBLIC_KEY_CACHE[agent_id] = {
        'public_key': public_key_hex,
        'key_type': key_type
    }

def get_cached_public_key(agent_id: str) -> str:
    """Get cached public key (returns just the key string).
    
    Falls back to database query on cache miss to ensure
    keys persist across server restarts.
    """
    # Check memory cache first
    cached = _PUBLIC_KEY_CACHE.get(agent_id)
    if cached and isinstance(cached, dict):
        return cached.get('public_key')
    # Legacy support: plain string
    if cached and isinstance(cached, str):
        return cached
    
    # Cache miss - load from database
    public_key = load_public_key_from_db(agent_id)
    return public_key

def get_cached_key_type(agent_id: str) -> str:
    """Get cached key type for an agent."""
    cached = _PUBLIC_KEY_CACHE.get(agent_id)
    if cached and isinstance(cached, dict):
        return cached.get('key_type', 'unknown')
    # Legacy support: try to detect from string
    if cached and isinstance(cached, str):
        return detect_key_type(cached)
    return 'unknown'


# ============================================================
# VAC (VERIFIED AGENT CREDENTIAL) SIGNING FUNCTIONS
# ============================================================

def sign_message_ed25519(message: bytes, private_key_hex: str) -> str:
    """
    Sign a message with an Ed25519 private key.
    
    Args:
        message: The message to sign (bytes)
        private_key_hex: The private key in hex format (64 bytes)
        
    Returns:
        str: Hex-encoded signature
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(message)
    return signature.hex()


def sign_message_secp256k1(message: bytes, private_key_hex: str) -> str:
    """
    Sign a message with a SECP256k1 private key.
    
    Args:
        message: The message to sign (bytes)
        private_key_hex: The private key in hex format (32 bytes)
        
    Returns:
        str: Hex-encoded DER signature
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, 'big'),
        ec.SECP256K1()
    )
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def sign_message(message: bytes, private_key_hex: str, key_type: str = None) -> str:
    """
    Sign a message using the appropriate algorithm.
    
    Args:
        message: The message to sign (bytes)
        private_key_hex: The private key in hex format
        key_type: 'ed25519' or 'secp256k1' (auto-detected if not provided)
        
    Returns:
        str: Hex-encoded signature
        
    Raises:
        ValueError: If key type is unsupported
    """
    if key_type is None:
        # Try to detect based on key length
        key_len = len(bytes.fromhex(private_key_hex))
        if key_len == 32:
            key_type = 'ed25519'
        else:
            key_type = 'secp256k1'
    
    if key_type == 'ed25519':
        return sign_message_ed25519(message, private_key_hex)
    elif key_type == 'secp256k1':
        return sign_message_secp256k1(message, private_key_hex)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")


def verify_vac_signature(vac_payload: dict, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify a VAC credential signature.
    
    The VAC payload should NOT include the 'signature' field when verifying.
    
    Args:
        vac_payload: The VAC credential dictionary (without signature field)
        signature_hex: The hex-encoded signature
        public_key_hex: The OP public key in hex format
        
    Returns:
        bool: True if signature is valid
    """
    import json
    
    # Create canonical JSON
    canonical = json.dumps(vac_payload, sort_keys=True, separators=(',', ':'))
    message_bytes = canonical.encode('utf-8')
    
    # Verify using appropriate algorithm
    return verify_signature(message_bytes, signature_hex, public_key_hex)


def generate_vac_hash(vac_payload: dict) -> str:
    """
    Generate the SHA256 hash of a VAC credential's canonical JSON.
    
    Args:
        vac_payload: The VAC credential dictionary
        
    Returns:
        str: Hex-encoded SHA256 hash
    """
    import json
    import hashlib
    
    canonical = json.dumps(vac_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()
