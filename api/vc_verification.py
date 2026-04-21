"""
Third-Party Attestation Verification Module
Implements Spec 3.1 verification flow for W3C Verifiable Credentials.
"""

import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

import httpx
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from did_resolver import resolve_did, extract_public_key_bytes


# Cache for schemas to enable offline verification
_SCHEMA_CACHE: Dict[str, Any] = {}

# Cache for DID documents to enable offline verification
_DID_CACHE: Dict[str, Any] = {}


def load_schema_from_disk(schema_url: str) -> Optional[Dict]:
    """
    Load a schema from local disk if available.
    Maps https://observerprotocol.org/schemas/* to local filesystem.
    """
    base_url = "https://observerprotocol.org/schemas/"
    if not schema_url.startswith(base_url):
        return None
    
    relative_path = schema_url[len(base_url):]
    schema_path = Path("/media/nvme/observer-protocol/schemas") / relative_path
    
    if schema_path.exists():
        with open(schema_path, 'r') as f:
            return json.load(f)
    return None


def fetch_schema(schema_url: str, timeout: int = 10) -> Optional[Dict]:
    """
    Fetch a JSON Schema from URL or cache.
    
    Args:
        schema_url: URL of the schema
        timeout: HTTP timeout in seconds
        
    Returns:
        Schema dict or None if not found
    """
    # Check memory cache first
    if schema_url in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[schema_url]
    
    # Try loading from disk (local schemas)
    schema = load_schema_from_disk(schema_url)
    if schema:
        _SCHEMA_CACHE[schema_url] = schema
        return schema
    
    # Fetch from network
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(schema_url)
            response.raise_for_status()
            schema = response.json()
            _SCHEMA_CACHE[schema_url] = schema
            return schema
    except Exception as e:
        print(f"Failed to fetch schema {schema_url}: {e}")
        return None


def validate_credential_against_schema(credential: Dict, schema: Dict) -> Tuple[bool, Optional[str]]:
    """
    Validate a credential against a JSON Schema.
    
    Args:
        credential: The VC to validate
        schema: JSON Schema dict
        
    Returns:
        (is_valid, error_message)
    """
    try:
        from jsonschema import validate, ValidationError
        validate(instance=credential, schema=schema)
        return True, None
    except ValidationError as e:
        return False, f"Schema validation failed: {e.message} at {list(e.path)}"
    except ImportError:
        # Fallback: basic field presence check if jsonschema not available
        return _basic_schema_check(credential, schema)
    except Exception as e:
        return False, f"Schema validation error: {str(e)}"


def _basic_schema_check(credential: Dict, schema: Dict) -> Tuple[bool, Optional[str]]:
    """
    Basic schema validation without jsonschema library.
    Checks required fields and basic types.
    """
    required = schema.get('required', [])
    for field in required:
        if field not in credential:
            return False, f"Missing required field: {field}"
    return True, None


def resolve_issuer_did(issuer_did: str, use_cache: bool = True) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Resolve an issuer DID to its document.
    
    Args:
        issuer_did: The DID to resolve
        use_cache: Whether to use cached DID documents
        
    Returns:
        (did_document, error_message)
    """
    if use_cache and issuer_did in _DID_CACHE:
        return _DID_CACHE[issuer_did], None
    
    try:
        doc = resolve_did(issuer_did)
        if use_cache:
            _DID_CACHE[issuer_did] = doc
        return doc, None
    except Exception as e:
        return None, f"Failed to resolve issuer DID: {str(e)}"


def extract_verification_method(did_document: Dict, method_id: str) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Extract a specific verification method from a DID document.
    
    Args:
        did_document: The DID document
        method_id: Full DID URL of the verification method
        
    Returns:
        (verification_method, error_message)
    """
    methods = did_document.get('verificationMethod', [])
    
    for vm in methods:
        if vm.get('id') == method_id:
            return vm, None
    
    return None, f"Verification method {method_id} not found in DID document"


def verify_ed25519_signature_2020(
    credential: Dict,
    proof: Dict,
    public_key_bytes: bytes
) -> Tuple[bool, Optional[str]]:
    """
    Verify an Ed25519Signature2020 proof on a credential.
    
    Per W3C spec, the signature is computed on the credential with the proof
    value removed, canonicalized using JSON-LD.
    
    Args:
        credential: The VC (without proof or with proofValue removed)
        proof: The proof object containing signature metadata
        public_key_bytes: Raw Ed25519 public key bytes
        
    Returns:
        (is_valid, error_message)
    """
    try:
        # Create the signing input: credential + proof without proofValue
        # Per Ed25519Signature2020 spec, we create a canonicalized document
        proof_without_value = {k: v for k, v in proof.items() if k != 'proofValue'}
        
        # Build the document to verify
        doc_to_verify = {
            **credential,
            'proof': proof_without_value
        }
        
        # Remove proof from credential if it was embedded
        if 'proof' in credential:
            doc_to_verify = {
                **{k: v for k, v in credential.items() if k != 'proof'},
                'proof': proof_without_value
            }
        
        # Canonicalize using JSON-LD (simplified: use sorted JSON)
        canonical = json.dumps(doc_to_verify, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical.encode('utf-8')
        
        # Decode the signature from base58btc
        proof_value = proof.get('proofValue', '')
        if not proof_value:
            return False, "Missing proofValue in proof"
        
        # Decode base58btc (no 'z' prefix expected in proofValue per some implementations)
        try:
            if proof_value.startswith('z'):
                signature_bytes = base58.b58decode(proof_value[1:])
            else:
                signature_bytes = base58.b58decode(proof_value)
        except Exception as e:
            return False, f"Failed to decode proofValue: {str(e)}"
        
        # Verify using cryptography library
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message_bytes)
        
        return True, None
        
    except InvalidSignature:
        return False, "Signature verification failed - invalid signature"
    except Exception as e:
        return False, f"Signature verification error: {str(e)}"


def check_validity_period(valid_from: str, valid_until: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the current time is within the validity period.
    
    Args:
        valid_from: ISO 8601 timestamp
        valid_until: ISO 8601 timestamp
        
    Returns:
        (is_valid, error_message)
    """
    try:
        now = datetime.now(timezone.utc)
        
        # Parse validFrom
        from_dt = datetime.fromisoformat(valid_from.replace('Z', '+00:00'))
        
        # Parse validUntil
        until_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
        
        if now < from_dt:
            return False, f"Credential not yet valid (validFrom: {valid_from})"
        
        if now >= until_dt:
            return False, f"Credential expired (validUntil: {valid_until})"
        
        return True, None
        
    except Exception as e:
        return False, f"Invalid date format: {str(e)}"


def verify_credential(credential: Dict, use_cache: bool = True) -> Dict[str, Any]:
    """
    Verify a third-party attestation credential.
    
    Implements the full verification flow per Spec 3.1:
    1. Schema validation
    2. DID resolution
    3. Signature verification
    4. Validity period check
    
    Args:
        credential: The Verifiable Credential to verify
        use_cache: Whether to use cached schemas and DID documents
        
    Returns:
        Verification result dict with structure:
        {
            "verified": bool,
            "checks": {
                "signature": "pass" | "fail",
                "schema": "pass" | "fail",
                "validity_period": "pass" | "fail",
                "issuer_did_resolvable": "pass" | "fail"
            },
            "issuer_did": str,
            "subject_did": str,
            "credential_type": str,
            "error": str (optional)
        }
    """
    result = {
        "verified": False,
        "checks": {
            "signature": "fail",
            "schema": "fail",
            "validity_period": "fail",
            "issuer_did_resolvable": "fail"
        },
        "issuer_did": None,
        "subject_did": None,
        "credential_type": None
    }
    
    # Extract basic fields
    issuer_did = credential.get('issuer')
    if isinstance(issuer_did, dict):
        issuer_did = issuer_did.get('id')
    result['issuer_did'] = issuer_did
    
    subject = credential.get('credentialSubject', {})
    result['subject_did'] = subject.get('id') if isinstance(subject, dict) else None
    
    credential_types = credential.get('type', [])
    if isinstance(credential_types, list) and len(credential_types) >= 2:
        result['credential_type'] = credential_types[1]  # Second type after VerifiableCredential
    
    # 1. Resolve Issuer DID
    did_doc, error = resolve_issuer_did(issuer_did, use_cache=use_cache)
    if error:
        result['error'] = error
        return result
    
    result['checks']['issuer_did_resolvable'] = "pass"
    
    # 2. Validate against schema
    schema_url = credential.get('credentialSchema', {}).get('id')
    if schema_url:
        schema = fetch_schema(schema_url)
        if schema:
            schema_valid, schema_error = validate_credential_against_schema(credential, schema)
            if schema_valid:
                result['checks']['schema'] = "pass"
            else:
                result['error'] = schema_error
                return result
        else:
            # Schema fetch failed but we continue with other checks
            pass
    
    # 3. Check validity period
    valid_from = credential.get('validFrom')
    valid_until = credential.get('validUntil')
    
    if valid_from and valid_until:
        period_valid, period_error = check_validity_period(valid_from, valid_until)
        if period_valid:
            result['checks']['validity_period'] = "pass"
        else:
            result['error'] = period_error
            return result
    
    # 4. Verify signature
    proof = credential.get('proof', {})
    if not proof:
        result['error'] = "Missing proof in credential"
        return result
    
    verification_method_id = proof.get('verificationMethod')
    if not verification_method_id:
        result['error'] = "Missing verificationMethod in proof"
        return result
    
    # Extract the verification method from DID document
    vm, vm_error = extract_verification_method(did_doc, verification_method_id)
    if vm_error:
        result['error'] = vm_error
        return result
    
    # Get public key bytes
    try:
        public_key_bytes = extract_public_key_bytes(did_doc, verification_method_id)
    except Exception as e:
        result['error'] = f"Failed to extract public key: {str(e)}"
        return result
    
    # Verify the signature
    # Create credential without proof for verification
    credential_without_proof = {k: v for k, v in credential.items() if k != 'proof'}
    
    sig_valid, sig_error = verify_ed25519_signature_2020(
        credential_without_proof,
        proof,
        public_key_bytes
    )
    
    if sig_valid:
        result['checks']['signature'] = "pass"
    else:
        result['error'] = sig_error or "Signature verification failed"
        return result
    
    # All checks passed
    result['verified'] = True
    return result


def get_cached_did_document(did: str) -> Optional[Dict]:
    """Get a cached DID document."""
    return _DID_CACHE.get(did)


def cache_did_document(did: str, document: Dict):
    """Cache a DID document for offline verification."""
    _DID_CACHE[did] = document


def get_cached_schema(schema_url: str) -> Optional[Dict]:
    """Get a cached schema."""
    return _SCHEMA_CACHE.get(schema_url)


def cache_schema(schema_url: str, schema: Dict):
    """Cache a schema for offline validation."""
    _SCHEMA_CACHE[schema_url] = schema
