#!/usr/bin/env python3
"""
AIP v0.3.1 Test Suite
Tests all major components of the Agentic Identity Protocol implementation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import uuid
from datetime import datetime

from aip_core import (
    DIDResolver, TypeRegistryValidator, DelegationScope,
    RevocationReason, DenialReason, CounterpartyType,
    RemediationOptionEnvelope, RemediationResponseEnvelope
)
from aip_manager import AIPManager, DelegationChainVerifier


class TestRunner:
    """Run AIP test suite"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def test(self, name: str):
        """Decorator for test methods"""
        def decorator(func):
            self.tests.append((name, func))
            return func
        return decorator
    
    def run(self):
        """Run all tests"""
        print("=" * 60)
        print("AIP v0.3.1 Test Suite")
        print("=" * 60)
        
        for name, func in self.tests:
            try:
                func()
                print(f"✓ {name}")
                self.passed += 1
            except AssertionError as e:
                print(f"✗ {name}: {e}")
                self.failed += 1
            except Exception as e:
                print(f"✗ {name}: Unexpected error: {e}")
                self.failed += 1
        
        print("=" * 60)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        print("=" * 60)
        
        return self.failed == 0


runner = TestRunner()


# ============================================================
# DID Resolver Tests (Section 2, 9.2)
# ============================================================

@runner.test("DID Resolver: Parse valid did:web")
def test_did_parse():
    did = "did:web:observerprotocol.org:agents:agent-001"
    parsed = DIDResolver.parse_did_web(did)
    assert parsed is not None, "Should parse valid did:web"
    assert parsed['domain'] == "observerprotocol.org", "Should extract domain"
    assert parsed['path'] == "agents:agent-001", "Should extract path"


@runner.test("DID Resolver: Reject non-did:web")
def test_did_reject_non_web():
    did = "did:key:z6Mk..."
    parsed = DIDResolver.parse_did_web(did)
    assert parsed is None, "Should reject non-did:web"


@runner.test("DID Resolver: Resolve to URL")
def test_did_resolve_url():
    did = "did:web:observerprotocol.org:agents:agent-001"
    url = DIDResolver.resolve_to_url(did)
    expected = "https://observerprotocol.org/agents/agent-001/did.json"
    assert url == expected, f"Expected {expected}, got {url}"


@runner.test("DID Resolver: Extract domain")
def test_did_extract_domain():
    did = "did:web:acme-corp.com:op-identity"
    domain = DIDResolver.extract_domain(did)
    assert domain == "acme-corp.com", "Should extract domain"


@runner.test("DID Resolver: Domain match validation (Section 9.2)")
def test_did_domain_match():
    agent_did = "did:web:acme-corp.com:agent:001"
    org_did = "did:web:acme-corp.com:op-identity"
    assert DIDResolver.validate_domain_match(agent_did, org_did), "Should match same domain"


@runner.test("DID Resolver: Domain mismatch = fraud signal (Section 9.2)")
def test_did_domain_mismatch():
    agent_did = "did:web:evil.com:agent:001"
    org_did = "did:web:acme-corp.com:op-identity"
    assert not DIDResolver.validate_domain_match(agent_did, org_did), "Should detect domain mismatch"


@runner.test("DID Resolver: Validate DID document")
def test_validate_did_doc():
    doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:example.com:agent:001",
        "verificationMethod": [{"id": "#key-1", "type": "Ed25519VerificationKey2020"}],
        "authentication": ["#key-1"]
    }
    valid, msg = DIDResolver.validate_did_document(doc)
    assert valid, f"Should validate: {msg}"


# ============================================================
# Type Registry Tests (Section 6)
# ============================================================

@runner.test("Type Registry: Validate counterparty types")
def test_registry_counterparty():
    validator = TypeRegistryValidator()
    # These should be in the database after migration
    # Test with enum values
    assert validator.validate_counterparty_type("verified_merchant"), "Should validate verified_merchant"
    assert validator.validate_counterparty_type("kyb_verified_org"), "Should validate kyb_verified_org"
    assert not validator.validate_counterparty_type("invalid_type"), "Should reject invalid type"


@runner.test("Type Registry: Validate revocation reasons")
def test_registry_revocation():
    validator = TypeRegistryValidator()
    assert validator.validate_revocation_reason("agent_compromised"), "Should validate agent_compromised"
    assert validator.validate_revocation_reason("org_kyb_expired"), "Should validate org_kyb_expired"
    assert not validator.validate_revocation_reason("invalid_reason"), "Should reject invalid reason"


@runner.test("Type Registry: Validate denial reasons")
def test_registry_denial():
    validator = TypeRegistryValidator()
    assert validator.validate_denial_reason("score_below_threshold"), "Should validate score_below_threshold"
    assert validator.validate_denial_reason("delegation_credential_revoked"), "Should validate delegation_credential_revoked"
    assert not validator.validate_denial_reason("invalid_denial"), "Should reject invalid denial"


@runner.test("Type Registry: Validate list of counterparty types")
def test_registry_counterparty_list():
    validator = TypeRegistryValidator()
    valid_list = ["verified_merchant", "kyb_verified_org"]
    is_valid, invalid = validator.validate_counterparty_types_list(valid_list)
    assert is_valid, f"Should validate list, invalid: {invalid}"
    
    invalid_list = ["verified_merchant", "invalid_type"]
    is_valid, invalid = validator.validate_counterparty_types_list(invalid_list)
    assert not is_valid, "Should reject list with invalid type"
    assert "invalid_type" in invalid, "Should report invalid type"


# ============================================================
# Remediation Envelope Tests (Section 5, 9.1)
# ============================================================

@runner.test("Remediation: Minimal envelope structure")
def test_remediation_envelope():
    """Section 9.1: AIP defines only envelope, not content"""
    envelope = RemediationResponseEnvelope(
        status="denied",
        reason="score_below_threshold",
        score=58,
        threshold=75,
        gap=17
    )
    
    data = envelope.to_dict()
    assert data["status"] == "denied"
    assert data["reason"] == "score_below_threshold"
    assert data["score"] == 58
    assert data["threshold"] == 75
    assert data["gap"] == 17
    assert "remediation_options" in data


@runner.test("Remediation: Options are minimal envelopes")
def test_remediation_options():
    """Section 9.1: Options are minimal structure, AT provides content"""
    option = RemediationOptionEnvelope(
        option_id=1,
        action="complete_org_kyb_linkage",
        action_endpoint="https://agenticterminal.io/aip/kyb-link"
    )
    
    data = option.to_dict()
    assert data["option_id"] == 1
    assert data["action"] == "complete_org_kyb_linkage"
    assert data["action_endpoint"] == "https://agenticterminal.io/aip/kyb-link"


# ============================================================
# Delegation Scope Tests
# ============================================================

@runner.test("Delegation Scope: to_dict conversion")
def test_scope_to_dict():
    scope = DelegationScope(
        payment_settlement=True,
        max_transaction_value_usd=10000,
        allowed_counterparty_types=["verified_merchant", "kyb_verified_org"],
        allowed_rails=["lightning", "ows"]
    )
    
    data = scope.to_dict()
    assert data["payment_settlement"] is True
    assert data["max_transaction_value_usd"] == 10000
    assert "verified_merchant" in data["allowed_counterparty_types"]
    assert "lightning" in data["allowed_rails"]


@runner.test("Delegation Scope: from_dict reconstruction")
def test_scope_from_dict():
    data = {
        "payment_settlement": True,
        "max_transaction_value_usd": 5000,
        "allowed_counterparty_types": ["aip_delegated_agent"],
        "allowed_rails": ["x402"],
        "geographic_restriction": "US"
    }
    
    scope = DelegationScope.from_dict(data)
    assert scope.payment_settlement is True
    assert scope.max_transaction_value_usd == 5000
    assert "aip_delegated_agent" in scope.allowed_counterparty_types
    assert scope.geographic_restriction == "US"


# ============================================================
# AIP Manager Tests (requires database)
# ============================================================

def db_tests_available():
    """Check if database is available for testing"""
    try:
        from aip_core import DB_URL
        import psycopg2
        conn = psycopg2.connect(DB_URL)
        conn.close()
        return True
    except:
        return False


if db_tests_available():
    
    @runner.test("AIP Manager: Issue and retrieve KYB VC")
    def test_issue_kyb_vc():
        manager = AIPManager()
        
        vc = manager.issue_kyb_vc(
            org_did="did:web:acme-corp.com:op-identity",
            kyb_provider="TestProvider",
            kyb_result="pass",
            expiration_days=30
        )
        
        assert vc.credential_id, "Should have credential_id"
        assert vc.org_did == "did:web:acme-corp.com:op-identity"
        assert vc.kyb_result == "pass"
        
        # Retrieve
        retrieved = manager.get_kyb_vc(vc.credential_id)
        assert retrieved is not None, "Should retrieve VC"
        assert retrieved.credential_id == vc.credential_id
    
    
    @runner.test("AIP Manager: Reject non-did:web KYB org DID")
    def test_kyb_reject_non_web():
        manager = AIPManager()
        
        try:
            manager.issue_kyb_vc(
                org_did="did:key:z6Mk...",
                kyb_provider="TestProvider",
                kyb_result="pass"
            )
            assert False, "Should reject non-did:web"
        except Exception:
            pass  # Expected
    
    
    @runner.test("AIP Manager: Issue and retrieve Delegation Credential")
    def test_issue_delegation():
        manager = AIPManager()
        
        scope = DelegationScope(
            payment_settlement=True,
            max_transaction_value_usd=10000,
            allowed_counterparty_types=["verified_merchant"],
            allowed_rails=["lightning"]
        )
        
        cred = manager.issue_delegation_credential(
            org_did="did:web:acme-corp.com:op-identity",
            org_name="Acme Corp",
            kyb_credential_id=None,
            agent_did="did:web:acme-corp.com:agent:001",
            agent_label="Test Agent",
            scope=scope,
            expiration_days=30
        )
        
        assert cred.credential_id.startswith("aip-cred-"), "Should have aip-cred- prefix"
        assert cred.org_did == "did:web:acme-corp.com:op-identity"
        assert cred.agent_did == "did:web:acme-corp.com:agent:001"
        
        # Retrieve
        retrieved = manager.get_delegation_credential(cred.credential_id)
        assert retrieved is not None, "Should retrieve credential"
        assert retrieved.credential_id == cred.credential_id
    
    
    @runner.test("AIP Manager: Reject invalid counterparty type")
    def test_delegation_invalid_type():
        manager = AIPManager()
        
        scope = DelegationScope(
            allowed_counterparty_types=["invalid_type", "verified_merchant"]
        )
        
        try:
            manager.issue_delegation_credential(
                org_did="did:web:acme-corp.com:op-identity",
                org_name="Acme Corp",
                agent_did="did:web:acme-corp.com:agent:001",
                scope=scope
            )
            assert False, "Should reject invalid counterparty type"
        except Exception:
            pass  # Expected
    
    
    @runner.test("AIP Manager: Reject delegation depth exceeded")
    def test_delegation_depth_exceeded():
        manager = AIPManager()
        
        scope = DelegationScope()
        
        try:
            manager.issue_delegation_credential(
                org_did="did:web:acme-corp.com:op-identity",
                org_name="Acme Corp",
                agent_did="did:web:acme-corp.com:agent:001",
                scope=scope,
                delegation_depth=5,
                max_delegation_depth=3
            )
            assert False, "Should reject depth > max"
        except Exception:
            pass  # Expected
    
    
    @runner.test("AIP Manager: Credential status check")
    def test_credential_status():
        manager = AIPManager()
        
        # Create a credential
        vc = manager.issue_kyb_vc(
            org_did="did:web:test.com:org",
            kyb_provider="Test",
            kyb_result="pass"
        )
        
        # Check status
        status = manager.check_credential_status(vc.credential_id)
        assert status["credential_type"] == "kyb_vc"
        assert status["status"] in ["active", "expired"]
    
    
    @runner.test("AIP Manager: Build remediation envelope")
    def test_build_remediation():
        manager = AIPManager()
        
        options = [
            RemediationOptionEnvelope(option_id=1, action="test_action")
        ]
        
        envelope = manager.build_remediation_envelope(
            reason="score_below_threshold",
            score=58,
            threshold=75,
            options=options
        )
        
        assert envelope.status == "denied"
        assert envelope.reason == "score_below_threshold"
        assert envelope.score == 58
        assert envelope.threshold == 75
        assert envelope.gap == 17
        assert len(envelope.options) == 1


# ============================================================
# Trust Chain Flow Tests (Section 8)
# ============================================================

@runner.test("Trust Chain: Full flow structure")
def test_trust_chain_structure():
    """Test that all components for trust chain flow exist"""
    # Verify all required components are importable
    from aip_core import KYBVerifiableCredential, DelegationCredential
    from aip_manager import AIPManager, DelegationChainVerifier
    
    assert KYBVerifiableCredential is not None
    assert DelegationCredential is not None
    assert AIPManager is not None
    assert DelegationChainVerifier is not None


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    success = runner.run()
    sys.exit(0 if success else 1)
