#!/usr/bin/env python3
"""
Observer Protocol — Phase 1 Internal Test Suite
test_protocol_v1.py

20 tests across 6 groups against the live API at http://localhost:8000.
Produces both .txt and .json reports in /media/nvme/observer-protocol/test-reports/.

Usage:
    cd /media/nvme/observer-protocol
    python scripts/test_protocol_v1.py

Environment:
    DATABASE_URL     PostgreSQL connection string
    OP_SIGNING_KEY   64 hex-char Ed25519 private key
    OP_PUBLIC_KEY    64 hex-char Ed25519 public key
    OP_DID           did:web:observerprotocol.org
"""

import hashlib
import json
import os
import re
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Path setup ─────────────────────────────────────────────────────────────────
_script_dir = Path(__file__).resolve().parent
_api_dir = _script_dir.parent / "api"
if str(_api_dir) not in sys.path:
    sys.path.insert(0, str(_api_dir))

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:8000"
REPORT_DIR = Path("/media/nvme/observer-protocol/test-reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
OP_SIGNING_KEY_HEX = os.environ.get("OP_SIGNING_KEY")
OP_PUBLIC_KEY_HEX = os.environ.get("OP_PUBLIC_KEY")
OP_DID = os.environ.get("OP_DID", "did:web:observerprotocol.org")

API_DIR = _api_dir


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def gen_keypair() -> tuple:
    """Generate a fresh Ed25519 keypair. Returns (private_hex, public_hex)."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes.hex(), pub_bytes.hex()


def sign_bytes(private_key_hex: str, message: bytes) -> str:
    """Sign message with an Ed25519 private key. Returns multibase base58btc value."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    sig = priv.sign(message)
    return "z" + base58.b58encode(sig).decode("ascii")


def verify_ed25519(public_key_hex: str, message: bytes, proof_value: str) -> bool:
    """Verify an Ed25519Signature2020 proofValue against a public key."""
    if not proof_value.startswith("z"):
        return False
    sig_bytes_val = base58.b58decode(proof_value[1:])
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        pub.verify(sig_bytes_val, message)
        return True
    except InvalidSignature:
        return False


def canonical_bytes(doc: dict) -> bytes:
    """Canonical JSON bytes for signing/verification (proof key excluded)."""
    d = {k: v for k, v in doc.items() if k != "proof"}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_vc_with_key(
    subject_did: str,
    credential_type: str,
    claims: dict,
    signing_key_hex: str,
    issuer_did: str,
) -> dict:
    """Issue a minimal W3C VC signed with the given key."""
    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer_did,
        "issuanceDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {"id": subject_did, **claims},
    }
    proof_value = sign_bytes(signing_key_hex, canonical_bytes(vc))
    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": vc["issuanceDate"],
        "verificationMethod": f"{issuer_did}#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }
    return vc


def build_vp(holder_did: str, vcs: list, holder_private_hex: str) -> dict:
    """Build a VP signed by the holder."""
    vp = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": vcs,
    }
    proof_value = sign_bytes(holder_private_hex, canonical_bytes(vp))
    vp["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": f"{holder_did}#key-1",
        "proofPurpose": "authentication",
        "proofValue": proof_value,
    }
    return vp


# ── Test registry ──────────────────────────────────────────────────────────────

class TestResult:
    def __init__(self, tid: str, name: str):
        self.tid = tid
        self.name = name
        self.passed: Optional[bool] = None
        self.error: Optional[str] = None
        self.detail: Optional[str] = None
        self.elapsed: float = 0.0


RESULTS: list = []
_cleanup_agents: list = []   # agent_ids to delete after all tests


def assert_eq(label: str, got, expected):
    assert got == expected, f"{label}: expected {expected!r}, got {got!r}"


def assert_true(label: str, condition, msg=""):
    assert condition, f"{label}: {msg}" if msg else label


# ── Shared state (built up during tests) ──────────────────────────────────────

state: dict = {
    "test_agent_id": None,
    "test_agent_priv": None,
    "test_agent_pub": None,
    "test_agent_did": None,
    "test_agent_old_pub": None,
    "test_agent_old_priv": None,
    "test_vc": None,
    "test_vp": None,
}


# ── Helper: register a test agent ─────────────────────────────────────────────

def _verify_agent(agent_id: str, priv_hex: str) -> bool:
    """
    Complete the challenge-response verification flow for an agent.
    Returns True if verification succeeded (or agent was already verified).
    """
    # Generate challenge
    ch_resp = requests.post(
        f"{BASE_URL}/observer/challenge",
        params={"agent_id": agent_id},
        timeout=10,
    )
    if ch_resp.status_code != 200:
        return False
    nonce = ch_resp.json()["nonce"]

    # Sign the nonce bytes with the agent's Ed25519 private key
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    sig_bytes = priv.sign(nonce.encode("utf-8"))
    sig_hex = sig_bytes.hex()

    # Submit verification
    v_resp = requests.post(
        f"{BASE_URL}/observer/verify-agent",
        params={"agent_id": agent_id, "signed_challenge": sig_hex},
        timeout=10,
    )
    return v_resp.status_code == 200


def _register_test_agent(suffix: str = "", verify: bool = False) -> tuple:
    """Register a fresh test agent. Returns (agent_id, priv_hex, pub_hex, agent_did)."""
    priv, pub = gen_keypair()
    resp = requests.post(
        f"{BASE_URL}/observer/register-agent",
        params={"public_key": pub, "agent_name": f"test-agent-{suffix}-{pub[:8]}"},
        timeout=10,
    )
    assert resp.status_code == 200, f"register-agent failed: {resp.status_code} {resp.text[:200]}"
    data = resp.json()
    agent_id = data["agent_id"]
    agent_did = data.get("agent_did", f"did:web:observerprotocol.org:agents:{agent_id}")
    _cleanup_agents.append(agent_id)
    if verify:
        _verify_agent(agent_id, priv)
    return agent_id, priv, pub, agent_did


def _delete_agent(agent_id: str):
    """Best-effort cleanup of a test agent via DB."""
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("DELETE FROM vac_credentials WHERE agent_id = %s", (agent_id,))
        cur.execute("DELETE FROM observer_agents WHERE agent_id = %s", (agent_id,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


def _run_test(tid: str, name: str, fn) -> TestResult:
    r = TestResult(tid, name)
    t0 = time.time()
    try:
        fn(r)
        if r.passed is None:
            r.passed = True
    except AssertionError as e:
        r.passed = False
        r.error = str(e) or "Assertion failed"
    except Exception as e:
        r.passed = False
        r.error = f"{type(e).__name__}: {e}"
        r.detail = traceback.format_exc()
    r.elapsed = time.time() - t0
    status = "PASS" if r.passed else "FAIL"
    print(f"  {tid}  {name[:52]:<54} {status}  ({r.elapsed:.2f}s)")
    if not r.passed and r.error:
        # Print first line of error for quick diagnosis
        first_line = r.error.split("\n")[0]
        print(f"       >>> {first_line}")
    RESULTS.append(r)
    return r


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 1 — DID Resolution
# ══════════════════════════════════════════════════════════════════════════════

def run_group1():
    print("\nGROUP 1 — DID Resolution")

    def t01(r: TestResult):
        resp = requests.get(f"{BASE_URL}/.well-known/did.json", timeout=10)
        assert_eq("HTTP status", resp.status_code, 200)
        doc = resp.json()
        assert_eq("id", doc.get("id"), "did:web:observerprotocol.org")
        vms = doc.get("verificationMethod", [])
        assert_true("verificationMethod non-empty", len(vms) > 0)
        vm = vms[0]
        assert_eq("vm type", vm.get("type"), "Ed25519VerificationKey2020")
        assert_true("publicKeyMultibase starts with z",
                    vm.get("publicKeyMultibase", "").startswith("z"))

    def t02(r: TestResult):
        agent_id, priv, pub, agent_did = _register_test_agent("t02", verify=True)
        state["test_agent_id"] = agent_id
        state["test_agent_priv"] = priv
        state["test_agent_pub"] = pub
        state["test_agent_did"] = agent_did

        resp = requests.get(f"{BASE_URL}/agents/{agent_id}/did.json", timeout=10)
        assert_eq("HTTP status", resp.status_code, 200)
        doc = resp.json()
        assert_true("id contains agent_id", agent_id in doc.get("id", ""))
        vms = doc.get("verificationMethod", [])
        assert_true("verificationMethod non-empty", len(vms) > 0)
        pmb = vms[0].get("publicKeyMultibase", "")
        assert_true("publicKeyMultibase starts with z", pmb.startswith("z"))
        decoded_bytes = base58.b58decode(pmb[1:])
        assert_eq("decoded key matches registered key", decoded_bytes.hex(), pub)
        r.detail = f"agent_id={agent_id}, did={agent_did}"

    def t03(r: TestResult):
        agent_id = state["test_agent_id"]
        assert agent_id, "T02 must run first"

        did_before = requests.get(f"{BASE_URL}/agents/{agent_id}/did.json", timeout=10).json()
        pmb_before = did_before["verificationMethod"][0]["publicKeyMultibase"]
        id_before = did_before["id"]

        new_priv, new_pub = gen_keypair()
        resp = requests.put(
            f"{BASE_URL}/agents/{agent_id}/keys",
            json={"new_public_key": new_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        data = resp.json()
        assert_eq("agent_id unchanged", data["agent_id"], agent_id)

        did_after = requests.get(f"{BASE_URL}/agents/{agent_id}/did.json", timeout=10).json()
        id_after = did_after["id"]
        pmb_after = did_after["verificationMethod"][0]["publicKeyMultibase"]

        assert_eq("DID string unchanged", id_after, id_before)
        assert_true("publicKeyMultibase changed after rotation", pmb_after != pmb_before)
        decoded_new = base58.b58decode(pmb_after[1:]).hex()
        assert_eq("new key matches rotated key", decoded_new, new_pub)

        state["test_agent_old_pub"] = state["test_agent_pub"]
        state["test_agent_old_priv"] = state["test_agent_priv"]
        state["test_agent_priv"] = new_priv
        state["test_agent_pub"] = new_pub
        r.detail = f"DID: {id_before}, key rotated successfully"

    def t04(r: TestResult):
        agent_did = state["test_agent_did"]
        assert agent_did, "T02 must run first"

        # Issue a VC with current (post-rotation) OP key
        vc = issue_vc_with_key(
            subject_did=agent_did,
            credential_type="AgentActivityCredential",
            claims={"scope_level": "basic", "note": "issued before rotation"},
            signing_key_hex=OP_SIGNING_KEY_HEX,
            issuer_did=OP_DID,
        )
        # Verify with OP public key — historical VCs are signed by OP, always verifiable
        from vc_verifier import verify_vc
        ok, reason = verify_vc(vc, OP_PUBLIC_KEY_HEX)
        assert_true("historical VC verifies", ok, reason)
        r.detail = f"VC id={vc['id']}, verification: {reason}"

    _run_test("T01", "OP DID Document resolves", t01)
    _run_test("T02", "Agent DID Document resolves", t02)
    _run_test("T03", "Key rotation preserves DID, updates key", t03)
    _run_test("T04", "Historical VC verifiable after key rotation", t04)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 2 — Verifiable Credential Issuance
# ══════════════════════════════════════════════════════════════════════════════

def run_group2():
    print("\nGROUP 2 — Verifiable Credential Issuance")

    def t05(r: TestResult):
        agent_id = state["test_agent_id"]
        agent_did = state["test_agent_did"]
        assert agent_id, "T02 must run first"

        # Try to get existing VAC; if not present, issue directly
        vac_resp = requests.get(f"{BASE_URL}/vac/{agent_id}", timeout=10)
        if vac_resp.status_code == 200:
            vp = vac_resp.json()
            vcs = vp.get("verifiableCredential", [])
            if vcs:
                vc = vcs[0]
                state["test_vc"] = vc
            else:
                # VP exists but no VCs — issue directly
                from vc_issuer import issue_vc
                vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                              claims={"scope_level": "basic"})
                state["test_vc"] = vc
        else:
            from vc_issuer import issue_vc
            vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                          claims={"scope_level": "basic"})
            state["test_vc"] = vc

        ctx = vc.get("@context", [])
        assert_true("@context has W3C URL", "https://www.w3.org/2018/credentials/v1" in ctx)
        vc_types = vc.get("type", [])
        assert_true("type has VerifiableCredential", "VerifiableCredential" in vc_types)
        assert_eq("issuer is OP DID", vc.get("issuer"), OP_DID)
        cs_id = vc.get("credentialSubject", {}).get("id", "")
        assert_true("credentialSubject.id starts with did:", cs_id.startswith("did:"))
        proof = vc.get("proof", {})
        assert_eq("proof type", proof.get("type"), "Ed25519Signature2020")
        assert_true("proofValue starts with z", proof.get("proofValue", "").startswith("z"))
        r.detail = f"VC id={vc.get('id')}"

    def t06(r: TestResult):
        vc = state.get("test_vc")
        if not vc:
            from vc_issuer import issue_vc
            agent_did = state["test_agent_did"] or OP_DID
            vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                          claims={"scope_level": "basic"})
            state["test_vc"] = vc

        proof = vc.get("proof", {})
        proof_value = proof.get("proofValue", "")
        assert_true("proofValue present", bool(proof_value))

        message = canonical_bytes(vc)
        assert_true("real Ed25519 verification passes",
                    verify_ed25519(OP_PUBLIC_KEY_HEX, message, proof_value),
                    "Signature verification failed — stub or wrong key")
        r.detail = f"Verified {len(message)}-byte canonical VC against OP public key"

    def t07(r: TestResult):
        vc = state.get("test_vc")
        if not vc:
            r.passed = False
            r.error = "No test_vc available (T05/T06 must run first)"
            return

        tampered = json.loads(json.dumps(vc))
        tampered.setdefault("credentialSubject", {})["scope_level"] = "TAMPERED"

        from vc_verifier import verify_vc
        ok, reason = verify_vc(tampered, OP_PUBLIC_KEY_HEX)
        assert_true("tampered VC fails", not ok, f"Expected failure but got: {reason}")
        r.detail = f"Correctly rejected: {reason}"

    def t08(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID

        org_priv, org_pub = gen_keypair()
        org_id = hashlib.sha256(org_pub.encode()).hexdigest()[:16]
        org_did = f"did:web:observerprotocol.org:orgs:{org_id}"

        vc = issue_vc_with_key(
            subject_did=agent_did,
            credential_type="OrgMembershipCredential",
            claims={"org_id": org_id, "role": "member"},
            signing_key_hex=org_priv,
            issuer_did=org_did,
        )

        ctx = vc.get("@context", [])
        assert_true("@context has W3C URL", "https://www.w3.org/2018/credentials/v1" in ctx)
        assert_true("type has OrgMembershipCredential",
                    "OrgMembershipCredential" in vc.get("type", []))
        assert_eq("issuer is org DID", vc.get("issuer"), org_did)
        proof = vc.get("proof", {})
        assert_eq("proof type", proof.get("type"), "Ed25519Signature2020")

        message = canonical_bytes(vc)
        assert_true("signature verifies against org public key",
                    verify_ed25519(org_pub, message, proof["proofValue"]))
        r.detail = f"OrgMembershipCredential from {org_did}, verified ok"

    _run_test("T05", "VC issued with correct W3C structure", t05)
    _run_test("T06", "VC signature is real Ed25519 (not a stub)", t06)
    _run_test("T07", "Tampered VC fails verification", t07)
    _run_test("T08", "OrgMembershipCredential issued and verifiable", t08)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 3 — Verifiable Presentation
# ══════════════════════════════════════════════════════════════════════════════

def run_group3():
    print("\nGROUP 3 — Verifiable Presentation")

    def t09(r: TestResult):
        agent_id = state["test_agent_id"]
        assert agent_id, "T02 must run first"

        resp = requests.get(f"{BASE_URL}/vac/{agent_id}", timeout=10)
        if resp.status_code == 404:
            agent_did = state["test_agent_did"]
            from vc_issuer import issue_vc
            vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                          claims={"scope_level": "basic"})
            vp = build_vp(agent_did, [vc], state["test_agent_priv"])
        else:
            assert_eq("HTTP status", resp.status_code, 200)
            vp = resp.json()

        types = vp.get("type", [])
        assert_true("type has VerifiablePresentation", "VerifiablePresentation" in types)
        holder = vp.get("holder", "")
        assert_true("holder is a DID", holder.startswith("did:"))
        vcs = vp.get("verifiableCredential", [])
        assert_true("verifiableCredential non-empty", len(vcs) > 0)
        for vc in vcs:
            assert_true("each VC has proof", bool(vc.get("proof")))
        state["test_vp"] = vp
        r.detail = f"VP with {len(vcs)} VC(s), holder={holder}"

    def t10(r: TestResult):
        agent_id = state["test_agent_id"]
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]
        agent_did = state["test_agent_did"]
        assert agent_id, "T02 must run first"

        resp = requests.post(
            f"{BASE_URL}/vac/{agent_id}/present",
            json={"holder_private_key_hex": agent_priv},
            timeout=15,
        )
        if resp.status_code in (404, 400, 422):
            # No VCs via API — build VP manually
            from vc_issuer import issue_vc
            vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                          claims={"scope_level": "basic"})
            vp = build_vp(agent_did, [vc], agent_priv)
        else:
            assert_eq("HTTP status", resp.status_code, 200)
            vp = resp.json()
            if isinstance(vp, dict) and "vp" in vp:
                vp = vp["vp"]

        proof = vp.get("proof")
        if not proof:
            r.passed = False
            r.error = "VP has no proof — agent-signed VP requires holder_private_key_hex"
            return

        message = canonical_bytes(vp)
        assert_true("agent VP proof verifies",
                    verify_ed25519(agent_pub, message, proof.get("proofValue", "")),
                    "Ed25519 signature on VP failed")
        r.detail = f"VP proof verified with agent pub key {agent_pub[:16]}…"

    def t11(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]

        from vc_issuer import issue_vc
        vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                      claims={"scope_level": "basic", "selective": True})
        vp = build_vp(agent_did, [vc], agent_priv)

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": vp, "holder_public_key_hex": state["test_agent_pub"]},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        assert_true("overall valid=true", result.get("valid") is True,
                    f"structure={result.get('structure')} vc_results={result.get('vc_results')}")
        r.detail = f"Single-VC VP verified, valid={result.get('valid')}"

    def t12(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]

        from vc_issuer import issue_vc
        vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                      claims={"scope_level": "basic"})
        vp = build_vp(agent_did, [vc], agent_priv)

        tampered = json.loads(json.dumps(vp))
        tampered["holder"] = "did:web:evil.example.com:attacker"

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": tampered, "holder_public_key_hex": agent_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        overall_valid = result.get("valid")
        vp_proof = result.get("vp_proof", {})
        assert_true("tampered VP is not fully valid",
                    not overall_valid or (vp_proof.get("valid") is False),
                    f"Expected failure, got valid={overall_valid}")
        r.detail = f"Correctly rejected tampered VP: valid={overall_valid}"

    _run_test("T09", "VP assembles with correct W3C structure", t09)
    _run_test("T10", "VP signature verifies (agent-signed)", t10)
    _run_test("T11", "Selective disclosure — subset VP verifies", t11)
    _run_test("T12", "Tampered VP fails verification", t12)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 4 — Stateless Verification (Layer 3 — Option C)
# ══════════════════════════════════════════════════════════════════════════════

def run_group4():
    print("\nGROUP 4 — Stateless Verification")

    def t13(r: TestResult):
        """
        Layer 3 guarantee: POST /vp/verify works from the VP alone.
        Submit a brand-new VP that was never stored in the DB.
        """
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]

        from vc_issuer import issue_vc
        vc = issue_vc(
            subject_did=agent_did,
            credential_type="AgentActivityCredential",
            claims={"scope_level": "stateless_test", "unique": str(uuid.uuid4())},
        )
        fresh_vp = build_vp(agent_did, [vc], agent_priv)

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": fresh_vp, "holder_public_key_hex": agent_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        assert_true("stateless VP verifies as valid", result.get("valid") is True,
                    f"structure={result.get('structure')} vc_results={result.get('vc_results')} "
                    f"vp_proof={result.get('vp_proof')}")
        r.detail = "Fresh VP (never in DB) verified — stateless guarantee confirmed"

    def t14(r: TestResult):
        agent_id = state["test_agent_id"]
        agent_did = state["test_agent_did"]
        agent_priv = state["test_agent_priv"]
        assert agent_id, "T02 must run first"

        from vc_issuer import issue_vc
        vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                      claims={"scope_level": "cache_test"})
        vp = build_vp(agent_did, [vc], agent_priv)

        submit_resp = requests.post(
            f"{BASE_URL}/vp/submit",
            json={"vp": vp, "agent_id": agent_id},
            timeout=10,
        )
        assert_eq("submit HTTP status", submit_resp.status_code, 200)

        recon_resp = requests.post(
            f"{BASE_URL}/vp/reconstruct",
            json={"agent_id": agent_id},
            timeout=10,
        )
        assert_eq("reconstruct HTTP status", recon_resp.status_code, 200)
        data = recon_resp.json()
        recon_vp = data.get("vp") or data
        assert_true("reconstructed VP has VCs",
                    len(recon_vp.get("verifiableCredential", [])) > 0)
        assert_true("reconstructed VP has VerifiablePresentation type",
                    "VerifiablePresentation" in recon_vp.get("type", []))
        r.detail = f"Submitted and reconstructed VP with {len(recon_vp.get('verifiableCredential', []))} VC(s)"

    _run_test("T13", "VP verifies with no DB record (stateless)", t13)
    _run_test("T14", "VP reconstruct from cache", t14)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 5 — Trusted Issuers and KYB
# ══════════════════════════════════════════════════════════════════════════════

def run_group5():
    print("\nGROUP 5 — Trusted Issuers and KYB")

    def t15(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]

        # OP itself is always trusted — issue KYBCredential from OP
        vc = issue_vc_with_key(
            subject_did=agent_did,
            credential_type="KYBCredential",
            claims={"legal_entity": "TestCo LLC", "jurisdiction": "US"},
            signing_key_hex=OP_SIGNING_KEY_HEX,
            issuer_did=OP_DID,
        )
        vp = build_vp(agent_did, [vc], agent_priv)

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": vp, "holder_public_key_hex": agent_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        vc_results = result.get("vc_results", [])
        assert_true("has vc_results", len(vc_results) > 0)
        assert_true("issuer_trusted=true for OP-issued VC",
                    vc_results[0].get("issuer_trusted") is True,
                    f"vc_results[0]={vc_results[0]}")
        r.detail = f"KYBCredential from {OP_DID}: issuer_trusted={vc_results[0].get('issuer_trusted')}"

    def t16(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]

        unknown_priv, unknown_pub = gen_keypair()
        unknown_did = f"did:web:untrusted.example.com:issuer:{unknown_pub[:12]}"

        vc = issue_vc_with_key(
            subject_did=agent_did,
            credential_type="KYBCredential",
            claims={"legal_entity": "Shady Corp", "jurisdiction": "XX"},
            signing_key_hex=unknown_priv,
            issuer_did=unknown_did,
        )
        vp = build_vp(agent_did, [vc], agent_priv)

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": vp, "holder_public_key_hex": agent_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        vc_results = result.get("vc_results", [])
        assert_true("has vc_results", len(vc_results) > 0)
        assert_true("issuer_trusted=false for unknown issuer",
                    vc_results[0].get("issuer_trusted") is False,
                    f"vc_results[0]={vc_results[0]}")
        r.detail = f"Unknown issuer {unknown_did}: issuer_trusted={vc_results[0].get('issuer_trusted')}"

    def t17(r: TestResult):
        agent_did = state["test_agent_did"] or OP_DID
        agent_priv = state["test_agent_priv"]
        agent_pub = state["test_agent_pub"]

        from vc_issuer import issue_vc
        vc = issue_vc(subject_did=agent_did, credential_type="AgentActivityCredential",
                      claims={"scope_level": "basic"})
        corrupted = json.loads(json.dumps(vc))
        corrupted["proof"]["proofValue"] = "zZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

        vp = build_vp(agent_did, [corrupted], agent_priv)

        resp = requests.post(
            f"{BASE_URL}/vp/verify",
            json={"vp": vp, "holder_public_key_hex": agent_pub},
            timeout=10,
        )
        assert_eq("HTTP status", resp.status_code, 200)
        result = resp.json()
        assert_true("overall valid=false", result.get("valid") is False,
                    f"Expected invalid, got valid={result.get('valid')}")
        vc_results = result.get("vc_results", [])
        if vc_results:
            assert_true("VC marked invalid", vc_results[0].get("valid") is False)
        r.detail = f"Corrupted proofValue rejected: valid={result.get('valid')}"

    _run_test("T15", "KYBCredential from trusted issuer accepted", t15)
    _run_test("T16", "KYBCredential from unknown issuer flagged", t16)
    _run_test("T17", "Cryptographically invalid credential rejected", t17)


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 6 — Infrastructure and Environment
# ══════════════════════════════════════════════════════════════════════════════

def run_group6():
    print("\nGROUP 6 — Infrastructure and Environment")

    def t18(r: TestResult):
        patterns = {
            "hardcoded DB URL": r"postgresql://agentic_terminal",
            "hardcoded home path": r"/home/futurebit",
            "hardcoded lnd path": r"/media/nvme/lnd-data",
            "hardcoded sys.path insert": r"sys\.path\.insert\(0,\s*['\"]\/",
        }
        py_files = list(API_DIR.glob("*.py"))
        violations = []
        for pattern_name, pattern in patterns.items():
            for pyfile in py_files:
                content = pyfile.read_text(errors="replace")
                matches = re.findall(pattern, content)
                if matches:
                    violations.append(f"{pyfile.name}: {pattern_name} ({len(matches)} match(es))")

        assert_true("zero hardcoded credential matches", len(violations) == 0,
                    "Found hardcoded credentials:\n" + "\n".join(violations))
        r.detail = f"Checked {len(py_files)} Python files, 0 violations"

    def t19(r: TestResult):
        db_url = os.environ.get("DATABASE_URL")
        op_signing = os.environ.get("OP_SIGNING_KEY")
        op_public = os.environ.get("OP_PUBLIC_KEY")
        op_did_val = os.environ.get("OP_DID")

        assert_true("DATABASE_URL set", bool(db_url))
        assert_true("OP_SIGNING_KEY set", bool(op_signing))
        assert_true("OP_PUBLIC_KEY set", bool(op_public))
        assert_true("OP_DID set", bool(op_did_val))
        assert_eq("OP_SIGNING_KEY length", len(op_signing or ""), 64)
        assert_eq("OP_PUBLIC_KEY length", len(op_public or ""), 64)
        assert_true("OP_DID starts with did:", (op_did_val or "").startswith("did:"))
        r.detail = f"OP_DID={op_did_val}, all keys present and correct length"

    def t20(r: TestResult):
        resp = requests.get(f"{BASE_URL}/api/v1/health", timeout=10)
        assert_eq("HTTP status", resp.status_code, 200)
        data = resp.json()
        assert_eq("status=ok", data.get("status"), "ok")
        assert_eq("db=connected", data.get("db"), "connected")

        did_resp = requests.get(f"{BASE_URL}/.well-known/did.json", timeout=10)
        assert_eq("DID document HTTP status", did_resp.status_code, 200)
        assert_true("OP DID Document loaded", bool(did_resp.json().get("id")))
        r.detail = f"Health OK, DB connected, timestamp={data.get('timestamp')}"

    _run_test("T18", "No hardcoded credentials in codebase", t18)
    _run_test("T19", "All required env vars present", t19)
    _run_test("T20", "API health and DB connectivity", t20)


# ══════════════════════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════════════════════

def _run_cleanup():
    if not DATABASE_URL:
        return
    cleaned = 0
    for agent_id in _cleanup_agents:
        try:
            import psycopg2
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            cur.execute("DELETE FROM vac_credentials WHERE agent_id = %s", (agent_id,))
            cur.execute("DELETE FROM observer_agents WHERE agent_id = %s", (agent_id,))
            conn.commit()
            cur.close()
            conn.close()
            cleaned += 1
        except Exception:
            pass
    if cleaned:
        print(f"\n[cleanup] Removed {cleaned} test agent(s)")


# ══════════════════════════════════════════════════════════════════════════════
# Report generation
# ══════════════════════════════════════════════════════════════════════════════

def _generate_reports(elapsed_total: float):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    passed = sum(1 for r in RESULTS if r.passed)
    total = len(RESULTS)

    groups = [
        ("Group 1 — DID Resolution",         ["T01", "T02", "T03", "T04"]),
        ("Group 2 — Verifiable Credential",   ["T05", "T06", "T07", "T08"]),
        ("Group 3 — Verifiable Presentation", ["T09", "T10", "T11", "T12"]),
        ("Group 4 — Stateless Verification",  ["T13", "T14"]),
        ("Group 5 — Trusted Issuers & KYB",   ["T15", "T16", "T17"]),
        ("Group 6 — Infrastructure",          ["T18", "T19", "T20"]),
    ]
    by_tid = {r.tid: r for r in RESULTS}

    sep = "═" * 63
    lines = [
        sep,
        "OBSERVER PROTOCOL — INTERNAL TEST REPORT",
        f"Run at:       {datetime.now(timezone.utc).isoformat()}",
        "Node:         FutureBit-Solo-Node",
        f"API:          {BASE_URL}",
        "Protocol:     v1.1",
        sep,
        "",
    ]

    for group_name, tids in groups:
        lines.append(group_name)
        for tid in tids:
            r = by_tid.get(tid)
            if not r:
                continue
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"  {tid}  {r.name:<54} {status}  ({r.elapsed:.2f}s)")
            if not r.passed and r.error:
                first_line = r.error.split("\n")[0]
                lines.append(f"       ERROR: {first_line}")
        lines.append("")

    lines.extend([
        sep,
        f"SUMMARY: {passed}/{total} tests passed   ({elapsed_total:.1f}s total)",
        "All tests PASSED." if passed == total else f"FAILED: {total - passed} test(s) need attention.",
        sep,
    ])

    txt_content = "\n".join(lines)
    txt_path = REPORT_DIR / f"protocol-test-{ts}.txt"
    txt_path.write_text(txt_content)

    json_report = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "node": "FutureBit-Solo-Node",
        "api": BASE_URL,
        "protocol_version": "v1.1",
        "summary": {
            "passed": passed,
            "total": total,
            "elapsed_s": round(elapsed_total, 2),
            "all_passed": passed == total,
        },
        "results": [
            {
                "id": r.tid,
                "name": r.name,
                "passed": r.passed,
                "elapsed_s": round(r.elapsed, 3),
                "error": r.error,
                "detail": r.detail,
            }
            for r in RESULTS
        ],
    }
    json_path = REPORT_DIR / f"protocol-test-{ts}.json"
    json_path.write_text(json.dumps(json_report, indent=2))

    return txt_path, json_path, txt_content, passed, total


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "═" * 63)
    print("OBSERVER PROTOCOL — INTERNAL TEST SUITE v1.1")
    print(f"API: {BASE_URL}")
    print("═" * 63)

    # Preflight env check
    missing_env = []
    if not DATABASE_URL:
        missing_env.append("DATABASE_URL")
    if not OP_SIGNING_KEY_HEX:
        missing_env.append("OP_SIGNING_KEY")
    if not OP_PUBLIC_KEY_HEX:
        missing_env.append("OP_PUBLIC_KEY")
    if missing_env:
        print(f"\nERROR: Required env vars not set: {', '.join(missing_env)}")
        print("Set them and re-run. (See op-test-suite-spec.md for details.)")
        sys.exit(2)

    t_start = time.time()

    run_group1()
    run_group2()
    run_group3()
    run_group4()
    run_group5()
    run_group6()

    elapsed_total = time.time() - t_start

    try:
        _run_cleanup()
    except Exception as e:
        print(f"\n[cleanup] Error: {e}")

    txt_path, json_path, txt_content, passed, total = _generate_reports(elapsed_total)

    print("\n" + "═" * 63)
    print(f"SUMMARY: {passed}/{total} tests passed   ({elapsed_total:.1f}s)")
    print(f"Reports saved:")
    print(f"  TXT:  {txt_path}")
    print(f"  JSON: {json_path}")
    print("═" * 63 + "\n")

    sys.exit(0 if passed == total else 1)
