#!/usr/bin/env python3
"""
Observer Protocol — Verify a Lightning Payment

Demonstrates verifying a Lightning payment through OP's
three-tier verification model.

Requires an API key (get one at dev@observerprotocol.org).

Run:
    pip install observer-protocol
    python verify_lightning.py
"""

import hashlib
import os

from observer_protocol import ObserverClient


def main():
    api_key = os.environ.get("OP_API_KEY")
    if not api_key:
        print("Set OP_API_KEY environment variable first.")
        print("Get one at: dev@observerprotocol.org")
        return

    client = ObserverClient(api_key=api_key)

    # ── Example: Payee verifying they received a payment ──────
    # In a real scenario, the preimage comes from your Lightning
    # node after the invoice settles.

    preimage = "deadbeefcafebabe" * 4  # 32 bytes hex — replace with real preimage
    payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

    print("Verifying Lightning payment...")
    print(f"  Payment hash: {payment_hash[:32]}...")
    print(f"  Preimage:     {preimage[:32]}...")
    print(f"  Role:         payee (proving I received payment)")
    print()

    result = client.verify_lightning_payment(
        receipt_reference=f"urn:uuid:example-{payment_hash[:8]}",
        payment_hash=payment_hash,
        preimage=preimage,
        presenter_role="payee",
    )

    print(f"  Verified: {result.verified}")
    print(f"  Chain: {result.chain}")
    print(f"  Tier: {result.chain_specific.get('verification_tier')}")

    if result.verified:
        print(f"  Reference: {result.transaction_reference[:32]}...")
        print()
        print("Payment verified on Observer Protocol.")
        print("This verification is now part of the agent's trust history.")
    else:
        print(f"  Error: {result.error}")


if __name__ == "__main__":
    main()
