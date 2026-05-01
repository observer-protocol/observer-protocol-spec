# Observer Protocol x LightningProx

Adds verifiable agent identity to every LightningProx inference call. Zero changes required on LightningProx's side.

## What it does

Before each `ask_ai` call, generates a signed Ed25519 attestation proving which agent is making the request. The attestation travels as a custom header that LightningProx ignores. The audit trail lives locally.

## Run

```bash
pip install httpx cryptography
export LIGHTNINGPROX_TOKEN="your_spend_token"
python demo.py "What is Bitcoin?"
```

## What you see

1. Agent DID loaded (resolvable at observerprotocol.org)
2. Attestation signed with Ed25519
3. LightningProx call made with attestation header
4. Audit log entry saved to `audit_log.jsonl`

## The pitch

"We built a working agent-identity layer on top of your API in 2 hours. Zero changes required on your end. Here's the audit trail. Here's what it would look like as a feature."

## Files

- `demo.py` — single-file demo (~170 lines)
- `audit_log.jsonl` — generated on first run
