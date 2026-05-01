# Observer Protocol x AIProx

Adds cryptographic agent identity to AIProx's multi-rail agent registry. Zero changes required on AIProx's side.

AIProx has 26+ agents across Lightning, Solana USDC, and x402 rails with a `verified: true` flag that has no cryptographic backing. OP adds W3C DID identity, Ed25519 attestations, and a verifiable audit trail.

## Run

```bash
pip install httpx cryptography

# Show registry with OP identity overlay
python demo.py

# Make an OP-attested call to an AIProx agent
export AIPROX_SPEND_TOKEN="lnpx_..."
python demo.py --call search-bot "latest Bitcoin news"

# Show what OP-verified registration looks like
python demo.py --register my-agent
```

## The pitch

"AIProx is an agent registry with no identity layer. We built one on top of it in 2 hours. Zero changes on your end. Same demo, three rails: Lightning, Solana USDC, x402. Here's the audit trail."

## Files

- `demo.py` — single-file demo, three modes (registry, call, register)
- `audit_log.jsonl` — generated on verified calls
