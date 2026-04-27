# Observer Protocol — Examples

Working code examples demonstrating the Observer Protocol SDK.

## Prerequisites

```bash
pip install observer-protocol
```

## Examples

### Register an agent (60 seconds)

```bash
python register_agent.py
```

Generates a keypair, registers an agent on OP, proves key ownership, retrieves the VAC and trust score. Your agent gets a public profile immediately.

### Verify a Lightning payment

```bash
export OP_API_KEY="your_api_key"
python verify_lightning.py
```

Verifies a Lightning payment through OP's three-tier verification model. Requires an API key — email [dev@observerprotocol.org](mailto:dev@observerprotocol.org) to get one.

## What happens when you run these

- **`register_agent.py`** — Your agent is registered on the live Observer Protocol API. It gets a W3C DID, a public profile page, and a Verified Agent Credential. Real infrastructure, not a simulation.

- **`verify_lightning.py`** — A Lightning payment is verified against OP's chain verification endpoint. The verification result becomes part of the agent's trust history.

## Next steps

- [Developer Guide](../docs/developer-guide/)
- [API Reference](../docs/developer-guide/api-reference.md)
- [SDK Reference (Python)](../sdk/python/)
- [SDK Reference (JavaScript)](../sdk/javascript/)
