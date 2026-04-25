"""
StacksAdapter — Stacks chain verification stub.

Interface defined per CHAIN-ADAPTER-SPEC.md. Returns clear
"not yet implemented" error. Ready for AIBTC integration
when BD progresses.

Do not tell AIBTC "we support Stacks" before this adapter is real.
See MIGRATION-MAP.md § AIBTC engagement contingency.
"""

from chain_adapter import ChainAdapter, ChainVerificationResult, register_adapter


class StacksAdapter(ChainAdapter):

    @property
    def chain(self) -> str:
        return "stacks"

    def verify_transaction(self, transaction: dict, chain_specific: dict) -> ChainVerificationResult:
        """
        Stub: Stacks transaction verification not yet implemented.

        When implemented, will:
        - Query Hiro Stacks API for tx status
        - Verify block confirmations
        - For contract calls: verify function_name and post_conditions_met
        - Support AIBTC Clarity contract verification
        """
        return ChainVerificationResult(
            verified=False,
            chain="stacks",
            error=(
                "Stacks chain verification is not yet implemented. "
                "The adapter interface is defined and ready for integration. "
                "Contact the OP team to discuss Stacks integration timeline."
            ),
            chain_specific={
                "tx_id": chain_specific.get("tx_id"),
                "status": "adapter_not_implemented",
            },
        )

    def get_explorer_url(self, transaction_reference: str) -> str:
        return f"https://explorer.stacks.co/txid/{transaction_reference}"

    def to_vac_extension(self, result: ChainVerificationResult) -> dict:
        return {
            "type": "stacks_verification_v1",
            "chain": "stacks",
            "receiptId": result.transaction_reference,
            "verified": result.verified,
            "transactionReference": result.transaction_reference,
            "timestamp": result.confirmed_at,
            "chain_specific": result.chain_specific,
        }


register_adapter(StacksAdapter())
