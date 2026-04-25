"""
LightningPaymentReceipt — W3C VC 2.0 schema for payee-issued payment attestation.

This is the Tier 1 verification credential: the payee signs a VC attesting
that a specific payment was received. See CHAIN-ADAPTER-SPEC.md.

Protocol-layer credential. Re-homed from sandbox to OP proper.
"""

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class LightningPayment(BaseModel):
    """The payment details attested by the payee."""
    payment_hash: str = Field(..., min_length=64, max_length=64)
    preimage: str = Field(..., min_length=64, max_length=64)
    amount_msat: int = Field(..., ge=0)
    currency: str = Field(default="BTC")
    bolt11_invoice: Optional[str] = None
    settled_at: str
    payee_node_pubkey: Optional[str] = None
    description: Optional[str] = None

    @field_validator("payment_hash", "preimage")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError(f"Must be hex-encoded, got '{v[:20]}...'")
        return v.lower()


class LightningReceiptSubject(BaseModel):
    """credentialSubject — payer is the subject (attested about)."""
    id: str = Field(..., description="Payer agent DID")
    payment: LightningPayment


class LightningReceiptProof(BaseModel):
    type: str = "Ed25519Signature2020"
    created: str
    verificationMethod: str
    proofPurpose: str = "assertionMethod"
    proofValue: str


class LightningPaymentReceiptVC(BaseModel):
    """
    Full W3C VC 2.0 LightningPaymentReceipt.

    Issuer = payee (confirms receipt).
    Subject = payer (attested about).
    """
    context: List[str] = Field(
        alias="@context",
        default=[
            "https://www.w3.org/ns/credentials/v2",
            "https://observerprotocol.org/contexts/lightning-payment-receipt/v1",
        ],
    )
    type: List[str] = Field(
        default=["VerifiableCredential", "LightningPaymentReceipt"]
    )
    id: str
    issuer: str  # Payee DID
    validFrom: str
    credentialSubject: LightningReceiptSubject
    proof: Optional[LightningReceiptProof] = None

    model_config = {"populate_by_name": True}

    @field_validator("type")
    @classmethod
    def validate_type(cls, v):
        if "LightningPaymentReceipt" not in v:
            raise ValueError("type must include 'LightningPaymentReceipt'")
        if "VerifiableCredential" not in v:
            raise ValueError("type must include 'VerifiableCredential'")
        return v


def validate_lightning_receipt(credential: dict) -> tuple:
    """
    Validate a LightningPaymentReceipt credential against the schema.

    Returns:
        (valid: bool, error: str | None, parsed: LightningPaymentReceiptVC | None)
    """
    try:
        parsed = LightningPaymentReceiptVC.model_validate(credential)
        return True, None, parsed
    except Exception as e:
        return False, str(e), None
