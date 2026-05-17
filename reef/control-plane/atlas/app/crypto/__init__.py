"""ed25519 sign + verify primitives for the Atlas registry."""

from app.crypto.signer import (
    canonical_json,
    fingerprint,
    generate_keypair,
    sign_manifest,
)
from app.crypto.verifier import verify_manifest_signature

__all__ = [
    "canonical_json",
    "fingerprint",
    "generate_keypair",
    "sign_manifest",
    "verify_manifest_signature",
]
