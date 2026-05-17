"""ed25519 signature verification."""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature

from app.crypto.signer import canonical_json, load_public_key


def verify_manifest_signature(
    manifest_dict: dict[str, Any],
    signature_hex: str,
    public_key_hex: str,
) -> bool:
    """Verify an ed25519 signature over canonical-JSON(manifest_dict).

    Returns ``True`` on a good signature; ``False`` on any kind of mismatch
    (bad signature bytes, wrong key, payload tampering). Never raises — the
    caller cares only about the boolean verdict.
    """
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        pk = load_public_key(public_key_hex)
    except ValueError:
        return False
    try:
        pk.verify(sig_bytes, canonical_json(manifest_dict))
    except InvalidSignature:
        return False
    except Exception:
        # Any other crypto-layer surprise = treat as verification failure;
        # the caller's audit log will note the registry_id + publisher_id.
        return False
    return True
