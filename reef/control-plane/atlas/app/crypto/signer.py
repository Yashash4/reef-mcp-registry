"""ed25519 key generation and signing.

We sign over a canonical JSON serialisation of the manifest — sorted keys,
compact separators, UTF-8 — so signers and verifiers produce identical byte
sequences regardless of the order keys were written in upstream.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(payload: Any) -> bytes:
    """Return a deterministic byte serialisation suitable for signing.

    JSON with sorted keys + compact separators + no ASCII escaping for non-ASCII
    characters. Mirrors the convention used by Sigstore + JWS-RFC8785 for
    canonical signing payloads.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def fingerprint(public_key_hex: str) -> str:
    """Return the first 16 hex chars of sha256(pubkey) as a short fingerprint.

    Used in log lines so operators can recognise a publisher at a glance.
    """
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh ed25519 keypair.

    Returns ``(private_key_hex, public_key_hex)``, both as 64-char (32-byte) hex
    strings. The private key bytes are the raw seed, never the PEM/DER blob —
    keep this in a directory secured by filesystem permissions (the demo seed
    writes to ``REEF_ATLAS_PUBLISHER_KEYS_DIR``, gitignored).
    """
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk_bytes.hex(), pk_bytes.hex()


def sign_manifest(manifest_dict: dict[str, Any], private_key_hex: str) -> str:
    """Sign a manifest dict with ed25519.

    Returns the hex-encoded signature. ``manifest_dict`` MUST be a serialisable
    Python dict matching the ``Manifest`` schema; callers commonly pass
    ``manifest.model_dump(mode='json')``.
    """
    sk_bytes = bytes.fromhex(private_key_hex)
    if len(sk_bytes) != 32:
        raise ValueError(
            f"ed25519 private key must be 32 raw bytes (got {len(sk_bytes)})"
        )
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    sig = sk.sign(canonical_json(manifest_dict))
    return sig.hex()


def load_public_key(public_key_hex: str) -> Ed25519PublicKey:
    """Build an Ed25519PublicKey from a 32-byte hex pubkey."""
    pk_bytes = bytes.fromhex(public_key_hex)
    if len(pk_bytes) != 32:
        raise ValueError(
            f"ed25519 public key must be 32 raw bytes (got {len(pk_bytes)})"
        )
    return Ed25519PublicKey.from_public_bytes(pk_bytes)
