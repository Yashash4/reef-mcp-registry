"""ed25519 bundle signature verification + publisher allowlist.

Wire contract (matches `pkg/policysync/cosign.go` in the Go Lobster Trap fork):

    signature = ed25519.Sign(priv, SHA-256(bundle_yaml))

Signatures may arrive as raw 64 bytes OR base64-encoded. Both shapes are
accepted because operators frequently copy through Slack / GitHub and the
bytes get re-encoded. See `decode_signature` for the canonicalisation.

The publisher allowlist lives in `REEF_POLICY_BUS_PUBLISHER_KEYS_DIR`. Each
`*.pub` / `*.pem` / `*.hex` file contributes one trusted key. The file's
basename (sans extension) becomes the `key_id` — bundles must declare a
matching `signer_key_id` to be accepted.

We mirror Atlas's `app/crypto/signer.py` patterns deliberately so the two
control-plane services share the same operator workflow.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# Public sentinels for tests + audit grep.
class BundleVerifyError(Exception):
    """Base class for verification failures."""


class UnknownPublisher(BundleVerifyError):
    """The bundle's signer_key_id is not in the publisher allowlist."""


class SignatureMismatch(BundleVerifyError):
    """The signature does not verify against the publisher's key."""


@dataclass(frozen=True)
class Publisher:
    """One trusted bundle publisher."""

    key_id: str
    public_key: Ed25519PublicKey
    public_key_bytes: bytes  # raw 32-byte form
    source_path: str

    @property
    def fingerprint(self) -> str:
        """Short hex digest for log lines (first 16 hex chars of sha256)."""
        return hashlib.sha256(self.public_key_bytes).hexdigest()[:16]


class PublisherAllowlist:
    """File-backed publisher allowlist.

    Loaded once at construction time. Reload is a fresh construct — the
    bus's admin REST surface exposes /publishers POST for dynamic adds
    (Phase 2) but v1 reads from disk on boot.
    """

    def __init__(self, keys_dir: str | os.PathLike[str]) -> None:
        self._keys_dir = Path(keys_dir).resolve()
        self._by_key_id: dict[str, Publisher] = {}
        if self._keys_dir.exists():
            self._load_dir()

    def _load_dir(self) -> None:
        for entry in sorted(self._keys_dir.iterdir()):
            if entry.is_dir():
                continue
            suffix = entry.suffix.lower()
            if suffix not in {".pub", ".pem", ".hex", ".key", ".b64"}:
                continue
            try:
                pub = self._load_one(entry)
            except ValueError as e:
                # Surface bad keys structurally rather than silently dropping
                # — operators need to know if a publisher file is broken.
                raise RuntimeError(
                    f"publisher allowlist: failed to load {entry.name}: {e}"
                ) from e
            self._by_key_id[pub.key_id] = pub

    @staticmethod
    def _load_one(path: Path) -> Publisher:
        data = path.read_bytes()
        key_id = path.stem  # "publisher-prod" from "publisher-prod.pub"
        public_key, raw = _parse_public_key(data)
        return Publisher(
            key_id=key_id,
            public_key=public_key,
            public_key_bytes=raw,
            source_path=str(path),
        )

    # ---- Public API ------------------------------------------------------

    def get(self, key_id: str) -> Publisher | None:
        return self._by_key_id.get(key_id)

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._by_key_id

    def __len__(self) -> int:
        return len(self._by_key_id)

    def list_key_ids(self) -> list[str]:
        return sorted(self._by_key_id.keys())

    def add(self, key_id: str, public_key_b64: str) -> Publisher:
        """Add a publisher in-memory (admin REST). Raises on conflict."""
        if key_id in self._by_key_id:
            raise ValueError(f"publisher {key_id!r} already in allowlist")
        decoded = _decode_b64(public_key_b64)
        public_key, raw = _parse_public_key(decoded)
        pub = Publisher(
            key_id=key_id,
            public_key=public_key,
            public_key_bytes=raw,
            source_path="(in-memory)",
        )
        self._by_key_id[key_id] = pub
        return pub


class BundleVerifier:
    """Verifies a SignedBundle against the publisher allowlist."""

    def __init__(self, allowlist: PublisherAllowlist) -> None:
        self._allowlist = allowlist

    @property
    def allowlist(self) -> PublisherAllowlist:
        return self._allowlist

    def verify(
        self,
        *,
        signer_key_id: str,
        bundle_yaml: bytes,
        signature: bytes,
    ) -> Publisher:
        """Return the publisher on success; raise on failure."""
        if not signer_key_id:
            raise UnknownPublisher("missing signer_key_id")
        pub = self._allowlist.get(signer_key_id)
        if pub is None:
            raise UnknownPublisher(
                f"signer_key_id {signer_key_id!r} not in publisher allowlist"
            )
        if not bundle_yaml:
            raise SignatureMismatch("empty bundle_yaml")
        sig_bytes = decode_signature(signature)
        digest = hashlib.sha256(bundle_yaml).digest()
        try:
            pub.public_key.verify(sig_bytes, digest)
        except InvalidSignature as e:
            raise SignatureMismatch(
                f"signature does not verify against {signer_key_id!r}: {e}"
            ) from e
        return pub


# ---- helpers -------------------------------------------------------------


def decode_signature(sig: bytes) -> bytes:
    """Normalise sig as raw ed25519 bytes (64 bytes).

    Accepts:
      - raw 64 bytes
      - base64-encoded (std, urlsafe, raw — with or without padding)

    Mirrors `pkg/policysync/cosign.go` decodeSignature so operator workflows
    are symmetric across Go + Python.
    """
    if isinstance(sig, str):
        sig = sig.encode("utf-8")
    if not sig:
        raise SignatureMismatch("empty signature")
    if len(sig) == 64:
        return bytes(sig)
    text = sig.decode("ascii", errors="strict").strip()
    if not text:
        raise SignatureMismatch("empty signature")
    return _decode_b64(text)


def _decode_b64(text: str) -> bytes:
    # Try the four common shapes; pick whichever decodes cleanly. We keep
    # the trial-and-error explicit rather than guessing because operator
    # tooling produces different shapes (cosign emits std; some scripts emit
    # urlsafe).
    text = text.strip()
    for decoder in (
        base64.b64decode,
        base64.urlsafe_b64decode,
    ):
        try:
            decoded = decoder(text)
            return decoded
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            continue
    # Fall back to no-padding urlsafe (raw urlsafe).
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise SignatureMismatch(f"signature not valid base64: {e}") from e


def _parse_public_key(data: bytes) -> tuple[Ed25519PublicKey, bytes]:
    """Parse an ed25519 public key from PEM, raw 32 bytes, or base64."""
    # PEM (PKIX).
    text = data.decode("utf-8", errors="ignore").strip()
    if "BEGIN PUBLIC KEY" in text or "BEGIN PRIVATE KEY" in text:
        try:
            pub = serialization.load_pem_public_key(data)
        except (ValueError, TypeError) as e:
            raise ValueError(f"PEM public key parse failed: {e}") from e
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("PEM key is not Ed25519")
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub, raw

    # Raw 32 bytes.
    if len(data) == 32:
        pub = Ed25519PublicKey.from_public_bytes(data)
        return pub, bytes(data)

    # Hex string of 64 chars (32 bytes).
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        raw = bytes.fromhex(text)
        return Ed25519PublicKey.from_public_bytes(raw), raw

    # Base64-encoded 32-byte raw key.
    try:
        decoded = _decode_b64(text)
        if len(decoded) == 32:
            return Ed25519PublicKey.from_public_bytes(decoded), decoded
    except SignatureMismatch:
        pass

    raise ValueError(
        f"could not parse public key: {len(data)} bytes (expected PEM / 32 raw / hex / base64)"
    )


def sign_bundle(private_key_b64: str, bundle_yaml: bytes) -> bytes:
    """Sign a bundle as the operator helper does.

    Returns the raw 64-byte signature. Callers that want base64 should
    `base64.b64encode(...)` the result. Used by the test seed publisher
    and by `tests/test_integration_3nodes.py`.
    """
    raw_priv = _decode_b64(private_key_b64)
    if len(raw_priv) == 32:
        priv = Ed25519PrivateKey.from_private_bytes(raw_priv)
    elif len(raw_priv) == 64:
        # Full ed25519 private key (seed || pub); cryptography accepts the
        # seed half via from_private_bytes.
        priv = Ed25519PrivateKey.from_private_bytes(raw_priv[:32])
    else:
        raise ValueError(
            f"private key must decode to 32 or 64 bytes (got {len(raw_priv)})"
        )
    digest = hashlib.sha256(bundle_yaml).digest()
    return priv.sign(digest)
