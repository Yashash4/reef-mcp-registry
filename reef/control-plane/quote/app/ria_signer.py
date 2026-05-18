"""ed25519 Sigstore-style signing for the RIA PDF.

Signature contract (matches A-6 ``pkg/policysync/cosign.go`` so a Go
verifier can verify the same artifact):

* The signed message is ``SHA-256(pdf_bytes)`` — same as ``cosign sign-blob``.
* The signature is a raw 64-byte ed25519, returned as base64 + hex.
* The detached file is written next to the PDF as ``<ria_id>.pdf.sig``
  containing the base64 signature on a single line.

Keys are loaded from env:

* ``REEF_QUOTE_SIGNER_PRIV_KEY`` — PEM (PKCS#8) or raw / seed bytes
  (32 / 64 base64-encoded). Same parser as the Go policysync module.
* ``REEF_QUOTE_SIGNER_PUB_KEY`` — PEM (PKIX) or raw 32 bytes
  base64-encoded.

If the private key file is missing, the signer auto-generates a fresh
ed25519 key pair and persists it to ``REEF_QUOTE_SIGNER_PRIV_KEY`` (or
``./keys/quote-signer.key`` by default) so subsequent runs reuse it.
The auto-generation path is logged at INFO so the operator sees it.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("quote.ria_signer")


DEFAULT_PRIV_KEY_PATH = "./keys/quote-signer.key"
DEFAULT_PUB_KEY_PATH = "./keys/quote-signer.pub"


class RIASignerError(RuntimeError):
    code: str = "RIA_SIGNER_ERROR"

    def __init__(self, message: str, *, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class BadKeyMaterial(RIASignerError):
    code = "BAD_KEY_MATERIAL"


class SignatureVerificationFailed(RIASignerError):
    code = "SIGNATURE_VERIFICATION_FAILED"


@dataclasses.dataclass
class SignedPDFRecord:
    """Signed PDF + signature artifact set."""

    pdf_bytes: bytes
    sha256_hex: str
    signature_b64: str
    signature_hex: str
    signer_key_id: str
    signer_pub_pem: bytes

    @property
    def signature_hex_short(self) -> str:
        return self.signature_hex[:24] + "…"

    @property
    def signature_b64_short(self) -> str:
        return self.signature_b64[:32] + "…"


class RIASigner:
    """Loads + persists ed25519 keys, signs the RIA PDF, verifies signatures."""

    def __init__(
        self,
        *,
        priv_key_path: Optional[str] = None,
        pub_key_path: Optional[str] = None,
        signer_key_id: Optional[str] = None,
        auto_generate: bool = True,
    ) -> None:
        self._priv_key_path = Path(
            priv_key_path
            or os.environ.get("REEF_QUOTE_SIGNER_PRIV_KEY")
            or DEFAULT_PRIV_KEY_PATH
        )
        self._pub_key_path = Path(
            pub_key_path
            or os.environ.get("REEF_QUOTE_SIGNER_PUB_KEY")
            or DEFAULT_PUB_KEY_PATH
        )
        self._signer_key_id = (
            signer_key_id
            or os.environ.get("REEF_QUOTE_SIGNER_KEY_ID")
            or self._priv_key_path.stem
        )
        self._priv_key, self._pub_key = self._load_or_generate(auto_generate=auto_generate)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def signer_key_id(self) -> str:
        return self._signer_key_id

    @property
    def pub_key_path(self) -> Path:
        return self._pub_key_path

    @property
    def priv_key_path(self) -> Path:
        return self._priv_key_path

    @property
    def public_key_pem(self) -> bytes:
        return self._pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ------------------------------------------------------------------
    # Sign / verify
    # ------------------------------------------------------------------

    def sign_pdf_bytes(self, pdf_bytes: bytes) -> SignedPDFRecord:
        digest = hashlib.sha256(pdf_bytes).digest()
        sig = self._priv_key.sign(digest)
        return SignedPDFRecord(
            pdf_bytes=pdf_bytes,
            sha256_hex=digest.hex(),
            signature_b64=base64.b64encode(sig).decode("ascii"),
            signature_hex=sig.hex(),
            signer_key_id=self._signer_key_id,
            signer_pub_pem=self.public_key_pem,
        )

    def verify(self, pdf_bytes: bytes, signature_b64: str) -> bool:
        try:
            sig = base64.b64decode(signature_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise BadKeyMaterial(f"signature is not valid base64: {exc}") from exc
        digest = hashlib.sha256(pdf_bytes).digest()
        try:
            self._pub_key.verify(sig, digest)
            return True
        except InvalidSignature as exc:
            raise SignatureVerificationFailed(
                f"RIA signature did not verify against the loaded public key: {exc}"
            ) from exc

    def write_detached_signature(
        self, *, pdf_path: Path, signed: SignedPDFRecord
    ) -> Path:
        """Write ``<pdf>.sig`` next to the PDF, containing the base64 signature."""
        sig_path = Path(str(pdf_path) + ".sig")
        sig_path.parent.mkdir(parents=True, exist_ok=True)
        sig_path.write_text(signed.signature_b64 + "\n", encoding="ascii")
        return sig_path

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def _load_or_generate(
        self, *, auto_generate: bool
    ) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        if self._priv_key_path.exists():
            try:
                priv = self._parse_priv_key(self._priv_key_path.read_bytes())
            except BadKeyMaterial:
                raise
            except Exception as exc:  # noqa: BLE001
                raise BadKeyMaterial(
                    f"failed to parse private key at {self._priv_key_path}: {exc}"
                ) from exc
        elif auto_generate:
            logger.info(
                "RIA signer: no private key at %s — generating a fresh ed25519 key pair",
                self._priv_key_path,
            )
            priv = ed25519.Ed25519PrivateKey.generate()
            self._priv_key_path.parent.mkdir(parents=True, exist_ok=True)
            self._priv_key_path.write_bytes(
                priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        else:
            raise BadKeyMaterial(
                f"RIA signer private key not found at {self._priv_key_path} and auto_generate=False"
            )

        pub = priv.public_key()
        # Persist the public key alongside it so a separate verifier (Go +
        # Stage UI) can pick it up without re-deriving.
        if not self._pub_key_path.exists():
            self._pub_key_path.parent.mkdir(parents=True, exist_ok=True)
            self._pub_key_path.write_bytes(
                pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        return priv, pub

    def _parse_priv_key(self, data: bytes) -> ed25519.Ed25519PrivateKey:
        """Parse PEM (PKCS#8), raw seed (32 bytes), or full key (64 bytes).

        Mirrors :func:`policysync.ParsePrivateKey` in the Go fork — both
        accept the same formats so operator keys cross-load.
        """
        text = data.strip()
        # Try PEM first.
        if text.startswith(b"-----BEGIN"):
            priv = serialization.load_pem_private_key(text, password=None)
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise BadKeyMaterial(
                    f"PEM private key is not ed25519: {type(priv).__name__}"
                )
            return priv
        # Try base64 → raw bytes (seed 32 or full key 64).
        try:
            decoded = base64.b64decode(text, validate=True)
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            try:
                decoded = base64.urlsafe_b64decode(text + b"==")
            except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
                raise BadKeyMaterial(
                    f"private key payload is not PEM and not base64 (len={len(text)})"
                )
        if len(decoded) == 32:
            return ed25519.Ed25519PrivateKey.from_private_bytes(decoded)
        if len(decoded) == 64:
            # First 32 bytes are the seed, last 32 are the derived public key
            # (matches Go's ed25519.PrivateKey internal layout).
            return ed25519.Ed25519PrivateKey.from_private_bytes(decoded[:32])
        raise BadKeyMaterial(
            f"decoded private key has size {len(decoded)} (expected 32 or 64)"
        )


__all__ = [
    "RIASigner",
    "SignedPDFRecord",
    "RIASignerError",
    "BadKeyMaterial",
    "SignatureVerificationFailed",
    "DEFAULT_PRIV_KEY_PATH",
    "DEFAULT_PUB_KEY_PATH",
]
