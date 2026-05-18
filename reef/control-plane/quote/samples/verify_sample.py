"""Offline verifier for the committed Reef Insurance Artifact (RIA) sample.

Usage::

    python samples/verify_sample.py

Verifies ``samples/sample-ria.pdf`` against ``samples/sample-ria.pdf.sig``
using the committed ``samples/sample-signer.pub``. Exits 0 only when the
signature verifies cleanly; non-zero on any failure.

Phase B round 1 (R-1) added this script so an external auditor can verify
the committed sample with one command — no Reef services required. The
wire format is::

    sig = ed25519_sign(priv, SHA-256(pdf_bytes))

This matches both ``lobstertrap-reef/pkg/policysync/cosign.go`` (the Go
verifier path) and ``app/ria_signer.py`` (the Python signer path), so the
sample's signature is cross-verifier compatible.

The committed ``samples/sample-signer.key`` is a DEMO-ONLY key that
exists so anyone cloning the repo can reproduce the signed sample
deterministically. Do NOT reuse it for real operator deployments — see
``.env.example`` (``REEF_QUOTE_SIGNER_PRIV_KEY``) for the production
operator key path.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path


def verify_sample(samples_dir: Path) -> int:
    """Return 0 on signature verify success, non-zero on any failure."""
    pdf_path = samples_dir / "sample-ria.pdf"
    sig_path = samples_dir / "sample-ria.pdf.sig"
    pub_path = samples_dir / "sample-signer.pub"

    for p in (pdf_path, sig_path, pub_path):
        if not p.exists():
            sys.stderr.write(
                f"verify_sample: missing required file: {p}\n"
            )
            return 2

    pdf_bytes = pdf_path.read_bytes()
    sig_b64 = sig_path.read_text(encoding="ascii").strip()
    pub_pem = pub_path.read_bytes()

    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        sys.stderr.write(f"verify_sample: signature is not valid base64: {exc}\n")
        return 3

    if len(sig_bytes) != 64:
        sys.stderr.write(
            f"verify_sample: signature is {len(sig_bytes)} bytes; ed25519 expects 64.\n"
        )
        return 4

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        sys.stderr.write(
            "verify_sample: the `cryptography` package is required. "
            f"Install via `pip install cryptography`: {exc}\n"
        )
        return 5

    try:
        pub_key = serialization.load_pem_public_key(pub_pem)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"verify_sample: could not load public key: {exc}\n")
        return 6
    if not isinstance(pub_key, ed25519.Ed25519PublicKey):
        sys.stderr.write(
            f"verify_sample: public key is not ed25519 ({type(pub_key).__name__})\n"
        )
        return 7

    sha256_pdf = hashlib.sha256(pdf_bytes).digest()
    sha256_pdf_hex = sha256_pdf.hex()

    # The signer signs SHA-256(pdf_bytes) directly — same wire format as
    # the Go cosign verifier (pkg/policysync/cosign.go) so the sample is
    # cross-verifier compatible.
    try:
        pub_key.verify(sig_bytes, sha256_pdf)
    except InvalidSignature:
        sys.stderr.write(
            "verify_sample: SIGNATURE VERIFY FAILED.\n"
            f"  pdf       = {pdf_path}\n"
            f"  pdf_bytes = {len(pdf_bytes)} bytes\n"
            f"  pdf_sha256 = {sha256_pdf_hex}\n"
            f"  sig_b64   = {sig_b64[:40]}…\n"
            f"  pub_pem   = {pub_path}\n"
        )
        return 1

    sys.stdout.write(
        "verify_sample: OK\n"
        f"  pdf        = {pdf_path}\n"
        f"  pdf_bytes  = {len(pdf_bytes)} bytes\n"
        f"  pdf_sha256 = {sha256_pdf_hex}\n"
        f"  signature  = ed25519({sha256_pdf_hex[:24]}…) [verified]\n"
        f"  pub        = {pub_path.name}\n"
    )
    return 0


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parent
    return verify_sample(here)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
