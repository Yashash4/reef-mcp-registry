"""Phase B round 1 R-1 — committed sample RIA must verify offline.

The CISO and POV-1 (Veea engineering) reviewer flagged that
``samples/sample-ria.pdf.sig`` did NOT verify against
``samples/sample-signer.pub``. This is a credibility-grade bug for a
project whose third-act categorical separator is "the insurable AI
deployment" — every auditor who downloads the sample RIA from the
README runs the verify call as their first step.

The fixes for R-1 were:

1. ``ensure_sample_ria`` now commits both halves of the sample-signer
   key pair (``samples/sample-signer.key`` + ``samples/sample-signer.pub``).
   The .pdf, .pdf.sig and .pub are therefore always in lockstep on a
   fresh clone.
2. A standalone offline verifier ships at
   ``samples/verify_sample.py`` — exits 0 only when verify passes.
3. This pytest enforces the same invariant at every CI run so a future
   commit that re-renders the PDF without re-signing fails the build.

Wire format (matches the Go cosign verifier in
``lobstertrap-reef/pkg/policysync/cosign.go``)::

    sig = ed25519_sign(priv, SHA-256(pdf_bytes))
"""
from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"
_PDF_PATH = _SAMPLES_DIR / "sample-ria.pdf"
_SIG_PATH = _SAMPLES_DIR / "sample-ria.pdf.sig"
_PUB_PATH = _SAMPLES_DIR / "sample-signer.pub"
_PRIV_PATH = _SAMPLES_DIR / "sample-signer.key"


def test_sample_artifacts_are_committed_on_disk() -> None:
    """R-1: all three sample artifacts are present in the repo."""
    assert _PDF_PATH.exists(), f"missing committed sample: {_PDF_PATH}"
    assert _SIG_PATH.exists(), f"missing committed sample: {_SIG_PATH}"
    assert _PUB_PATH.exists(), f"missing committed sample: {_PUB_PATH}"
    # The committed demo-only private key is what makes the sample
    # reproducible by anyone cloning the repo (R-1 design call).
    assert _PRIV_PATH.exists(), (
        f"missing committed sample-signer private key at {_PRIV_PATH} — "
        "without it the sample cannot be regenerated deterministically."
    )


def test_sample_pdf_is_a_valid_pdf() -> None:
    pdf_bytes = _PDF_PATH.read_bytes()
    assert pdf_bytes.startswith(b"%PDF"), (
        f"committed sample is not a PDF — first bytes: {pdf_bytes[:8]!r}"
    )


def test_sample_signature_verifies_offline() -> None:
    """R-1 acceptance — same code an external auditor would run.

    This is the load-bearing test: any future commit that desyncs the
    .pdf / .sig / .pub triplet fails this test and the build.
    """
    pdf_bytes = _PDF_PATH.read_bytes()
    sig_b64 = _SIG_PATH.read_text(encoding="ascii").strip()
    pub_pem = _PUB_PATH.read_bytes()

    sig_bytes = base64.b64decode(sig_b64, validate=True)
    assert len(sig_bytes) == 64, (
        f"ed25519 signature must be 64 bytes; got {len(sig_bytes)}"
    )

    pub_key = serialization.load_pem_public_key(pub_pem)
    assert isinstance(pub_key, ed25519.Ed25519PublicKey), (
        f"committed sample-signer.pub is not ed25519: {type(pub_key).__name__}"
    )

    sha256_pdf = hashlib.sha256(pdf_bytes).digest()
    # The verify call MUST succeed against sha256(pdf_bytes) per the
    # documented wire format. If a future commit accidentally re-signs
    # raw pdf_bytes instead of sha256(pdf_bytes), this assertion fires.
    try:
        pub_key.verify(sig_bytes, sha256_pdf)
    except InvalidSignature as exc:
        pytest.fail(
            "SIGNATURE VERIFY FAILED against the committed sample. "
            f"pdf={_PDF_PATH.name}, pdf_bytes={len(pdf_bytes)}, "
            f"sha256={sha256_pdf.hex()}, sig_b64={sig_b64[:40]}…  ({exc})"
        )


def test_sample_priv_pub_pair_is_self_consistent() -> None:
    """R-1: the committed priv key MUST derive the committed pub key.

    Otherwise an operator who re-runs ``ensure_sample_ria`` against the
    committed private key would produce a .sig that fails to verify
    against the committed public key — exactly the bug we just fixed.
    """
    priv_text = _PRIV_PATH.read_bytes()
    priv_key = serialization.load_pem_private_key(priv_text, password=None)
    assert isinstance(priv_key, ed25519.Ed25519PrivateKey)

    derived_pub_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    committed_pub_pem = _PUB_PATH.read_bytes()
    assert derived_pub_pem.strip() == committed_pub_pem.strip(), (
        "committed sample-signer.key does not derive sample-signer.pub — "
        "fix by rerunning `ensure_sample_ria` so the triplet is in sync."
    )


def test_verify_sample_script_exits_zero() -> None:
    """The standalone ``samples/verify_sample.py`` must exit 0 in CI."""
    script = _SAMPLES_DIR / "verify_sample.py"
    assert script.exists(), f"missing verifier script: {script}"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"verify_sample.py exited {result.returncode}\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}\n"
    )
    assert "verify_sample: OK" in result.stdout


def test_sample_verifier_rejects_tampered_pdf(tmp_path: Path) -> None:
    """Negative: a one-byte-flipped PDF MUST fail verify (no false-OK path)."""
    tampered = bytearray(_PDF_PATH.read_bytes())
    # Flip the first 'P' of "%PDF" to 'Q'. Still a sensible byte; just
    # not the same content the signature commits to.
    tampered[1] = ord("Q")

    sig_b64 = _SIG_PATH.read_text(encoding="ascii").strip()
    sig_bytes = base64.b64decode(sig_b64, validate=True)

    pub_key = serialization.load_pem_public_key(_PUB_PATH.read_bytes())
    assert isinstance(pub_key, ed25519.Ed25519PublicKey)

    sha256_tampered = hashlib.sha256(bytes(tampered)).digest()
    with pytest.raises(InvalidSignature):
        pub_key.verify(sig_bytes, sha256_tampered)
