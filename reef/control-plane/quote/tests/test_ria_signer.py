"""Unit tests for the RIA signer."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from app.ria_signer import (
    BadKeyMaterial,
    DEFAULT_PRIV_KEY_PATH,
    DEFAULT_PUB_KEY_PATH,
    RIASigner,
    SignatureVerificationFailed,
    SignedPDFRecord,
)


def test_signer_autogenerates_key_pair_on_first_use(tmp_path: Path) -> None:
    priv = tmp_path / "quote-signer.key"
    pub = tmp_path / "quote-signer.pub"
    signer = RIASigner(priv_key_path=str(priv), pub_key_path=str(pub))

    assert priv.exists()
    assert pub.exists()
    assert priv.read_bytes().startswith(b"-----BEGIN")
    assert pub.read_bytes().startswith(b"-----BEGIN")
    # signer_key_id falls back to the priv-key stem when env is unset.
    assert signer.signer_key_id == "quote-signer"


def test_sign_and_verify_round_trip(tmp_path: Path) -> None:
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
    )
    pdf = b"%PDF-1.4 hello world"
    signed = signer.sign_pdf_bytes(pdf)
    assert isinstance(signed, SignedPDFRecord)
    assert len(signed.signature_hex) == 128  # ed25519 = 64 bytes → 128 hex
    assert signed.sha256_hex == _hash_hex(pdf)
    assert signer.verify(pdf, signed.signature_b64) is True


def test_verify_fails_for_tampered_bytes(tmp_path: Path) -> None:
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
    )
    signed = signer.sign_pdf_bytes(b"%PDF original")
    with pytest.raises(SignatureVerificationFailed):
        signer.verify(b"%PDF tampered", signed.signature_b64)


def test_verify_fails_for_bad_signature_format(tmp_path: Path) -> None:
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
    )
    with pytest.raises(BadKeyMaterial):
        signer.verify(b"%PDF", "this is not base64 ##")


def test_detached_signature_file_is_written(tmp_path: Path) -> None:
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
    )
    pdf_path = tmp_path / "ria.pdf"
    pdf_path.write_bytes(b"%PDF dummy")
    signed = signer.sign_pdf_bytes(pdf_path.read_bytes())
    sig_path = signer.write_detached_signature(pdf_path=pdf_path, signed=signed)
    assert sig_path.exists()
    assert sig_path.name == "ria.pdf.sig"
    assert sig_path.read_text(encoding="ascii").strip() == signed.signature_b64


def test_signature_truncation_helpers(tmp_path: Path) -> None:
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
    )
    signed = signer.sign_pdf_bytes(b"%PDF")
    assert signed.signature_hex_short.endswith("…")
    assert signed.signature_b64_short.endswith("…")
    assert len(signed.signature_hex_short) == 24 + 1


def test_existing_pem_key_is_reused(tmp_path: Path) -> None:
    # First signer creates the key.
    a = RIASigner(
        priv_key_path=str(tmp_path / "shared.key"),
        pub_key_path=str(tmp_path / "shared.pub"),
    )
    # Second signer loads the same key (no regenerate).
    b = RIASigner(
        priv_key_path=str(tmp_path / "shared.key"),
        pub_key_path=str(tmp_path / "shared.pub"),
    )
    msg = b"%PDF stable"
    signed = a.sign_pdf_bytes(msg)
    assert b.verify(msg, signed.signature_b64)


def test_raw_seed_base64_private_key(tmp_path: Path) -> None:
    """Parser must accept a base64-encoded raw 32-byte seed."""
    # Generate a fresh key with cryptography, dump seed as base64, parse it back.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert len(raw) == 32
    priv_path = tmp_path / "raw.key"
    priv_path.write_text(base64.b64encode(raw).decode("ascii"), encoding="ascii")

    signer = RIASigner(
        priv_key_path=str(priv_path),
        pub_key_path=str(tmp_path / "raw.pub"),
    )
    msg = b"%PDF raw-seed"
    signed = signer.sign_pdf_bytes(msg)
    assert signer.verify(msg, signed.signature_b64)


def test_no_auto_generate_raises_when_key_missing(tmp_path: Path) -> None:
    with pytest.raises(BadKeyMaterial):
        RIASigner(
            priv_key_path=str(tmp_path / "absent.key"),
            pub_key_path=str(tmp_path / "absent.pub"),
            auto_generate=False,
        )


def _hash_hex(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()
