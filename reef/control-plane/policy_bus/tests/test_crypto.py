"""Tests for app.crypto.verify_bundle."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto.verify_bundle import (
    BundleVerifier,
    PublisherAllowlist,
    SignatureMismatch,
    UnknownPublisher,
    decode_signature,
    sign_bundle,
)


def _write_pub(dir_: Path, key_id: str, priv: Ed25519PrivateKey) -> None:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (dir_ / f"{key_id}.pub").write_bytes(raw)


def _sign(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    return priv.sign(digest)


def test_allowlist_loads_raw_keys(tmp_path: Path) -> None:
    priv1 = Ed25519PrivateKey.generate()
    priv2 = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv1)
    _write_pub(tmp_path, "publisher-dev", priv2)
    allow = PublisherAllowlist(tmp_path)
    assert len(allow) == 2
    assert "publisher-prod" in allow
    assert "publisher-dev" in allow
    assert allow.list_key_ids() == ["publisher-dev", "publisher-prod"]


def test_allowlist_loads_pem_keys(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "pem-signer.pem").write_bytes(pem)
    allow = PublisherAllowlist(tmp_path)
    assert "pem-signer" in allow


def test_allowlist_skips_non_key_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("ignore me")
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    allow = PublisherAllowlist(tmp_path)
    assert allow.list_key_ids() == ["publisher-prod"]


def test_verify_happy_path(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"version: '1.0'\npolicy: ok\n"
    sig = _sign(priv, yaml)
    pub = verifier.verify(
        signer_key_id="publisher-prod",
        bundle_yaml=yaml,
        signature=sig,
    )
    assert pub.key_id == "publisher-prod"


def test_verify_accepts_base64_signature(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"policy yaml here"
    sig = _sign(priv, yaml)
    sig_b64 = base64.b64encode(sig)
    pub = verifier.verify(
        signer_key_id="publisher-prod",
        bundle_yaml=yaml,
        signature=sig_b64,
    )
    assert pub.key_id == "publisher-prod"


def test_verify_unknown_publisher_rejected(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    attacker = Ed25519PrivateKey.generate()
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"malicious yaml"
    sig = _sign(attacker, yaml)
    with pytest.raises(UnknownPublisher):
        verifier.verify(
            signer_key_id="attacker",  # NOT in allowlist
            bundle_yaml=yaml,
            signature=sig,
        )


def test_verify_tampered_yaml_rejected(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"original"
    sig = _sign(priv, yaml)
    with pytest.raises(SignatureMismatch):
        verifier.verify(
            signer_key_id="publisher-prod",
            bundle_yaml=b"TAMPERED",
            signature=sig,
        )


def test_verify_signature_from_wrong_publisher_rejected(tmp_path: Path) -> None:
    """Allowlist has key A but signature was made with key B → reject."""
    priv_a = Ed25519PrivateKey.generate()
    priv_b = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-a", priv_a)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"yaml"
    sig_from_b = _sign(priv_b, yaml)
    with pytest.raises(SignatureMismatch):
        verifier.verify(
            signer_key_id="publisher-a",
            bundle_yaml=yaml,
            signature=sig_from_b,
        )


def test_verify_empty_yaml_rejected(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    with pytest.raises(SignatureMismatch):
        verifier.verify(
            signer_key_id="publisher-prod",
            bundle_yaml=b"",
            signature=b"x" * 64,
        )


def test_verify_missing_signer_key_id_rejected(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    _write_pub(tmp_path, "publisher-prod", priv)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    yaml = b"yaml"
    sig = _sign(priv, yaml)
    with pytest.raises(UnknownPublisher, match="missing"):
        verifier.verify(signer_key_id="", bundle_yaml=yaml, signature=sig)


def test_decode_signature_raw_passthrough() -> None:
    sig = b"x" * 64
    assert decode_signature(sig) == sig


def test_decode_signature_base64() -> None:
    sig = b"y" * 64
    decoded = decode_signature(base64.b64encode(sig))
    assert decoded == sig


def test_decode_signature_urlsafe() -> None:
    sig = b"z" * 64
    decoded = decode_signature(base64.urlsafe_b64encode(sig))
    assert decoded == sig


def test_decode_signature_empty_rejected() -> None:
    with pytest.raises(SignatureMismatch, match="empty"):
        decode_signature(b"")


def test_sign_bundle_round_trip(tmp_path: Path) -> None:
    """The sign_bundle helper produces a signature the verifier accepts."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_b64 = base64.b64encode(seed).decode("ascii")
    _write_pub(tmp_path, "publisher-prod", priv)
    yaml = b"signed policy yaml"
    sig = sign_bundle(priv_b64, yaml)
    verifier = BundleVerifier(PublisherAllowlist(tmp_path))
    pub = verifier.verify(
        signer_key_id="publisher-prod",
        bundle_yaml=yaml,
        signature=sig,
    )
    assert pub.key_id == "publisher-prod"
