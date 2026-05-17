"""Crypto unit tests — canonical-JSON, sign, verify, key generation."""

from __future__ import annotations

from app.crypto import (
    canonical_json,
    fingerprint,
    generate_keypair,
    sign_manifest,
    verify_manifest_signature,
)


def test_canonical_json_is_stable_under_key_reorder():
    a = {"b": 1, "a": 2, "c": [3, 1, 2]}
    b = {"a": 2, "c": [3, 1, 2], "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_handles_unicode():
    payload = {"name": "café", "emoji": "✓"}
    raw = canonical_json(payload)
    assert b"caf\xc3\xa9" in raw


def test_generate_keypair_returns_32_byte_hex():
    sk_hex, pk_hex = generate_keypair()
    assert len(sk_hex) == 64
    assert len(pk_hex) == 64
    # hex should decode
    bytes.fromhex(sk_hex)
    bytes.fromhex(pk_hex)


def test_fingerprint_is_stable_and_short():
    _, pk_hex = generate_keypair()
    fp1 = fingerprint(pk_hex)
    fp2 = fingerprint(pk_hex)
    assert fp1 == fp2
    assert len(fp1) == 16
    int(fp1, 16)  # valid hex


def test_sign_then_verify_roundtrip():
    sk_hex, pk_hex = generate_keypair()
    manifest = {
        "mcpName": "com.example/weather-mcp",
        "version": "1.2.3",
        "transports": ["http"],
        "sdk_version": "@modelcontextprotocol/sdk@1.29.0",
        "tools": [],
        "capabilities": [],
        "protocolVersion": "2025-06-18",
        "stdio_entrypoint_hash": None,
    }
    sig = sign_manifest(manifest, sk_hex)
    assert verify_manifest_signature(manifest, sig, pk_hex)


def test_verify_fails_on_tampered_payload():
    sk_hex, pk_hex = generate_keypair()
    manifest = {"a": 1, "b": 2}
    sig = sign_manifest(manifest, sk_hex)
    tampered = {"a": 1, "b": 3}
    assert not verify_manifest_signature(tampered, sig, pk_hex)


def test_verify_fails_on_wrong_key():
    sk_hex, _ = generate_keypair()
    _, other_pk = generate_keypair()
    manifest = {"a": 1}
    sig = sign_manifest(manifest, sk_hex)
    assert not verify_manifest_signature(manifest, sig, other_pk)


def test_verify_fails_on_garbage_signature():
    _, pk_hex = generate_keypair()
    assert not verify_manifest_signature({"a": 1}, "not-hex", pk_hex)
    assert not verify_manifest_signature({"a": 1}, "ab" * 32, pk_hex)
