"""Tests for POST /register."""

from __future__ import annotations

from app.crypto import generate_keypair, sign_manifest
from app.models import Manifest


def _manifest_dict(**overrides) -> dict:
    base = {
        "mcpName": "com.example/weather-mcp",
        "version": "1.2.3",
        "protocolVersion": "2025-06-18",
        "transports": ["http"],
        "tools": [{"name": "get_weather", "description": "..."}],
        "capabilities": ["tools"],
        "stdio_entrypoint_hash": None,
        "sdk_version": "@modelcontextprotocol/sdk@1.29.0",
    }
    base.update(overrides)
    return base


def _register_publisher(client, sk_hex: str | None = None, scopes=None, pid="pub-tester"):
    if sk_hex is None:
        sk_hex, pk_hex = generate_keypair()
    else:
        from app.crypto import load_public_key
        from cryptography.hazmat.primitives import serialization
        pk_hex = load_public_key(sk_hex).public_bytes(  # type: ignore
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    if scopes is None:
        scopes = ["com.example.*"]
    resp = client.post(
        "/publishers",
        json={
            "publisher_id": pid,
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": scopes,
        },
    )
    assert resp.status_code == 201, resp.text
    return sk_hex, pk_hex


def test_register_happy_path(api_client):
    sk_hex, pk_hex = generate_keypair()
    api_client.post(
        "/publishers",
        json={
            "publisher_id": "pub-tester",
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": ["com.example.*"],
        },
    )
    md = _manifest_dict()
    sig = sign_manifest(Manifest(**md).model_dump(mode="json"), sk_hex)
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-tester", "signature": sig},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "verified"
    assert "publisher_provenance" in body["checks_passed"]
    assert body["checks_failed"] == []
    assert body["registry_id"].startswith("reg-")
    assert body["audit_id"].startswith("audit-")


def test_register_rejects_bad_signature(api_client):
    _, pk_hex = generate_keypair()
    api_client.post(
        "/publishers",
        json={
            "publisher_id": "pub-tester",
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": ["com.example.*"],
        },
    )
    md = _manifest_dict()
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-tester", "signature": "ab" * 32},
    )
    assert resp.status_code == 400, resp.text
    assert "signature" in resp.text.lower()


def test_register_unknown_publisher(api_client):
    sk_hex, _ = generate_keypair()
    md = _manifest_dict()
    sig = sign_manifest(Manifest(**md).model_dump(mode="json"), sk_hex)
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-nope", "signature": sig},
    )
    assert resp.status_code == 400
    assert "unknown publisher" in resp.text


def test_register_vulnerable_sdk_becomes_poisoned(api_client):
    sk_hex, pk_hex = generate_keypair()
    api_client.post(
        "/publishers",
        json={
            "publisher_id": "pub-tester",
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": ["com.example.*"],
        },
    )
    md = _manifest_dict(sdk_version="@modelcontextprotocol/sdk@0.5.0")
    sig = sign_manifest(Manifest(**md).model_dump(mode="json"), sk_hex)
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-tester", "signature": sig},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "poisoned"
    assert "sdk_version_policy" in body["checks_failed"]


def test_register_out_of_scope_becomes_poisoned(api_client):
    sk_hex, pk_hex = generate_keypair()
    api_client.post(
        "/publishers",
        json={
            "publisher_id": "pub-tester",
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": ["com.example.*"],
        },
    )
    # mcpName outside scope
    md = _manifest_dict(mcpName="com.attacker/weather-mcp")
    sig = sign_manifest(Manifest(**md).model_dump(mode="json"), sk_hex)
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-tester", "signature": sig},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "poisoned"
    assert "publisher_scope" in body["checks_failed"]


def test_register_stdio_without_hash_quarantined(api_client):
    sk_hex, pk_hex = generate_keypair()
    api_client.post(
        "/publishers",
        json={
            "publisher_id": "pub-tester",
            "display_name": "Tester",
            "public_key_hex": pk_hex,
            "scopes": ["com.example.*"],
        },
    )
    md = _manifest_dict(transports=["stdio"], stdio_entrypoint_hash=None)
    sig = sign_manifest(Manifest(**md).model_dump(mode="json"), sk_hex)
    resp = api_client.post(
        "/register",
        json={"manifest": md, "publisher_id": "pub-tester", "signature": sig},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "quarantined"
    assert "stdio_policy" in body["checks_failed"]
