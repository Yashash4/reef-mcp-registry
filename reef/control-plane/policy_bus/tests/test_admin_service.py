"""Tests for the FastAPI admin REST surface."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.service.admin_service import build_admin_app
from app.service.bus_service import ServiceState


def _sign(priv: Ed25519PrivateKey, payload: bytes) -> bytes:
    digest = hashlib.sha256(payload).digest()
    return priv.sign(digest)


@pytest.mark.asyncio
async def test_healthz_no_auth_required(service_state: ServiceState) -> None:
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["active_bundles"] == 0


@pytest.mark.asyncio
async def test_fleet_endpoint_returns_seed(service_state: ServiceState) -> None:
    from app.store.fleet_store import default_seed_nodes

    seeded = await service_state.fleet_store.seed_if_empty(default_seed_nodes())
    assert seeded == 49
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.get("/fleet?fleet_id=prod-fleet")
        assert r.status_code == 200
        snap = r.json()
        assert snap["fleet_id"] == "prod-fleet"
        assert snap["node_count"] == 49
        assert snap["region_count"] == 3
        assert snap["site_count"] == 7


@pytest.mark.asyncio
async def test_publish_requires_admin_token(service_state: ServiceState) -> None:
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.post(
            "/publish",
            json={
                "bundle_id": "b1",
                "version": "v1",
                "bundle_yaml_b64": base64.b64encode(b"yaml").decode("ascii"),
                "signature_b64": base64.b64encode(b"x" * 64).decode("ascii"),
                "signer_key_id": "prod-signer",
            },
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_publish_rejects_unknown_publisher(
    service_state: ServiceState,
    attacker_keypair: Ed25519PrivateKey,
) -> None:
    yaml = b"yaml-bytes"
    sig = _sign(attacker_keypair, yaml)
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.post(
            "/publish",
            headers={"X-Admin-Token": service_state.admin_token},
            json={
                "bundle_id": "b1",
                "version": "v1",
                "bundle_yaml_b64": base64.b64encode(yaml).decode("ascii"),
                "signature_b64": base64.b64encode(sig).decode("ascii"),
                "signer_key_id": "nobody",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] is False
        assert "unknown publisher" in body["reason"]


@pytest.mark.asyncio
async def test_publish_accepts_signed(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    priv, key_id = signer_keypair
    yaml = b"version: '1.0'\n"
    sig = _sign(priv, yaml)
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.post(
            "/publish",
            headers={"X-Admin-Token": service_state.admin_token},
            json={
                "bundle_id": "b1",
                "version": "v1",
                "scope_fleet_id": "prod-fleet",
                "bundle_yaml_b64": base64.b64encode(yaml).decode("ascii"),
                "signature_b64": base64.b64encode(sig).decode("ascii"),
                "signer_key_id": key_id,
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] is True
        assert body["bundle_id"] == "b1"
        assert body["audit_id"].startswith("audit-")


@pytest.mark.asyncio
async def test_list_bundles_hides_raw_bytes(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    priv, key_id = signer_keypair
    yaml = b"yaml"
    sig = _sign(priv, yaml)
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        client.post(
            "/publish",
            headers={"X-Admin-Token": service_state.admin_token},
            json={
                "bundle_id": "b1",
                "version": "v1",
                "bundle_yaml_b64": base64.b64encode(yaml).decode("ascii"),
                "signature_b64": base64.b64encode(sig).decode("ascii"),
                "signer_key_id": key_id,
            },
        )
        r = client.get("/bundles")
        assert r.status_code == 200
        bundles = r.json()
        assert len(bundles) == 1
        assert "bundle_yaml_b64" not in bundles[0]
        assert "signature_b64" not in bundles[0]
        assert bundles[0]["bundle_id"] == "b1"


@pytest.mark.asyncio
async def test_list_publishers(
    service_state: ServiceState,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.get("/publishers")
        assert r.status_code == 200
        publishers = r.json()
        assert len(publishers) == 1
        assert publishers[0]["key_id"] == "prod-signer"
        assert len(publishers[0]["fingerprint"]) == 16


@pytest.mark.asyncio
async def test_add_publisher_requires_admin_token(service_state: ServiceState) -> None:
    new_priv = Ed25519PrivateKey.generate()
    pub_raw = new_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        # No header → 401
        r = client.post(
            "/publishers",
            json={
                "key_id": "new-signer",
                "public_key_b64": base64.b64encode(pub_raw).decode("ascii"),
            },
        )
        assert r.status_code == 401
        # With header → 201
        r = client.post(
            "/publishers",
            headers={"X-Admin-Token": service_state.admin_token},
            json={
                "key_id": "new-signer",
                "public_key_b64": base64.b64encode(pub_raw).decode("ascii"),
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["key_id"] == "new-signer"


@pytest.mark.asyncio
async def test_audit_tail_requires_admin_token(service_state: ServiceState) -> None:
    app = build_admin_app(service_state)
    with TestClient(app) as client:
        r = client.get("/audit/tail")
        assert r.status_code == 401
        r = client.get(
            "/audit/tail",
            headers={"X-Admin-Token": service_state.admin_token},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)
