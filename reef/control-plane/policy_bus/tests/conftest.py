"""Pytest fixtures for the Reef Policy Bus tests."""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path
from typing import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.audit import AuditLogger
from app.crypto import BundleVerifier, PublisherAllowlist
from app.service.bus_service import ServiceState
from app.store import BundleStore, FleetStore


@pytest.fixture
def tmp_keys_dir(tmp_path: Path) -> Path:
    keys = tmp_path / "publishers"
    keys.mkdir(parents=True, exist_ok=True)
    return keys


@pytest.fixture
def signer_keypair(tmp_keys_dir: Path) -> tuple[Ed25519PrivateKey, str]:
    """Write a `prod-signer.pub` file + return the (priv, key_id) pair."""
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "prod-signer"
    (tmp_keys_dir / f"{key_id}.pub").write_bytes(pub_raw)
    return priv, key_id


@pytest.fixture
def attacker_keypair(tmp_path: Path) -> Ed25519PrivateKey:
    """An attacker's private key — NOT in the publisher allowlist."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
async def service_state(
    tmp_path: Path,
    tmp_keys_dir: Path,
    signer_keypair: tuple[Ed25519PrivateKey, str],
) -> ServiceState:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    allowlist = PublisherAllowlist(tmp_keys_dir)
    verifier = BundleVerifier(allowlist)
    bundle_store = BundleStore(tmp_path / "bundles.jsonl")
    fleet_store = FleetStore(tmp_path / "fleet.json")
    return ServiceState(
        bundle_store=bundle_store,
        fleet_store=fleet_store,
        verifier=verifier,
        audit=audit,
        admin_token="test-admin-token-" + secrets.token_hex(8),
    )
