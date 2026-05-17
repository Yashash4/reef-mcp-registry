"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditLogger
from app.crypto import generate_keypair
from app.main import create_app
from app.seed import seed_demo
from app.store import FileStore


@pytest.fixture()
def tmp_paths(tmp_path: Path) -> dict:
    data = tmp_path / "data"
    keys = tmp_path / "keys"
    audit = data / "audit.jsonl"
    return {"data": data, "keys": keys, "audit": audit}


@pytest.fixture()
def store(tmp_paths) -> FileStore:
    return FileStore(tmp_paths["data"])


@pytest.fixture()
def auditor(tmp_paths) -> AuditLogger:
    return AuditLogger(tmp_paths["audit"])


@pytest.fixture()
def seeded_store(tmp_paths) -> FileStore:
    s = FileStore(tmp_paths["data"])
    seed_demo(s, tmp_paths["keys"])
    return s


@pytest.fixture()
def keypair() -> tuple[str, str]:
    return generate_keypair()


@pytest.fixture()
def api_client(tmp_paths, monkeypatch) -> TestClient:
    monkeypatch.setenv("REEF_ATLAS_DATA_DIR", str(tmp_paths["data"]))
    monkeypatch.setenv("REEF_ATLAS_PUBLISHER_KEYS_DIR", str(tmp_paths["keys"]))
    monkeypatch.setenv("REEF_ATLAS_AUDIT_FILE", str(tmp_paths["audit"]))
    monkeypatch.setenv("REEF_ATLAS_SEED_ON_BOOT", "1")
    app = create_app()
    with TestClient(app) as client:
        yield client
