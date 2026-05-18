"""HTTP-level tests for the Reef Quote API."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Set the boot config BEFORE importing the app so lifespan uses our tmp paths.


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("REEF_QUOTE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("REEF_QUOTE_SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setenv("REEF_QUOTE_SIGNER_PRIV_KEY", str(tmp_path / "k.key"))
    monkeypatch.setenv("REEF_QUOTE_SIGNER_PUB_KEY", str(tmp_path / "k.pub"))
    monkeypatch.setenv("REEF_QUOTE_SIGNER_KEY_ID", "test-api-signer")
    monkeypatch.setenv("REEF_QUOTE_SAMPLE_ON_BOOT", "true")
    # Force sample mode by not setting GEMINI_API_KEY.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_PRO_MODEL", raising=False)

    # Import here so it picks up env.
    from app.api.app import create_app

    app = create_app()
    # `with TestClient(app):` is required to fire the lifespan handler,
    # which is what wires `app.state.signer` etc.
    with TestClient(app) as c:
        yield c


def test_healthz_returns_signer_fingerprint(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["signer_key_id"] == "test-api-signer"
    assert len(body["signer_pub_fingerprint"]) == 16


def test_sample_pdf_is_generated_on_boot_and_downloadable(client: TestClient) -> None:
    health = client.get("/healthz").json()
    assert health["sample_exists"] is True

    r = client.get("/quote/ria/sample/download")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert "X-Reef-RIA-Signature" in r.headers
    assert "X-Reef-RIA-SHA256" in r.headers
    assert r.content.startswith(b"%PDF")


def test_sample_verify_endpoint_returns_verified_true(client: TestClient) -> None:
    r = client.get("/quote/ria/sample/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["signer_key_id"] == "test-api-signer"


def test_generate_returns_503_when_no_atlas_and_no_fallback(client: TestClient) -> None:
    # No GEMINI_API_KEY + no Atlas + allow_sample_fallback=false → 503 with
    # the most upstream failure code (Atlas first).
    r = client.post(
        "/quote/ria/generate",
        json={
            "fleet_id": "prod-fleet",
            "audit_window_days": 30,
            "include_demo_data": False,
            "allow_sample_fallback": False,
        },
    )
    assert r.status_code == 503
    body = r.json()
    assert "code" in body["detail"]


def test_generate_with_fallback_succeeds(client: TestClient) -> None:
    r = client.post(
        "/quote/ria/generate",
        json={
            "fleet_id": "prod-fleet",
            "audit_window_days": 30,
            "include_demo_data": True,
            "allow_sample_fallback": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["sample_mode"] is True
    assert body["ria_id"].startswith("ria-")
    assert body["download_url"].endswith("/download")
    assert body["score_summary"]["reef_risk_tier"] == "B+"
    assert "mapped to Munich Re aiSure axes" in body["score_summary"]["tier_label_with_framing"]

    # Then download + verify the generated artifact.
    dl = client.get(body["download_url"])
    assert dl.status_code == 200
    assert dl.content.startswith(b"%PDF")
    ver = client.get(body["verify_url"])
    assert ver.status_code == 200
    assert ver.json()["verified"] is True


def test_download_nonexistent_returns_404(client: TestClient) -> None:
    r = client.get("/quote/ria/ria-does-not-exist/download")
    assert r.status_code == 404
