"""FastAPI endpoint tests using fastapi.testclient.TestClient."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client(tmp_dast_a_dirs: dict, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # The app's lifespan reads env vars at startup; tmp_dast_a_dirs already
    # sets them. We additionally point the human-review webhook at a noop
    # URL so any approve test in this module skips the network round-trip.
    monkeypatch.setenv(
        "REEF_HUMAN_REVIEW_WEBHOOK", "http://127.0.0.1:0/noop"
    )
    monkeypatch.setenv("REEF_DAST_A_USE_STUB_VICTIM", "1")
    app = create_app()
    with TestClient(app) as tc:
        yield tc


class TestHealth:
    def test_healthz_ok(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["catalog"]["total"] == 4

    def test_healthz_shows_seed_counts(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        data = resp.json()
        assert data["catalog"]["by_source"]["external_disclosure"] == 2
        assert data["catalog"]["by_source"]["dast_a_synthetic"] == 2


class TestPacks:
    def test_list_packs(self, client: TestClient) -> None:
        resp = client.get("/dast-a/packs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4
        ids = {p["pack_id"] for p in data["packs"]}
        assert "MCP-RCE-26.04" in ids
        assert "EchoLeak-26.05" in ids

    def test_get_pack_detail(self, client: TestClient) -> None:
        resp = client.get("/dast-a/packs/MCP-RCE-26.04")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pack_id"] == "MCP-RCE-26.04"
        assert "OX Security disclosed April 16 2026" in data["ox_security_citation"]

    def test_get_unknown_pack_returns_404(self, client: TestClient) -> None:
        resp = client.get("/dast-a/packs/does-not-exist")
        assert resp.status_code == 404

    def test_pagination(self, client: TestClient) -> None:
        resp = client.get("/dast-a/packs?page=1&page_size=2")
        data = resp.json()
        assert data["page_size"] == 2
        assert len(data["packs"]) == 2


class TestRun:
    def test_post_run_with_stub_victim(self, client: TestClient) -> None:
        resp = client.post(
            "/dast-a/run",
            json={
                "episodes": 5,
                "checkpoint": "auto",
                "reef_on": False,
                "use_stub_victim": True,
                "max_steps": 10,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert data["summary"]["episodes"] == 5
        assert len(data["episodes"]) == 5

    def test_post_run_async(self, client: TestClient) -> None:
        resp = client.post(
            "/dast-a/run?async=true",
            json={
                "episodes": 3,
                "checkpoint": "auto",
                "reef_on": False,
                "use_stub_victim": True,
                "max_steps": 8,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "scheduled"
        handle = data["run_handle"]
        # Run is small; eventual consistency check.
        import time

        for _ in range(60):
            poll = client.get(f"/dast-a/run/{handle}")
            poll_data = poll.json()
            if poll_data.get("status") == "completed":
                break
            time.sleep(0.1)
        else:
            pytest.fail("async run did not complete in time")


class TestReviewQueue:
    def test_review_queue_starts_empty(self, client: TestClient) -> None:
        resp = client.get("/dast-a/review-queue")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_status_filter_validates(self, client: TestClient) -> None:
        resp = client.get("/dast-a/review-queue?status=bogus")
        assert resp.status_code == 400
