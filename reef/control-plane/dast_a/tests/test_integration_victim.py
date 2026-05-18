"""Integration test for DAST-A vs. a victim app.

Two flavours of victim:

1. **Stub victim** (default in CI) — the deterministic ``StubVictimProxy``
   in-process. Mirrors the wire shape of the live victim's
   ``/api/summarize?demo=true`` response. Fast and reproducible.

2. **Live HTTP fixture** — an in-process FastAPI mock that echoes the
   payload back as a markdown image, optionally wrapped in a Reef-style
   proxy that strips markdown images to untrusted hosts. Exercises the
   real HTTP code path.

The integration assertions match the acceptance criteria in the dispatch
spec verbatim.
"""
from __future__ import annotations

import threading
import time
from typing import Iterator

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client(tmp_dast_a_dirs: dict, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv(
        "REEF_HUMAN_REVIEW_WEBHOOK", "http://127.0.0.1:0/noop"
    )
    monkeypatch.setenv("REEF_DAST_A_USE_STUB_VICTIM", "1")
    app = create_app()
    with TestClient(app) as tc:
        yield tc


class TestIntegrationStubVictim:
    """Drive 30 episodes against the in-process stub victim."""

    def test_reef_off_produces_successful_exfil_and_drafts(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/dast-a/run",
            json={
                "episodes": 30,
                "checkpoint": "auto",
                "reef_on": False,
                "use_stub_victim": True,
                "max_steps": 12,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["episodes"] == 30
        # With random / pre-trained policy and stub-victim feedback, at
        # least one successful exfil should land in 30 episodes.
        assert data["summary"]["successes"] >= 1, (
            f"expected ≥1 successful exfil, got summary={data['summary']!r}"
        )
        # And at least one draft should land in the review queue.
        review = client.get("/dast-a/review-queue").json()
        assert len(review) >= 1
        first_draft = review[0]
        assert "MODIFY" in first_draft["suggested_yaml_diff"]
        # Drafts must NOT be auto-approved.
        assert first_draft["status"] == "pending"

    def test_reef_on_blocks_attacks(self, client: TestClient) -> None:
        # With reef_on=True the stub Reef enforces MODIFY on every exfil
        # payload to an untrusted host. Across 50 episodes:
        #
        # * no successful exfil should land (success rate ≈ 0)
        # * of the exfil attempts that WOULD HAVE succeeded with reef_off
        #   (i.e. payloads carrying the secret to an untrusted host), the
        #   block_rate should be ≥ 90%.
        resp = client.post(
            "/dast-a/run",
            json={
                "episodes": 50,
                "checkpoint": "auto",
                "reef_on": True,
                "use_stub_victim": True,
                "max_steps": 12,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # Reef_on blocks every exfil; success_rate is effectively zero.
        assert data["summary"]["success_rate"] == pytest.approx(0.0, abs=0.05)
        # Episodes that recorded any attempt at exfil (i.e. blocked OR
        # succeeded) — measure the block-rate. The blocked-vs-succeeded
        # ratio is the spec's "≥ 90%" check.
        attempt_episodes = [
            ep
            for ep in data["episodes"]
            if ep["blocked_by_reef"] or ep["exfil_success"]
        ]
        if attempt_episodes:
            blocked = [ep for ep in attempt_episodes if ep["blocked_by_reef"]]
            block_rate = len(blocked) / len(attempt_episodes)
            assert block_rate >= 0.9, (
                f"expected ≥90% block rate on exfil attempts, "
                f"got {block_rate:.2%} ({len(blocked)}/{len(attempt_episodes)})"
            )


# ---------------------------------------------------------------------------
# Live HTTP fixture — boot an in-process FastAPI mock and run DAST-A against it
# ---------------------------------------------------------------------------


def _build_mock_victim_app(reef_on: bool) -> FastAPI:
    """Mock Next.js victim mirroring `/api/summarize?demo=true` shape."""
    app = FastAPI()

    @app.post("/api/summarize")
    async def summarize(req: Request) -> JSONResponse:
        body = await req.json()
        payload = str(body.get("payload", "")) if isinstance(body, dict) else ""
        # If Reef is ON, strip markdown images pointing at untrusted hosts.
        if reef_on and payload.startswith("!["):
            return JSONResponse(
                status_code=451,
                content={
                    "summary": "[REDACTED]",
                    "exfilDetected": False,
                    "exfilDestination": None,
                    "exfilUrl": None,
                    "blockedByReef": True,
                },
            )
        if payload.startswith("!["):
            host_start = payload.find("https://")
            host_end = payload.find("/", host_start + len("https://"))
            host = payload[host_start + len("https://"): host_end] if host_start >= 0 else None
            return JSONResponse(
                status_code=200,
                content={
                    "summary": payload,
                    "exfilDetected": True,
                    "exfilDestination": host,
                    "exfilUrl": payload[host_start: host_end + 10] if host_start >= 0 else None,
                },
            )
        return JSONResponse(
            status_code=200,
            content={
                "summary": payload,
                "exfilDetected": False,
                "exfilDestination": None,
                "exfilUrl": None,
            },
        )

    return app


def _start_uvicorn_in_thread(app: FastAPI, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for liveness.
    for _ in range(100):
        try:
            with httpx.Client(timeout=0.3) as c:
                # Any endpoint that responds — a POST to /api/summarize will
                # return 200 even with empty body.
                c.post(
                    f"http://127.0.0.1:{port}/api/summarize",
                    json={"payload": ""},
                )
            break
        except httpx.HTTPError:
            time.sleep(0.05)
    return server, thread


def _stop_server(server: uvicorn.Server, thread: threading.Thread) -> None:
    server.should_exit = True
    thread.join(timeout=5.0)


class TestIntegrationLiveHTTP:
    """Boot a real HTTP server and run DAST-A against it.

    Slower than the stub flavour (full TCP round-trip); only one
    representative episode count is used.
    """

    def test_live_mock_victim_handshake(
        self, tmp_dast_a_dirs: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        port = 8743
        mock_app = _build_mock_victim_app(reef_on=False)
        server, thread = _start_uvicorn_in_thread(mock_app, port)
        try:
            monkeypatch.setenv("REEF_VICTIM_URL", f"http://127.0.0.1:{port}")
            monkeypatch.setenv(
                "REEF_HUMAN_REVIEW_WEBHOOK", "http://127.0.0.1:0/noop"
            )
            app = create_app()
            with TestClient(app) as tc:
                resp = tc.post(
                    "/dast-a/run",
                    json={
                        "episodes": 5,
                        "checkpoint": "auto",
                        "reef_on": False,
                        "use_stub_victim": False,
                        "max_steps": 10,
                    },
                )
                assert resp.status_code == 200
                data = resp.json()
                # 5 episodes against the live HTTP mock; we don't insist on
                # success counts (we may or may not hit the markdown-image
                # combo in 5 random episodes), but we DO insist that the
                # transport layer made the round-trip without error: each
                # episode took at least one step.
                assert all(ep["steps"] >= 1 for ep in data["episodes"])
        finally:
            _stop_server(server, thread)
