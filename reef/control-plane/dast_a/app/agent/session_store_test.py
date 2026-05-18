"""Unit tests for the bounded Gemini red-team session store."""
from __future__ import annotations

import datetime as dt

import pytest

from app.agent.gemini_red import RedTeamRound, SessionResult
from app.agent.session_store import RedTeamSessionStore


def _make_session(session_id: str, *, rounds: int = 1) -> SessionResult:
    now = dt.datetime.now(tz=dt.timezone.utc)
    return SessionResult(
        session_id=session_id,
        started_at=now,
        finished_at=now,
        victim_url="http://stub",
        reef_on=False,
        rounds=[
            RedTeamRound(
                round_index=i,
                template="markdown_image",
                host="attacker.example.com",
                encoding="raw",
                secret_fragment="sk",
                payload_prefix="p",
                payload="payload",
                browser_status_code=200,
                response_text="ok",
                screenshot_b64=None,
                exfil_succeeded=False,
                exfil_destination=None,
                exfil_url=None,
                secret_fragment_visible=False,
                reasoning="",
                payload_signature=f"sig-{i}",
            )
            for i in range(rounds)
        ],
        succeeded=False,
        first_success_round=None,
        novel_signatures=[],
        pro_call_count=1,
    )


class TestRedTeamSessionStore:
    def test_add_and_get_round_trip(self) -> None:
        store = RedTeamSessionStore(max_sessions=3)
        s = _make_session("sess-1")
        store.add(s)
        retrieved = store.get("sess-1")
        assert retrieved is s
        assert len(store) == 1

    def test_get_missing_returns_none(self) -> None:
        store = RedTeamSessionStore(max_sessions=3)
        assert store.get("not-there") is None

    def test_lru_evicts_oldest_when_over_capacity(self) -> None:
        store = RedTeamSessionStore(max_sessions=2)
        store.add(_make_session("a"))
        store.add(_make_session("b"))
        store.add(_make_session("c"))
        # "a" should be evicted.
        assert store.get("a") is None
        assert store.get("b") is not None
        assert store.get("c") is not None
        assert len(store) == 2

    def test_access_bumps_recency(self) -> None:
        store = RedTeamSessionStore(max_sessions=2)
        store.add(_make_session("a"))
        store.add(_make_session("b"))
        # Touching "a" bumps it to MRU; adding "c" should evict "b" now.
        store.get("a")
        store.add(_make_session("c"))
        assert store.get("a") is not None
        assert store.get("b") is None
        assert store.get("c") is not None

    def test_session_ids_returns_insertion_order(self) -> None:
        store = RedTeamSessionStore(max_sessions=3)
        store.add(_make_session("a"))
        store.add(_make_session("b"))
        store.add(_make_session("c"))
        assert store.session_ids() == ["a", "b", "c"]

    def test_re_adding_existing_id_bumps_recency_without_growing(self) -> None:
        store = RedTeamSessionStore(max_sessions=2)
        store.add(_make_session("a"))
        store.add(_make_session("b"))
        # Re-add "a" — it should become MRU; "b" stays second.
        store.add(_make_session("a", rounds=2))
        assert len(store) == 2
        # Verify the new copy replaced the old one (rounds count differs).
        latest = store.get("a")
        assert latest is not None
        assert len(latest.rounds) == 2
        # Adding "c" should now evict "b" (LRU), not "a".
        store.add(_make_session("c"))
        assert store.get("a") is not None
        assert store.get("b") is None
        assert store.get("c") is not None

    def test_max_sessions_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            RedTeamSessionStore(max_sessions=0)
