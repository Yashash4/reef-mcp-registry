"""Bounded in-memory store for recent Gemini-Pro red-team sessions.

The ``POST /dast-a/red-team/gemini-run`` route caches each completed
:class:`SessionResult` here so the
``GET /dast-a/red-team/sessions/{id}/screenshots`` route can replay the
captured Playwright screenshots + Pro multimodal classifier verdicts.

Sessions can carry several megabytes of PNG data (one screenshot per
round, base64-encoded). The store is therefore a bounded LRU keyed on
session_id, with the cap tunable via ``REEF_GEMINI_SESSION_CACHE_SIZE``
(default 16). It is process-local — there is no persistence across
restarts. Phase 2 work moves this onto a real artifact store; for the
hackathon window the in-memory cache is sufficient.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Optional

from app.agent.gemini_red import SessionResult


class RedTeamSessionStore:
    """Thread-safe bounded LRU of :class:`SessionResult` keyed by session_id."""

    def __init__(self, *, max_sessions: int = 16) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be >= 1")
        self._max = int(max_sessions)
        self._sessions: "OrderedDict[str, SessionResult]" = OrderedDict()
        self._lock = threading.Lock()

    def add(self, session: SessionResult) -> None:
        """Insert (or refresh) a session, evicting the oldest if over capacity."""
        with self._lock:
            if session.session_id in self._sessions:
                # Move to end (most recently used)
                self._sessions.move_to_end(session.session_id)
            self._sessions[session.session_id] = session
            while len(self._sessions) > self._max:
                self._sessions.popitem(last=False)

    def get(self, session_id: str) -> Optional[SessionResult]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                # Bump LRU recency on access.
                self._sessions.move_to_end(session_id)
            return session

    def session_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


__all__ = ["RedTeamSessionStore"]
