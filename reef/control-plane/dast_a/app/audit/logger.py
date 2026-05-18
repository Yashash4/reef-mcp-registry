"""JSONL audit logger for training episodes + discovered attacks.

Every event lands in ``REEF_DAST_A_DATA_DIR/audit.jsonl`` (one line each).
Writes are mutex-protected and flushed immediately so the demo recording
can ``tail -f`` the file.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("dast_a.audit")


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    """One audit-log entry."""

    timestamp: dt.datetime
    kind: str
    payload: dict[str, Any]

    def to_json(self) -> str:
        record = {
            "ts": self.timestamp.isoformat(),
            "kind": self.kind,
            "payload": self.payload,
        }
        return json.dumps(record, sort_keys=True, default=_json_default)


def _json_default(value: Any) -> Any:
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    return str(value)


class AuditLogger:
    """Append-only JSONL audit logger.

    Multi-process safety: the underlying FS append-mode handle relies on
    POSIX-style appends being atomic for line-sized writes. Within a single
    process, the threading mutex serialises writes from the FastAPI request
    handlers and the PPO training loop.
    """

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self._lock = threading.RLock()
        default = (
            Path(os.environ.get("REEF_DAST_A_DATA_DIR", "./data")) / "audit.jsonl"
        )
        self._path = Path(path or default).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def log(self, kind: str, payload: dict[str, Any]) -> AuditEvent:
        event = AuditEvent(
            timestamp=dt.datetime.now(tz=dt.timezone.utc),
            kind=kind,
            payload=payload,
        )
        line = event.to_json()
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.write("\n")
        return event

    def tail(self, *, max_lines: int = 100) -> list[AuditEvent]:
        """Read the last ``max_lines`` events (used by the API for replay)."""
        if not self._path.exists():
            return []
        with self._lock:
            raw = self._path.read_text(encoding="utf-8")
        if not raw.strip():
            return []
        lines = raw.strip().splitlines()[-max_lines:]
        events: list[AuditEvent] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed audit line %r (%r)", line, exc)
                continue
            try:
                events.append(
                    AuditEvent(
                        timestamp=dt.datetime.fromisoformat(record["ts"]),
                        kind=str(record["kind"]),
                        payload=dict(record.get("payload") or {}),
                    )
                )
            except (KeyError, ValueError) as exc:
                logger.warning(
                    "skipping audit line with bad schema: %r (%r)", line, exc
                )
        return events
