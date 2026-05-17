"""Append-only JSONL audit logger.

Every register/verify/publisher decision becomes one JSON line. Audit IDs are
``audit-<32-hex>`` so they're easy to grep against. The pipeline uses
``audit_id`` as the correlation ID in HTTP responses, and the Lobster Trap
sidecar forwards it in its own pipeline event.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    """Concurrency-safe JSONL audit log.

    Writes are serialised on a single lock. Failure to write the audit line is
    surfaced (RuntimeError) — never silenced — because a missing audit trail
    is a bigger problem than a slow request.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Touch the file so subsequent reads (tests) always find something.
        if not self._path.exists():
            self._path.touch()
        self._lock = threading.Lock()

    @staticmethod
    def new_audit_id() -> str:
        return "audit-" + secrets.token_hex(16)

    def log(self, event: dict[str, Any]) -> str:
        """Persist one event, returning its audit_id.

        ``event`` is augmented with ``audit_id`` and ``ts`` (epoch seconds) if
        not already set. The caller is expected to supply at minimum:
        ``kind`` (register/verify/publisher), ``decision`` or ``status``, and
        any free-form metadata (mcpName, version, agent_id, reason, etc.).
        """
        audit_id = event.get("audit_id") or self.new_audit_id()
        record = dict(event)
        record["audit_id"] = audit_id
        record.setdefault("ts", time.time())
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        return audit_id

    @property
    def path(self) -> Path:
        return self._path

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the last ``n`` audit lines parsed as dicts (debug helper)."""
        if not self._path.exists():
            return []
        text = self._path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        out: list[dict[str, Any]] = []
        for ln in lines[-n:]:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                # Surface as a structured event rather than ignoring — bad
                # JSON in audit indicates an out-of-band tamper.
                out.append({"_corrupt": True, "_raw": ln})
        return out
