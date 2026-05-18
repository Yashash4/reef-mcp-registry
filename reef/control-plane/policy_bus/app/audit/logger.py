"""Append-only JSONL audit logger.

Mirrors `reef/control-plane/atlas/app/audit/logger.py` so operators see the
same audit shape across the control plane. Every publish, every Subscribe
stream open/close, and every Ack becomes a JSON line.

The audit_id (``audit-<32-hex>``) is returned to callers so the gRPC
PublishResponse / AckResponse can carry it back. Operators grep the bus's
audit log by audit_id when investigating fleet propagation.
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
    """Thread-safe JSONL audit log writer."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        self._lock = threading.Lock()

    @staticmethod
    def new_audit_id() -> str:
        return "audit-" + secrets.token_hex(16)

    def log(self, event: dict[str, Any]) -> str:
        """Persist one event, returning the audit_id."""
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

    def tail(self, n: int = 100) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        text = self._path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        out: list[dict[str, Any]] = []
        for ln in lines[-n:]:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                out.append({"_corrupt": True, "_raw": ln})
        return out
