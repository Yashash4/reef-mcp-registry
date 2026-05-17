"""JSON-file-backed storage for publishers and registry entries.

We keep two top-level files under the configured data dir:

  - ``registry.json``  — array of ``RegistryEntry`` records
  - ``publishers.json`` — array of ``Publisher`` records

Each load/save acquires a re-entrant lock so concurrent FastAPI requests don't
corrupt the file. Writes are atomic on POSIX + Windows via "write to temp,
rename" with ``os.replace`` (atomic on both platforms).

This is not a production database. It's the centerpiece-demo store that
trivially survives container restarts, is greppable, and can be inspected by
hand during the recorded demo.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable

from app.models import Publisher, RegistryEntry


class FileStore:
    """Mutex-protected file-backed storage."""

    def __init__(self, data_dir: str | os.PathLike[str]) -> None:
        self._dir = Path(data_dir).resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._registry_path = self._dir / "registry.json"
        self._publishers_path = self._dir / "publishers.json"
        self._lock = threading.RLock()
        # Ensure files exist (empty array) — keeps the rest of the code simple.
        if not self._registry_path.exists():
            self._atomic_write(self._registry_path, [])
        if not self._publishers_path.exists():
            self._atomic_write(self._publishers_path, [])

    # ------------------------------------------------------------------
    # Disk helpers
    # ------------------------------------------------------------------

    def _atomic_write(self, path: Path, payload: list[dict]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, path)

    def _load_raw(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            # File-store corruption is a fail-closed situation — better to
            # surface than to silently silently re-seed and lose state.
            raise RuntimeError(f"corrupt store at {path}: {e}") from e
        if not isinstance(data, list):
            raise RuntimeError(f"store {path} must contain a JSON array")
        return data

    # ------------------------------------------------------------------
    # Publishers
    # ------------------------------------------------------------------

    def list_publishers(self) -> list[Publisher]:
        with self._lock:
            return [Publisher(**row) for row in self._load_raw(self._publishers_path)]

    def get_publisher(self, publisher_id: str) -> Publisher | None:
        for p in self.list_publishers():
            if p.publisher_id == publisher_id:
                return p
        return None

    def upsert_publisher(self, publisher: Publisher) -> Publisher:
        with self._lock:
            rows = self._load_raw(self._publishers_path)
            rows = [r for r in rows if r.get("publisher_id") != publisher.publisher_id]
            rows.append(publisher.model_dump(mode="json"))
            self._atomic_write(self._publishers_path, rows)
            return publisher

    # ------------------------------------------------------------------
    # Registry entries
    # ------------------------------------------------------------------

    def list_entries(self) -> list[RegistryEntry]:
        with self._lock:
            return [RegistryEntry(**row) for row in self._load_raw(self._registry_path)]

    def find_entry(self, mcp_name: str, version: str) -> RegistryEntry | None:
        mcp_name_lc = mcp_name.lower()
        for e in self.list_entries():
            if e.manifest.mcpName == mcp_name_lc and e.manifest.version == version:
                return e
        return None

    def find_any_version(self, mcp_name: str) -> list[RegistryEntry]:
        mcp_name_lc = mcp_name.lower()
        return [e for e in self.list_entries() if e.manifest.mcpName == mcp_name_lc]

    def upsert_entry(self, entry: RegistryEntry) -> RegistryEntry:
        with self._lock:
            rows = self._load_raw(self._registry_path)
            rows = [
                r
                for r in rows
                if not (
                    r.get("manifest", {}).get("mcpName") == entry.manifest.mcpName
                    and r.get("manifest", {}).get("version") == entry.manifest.version
                )
            ]
            rows.append(entry.model_dump(mode="json"))
            self._atomic_write(self._registry_path, rows)
            return entry

    def bulk_upsert_entries(self, entries: Iterable[RegistryEntry]) -> None:
        with self._lock:
            entries = list(entries)
            if not entries:
                return
            rows = self._load_raw(self._registry_path)
            keys = {(e.manifest.mcpName, e.manifest.version) for e in entries}
            rows = [
                r
                for r in rows
                if (
                    r.get("manifest", {}).get("mcpName"),
                    r.get("manifest", {}).get("version"),
                )
                not in keys
            ]
            rows.extend(e.model_dump(mode="json") for e in entries)
            self._atomic_write(self._registry_path, rows)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    @property
    def data_dir(self) -> Path:
        return self._dir

    def count_entries(self) -> int:
        with self._lock:
            return len(self._load_raw(self._registry_path))

    def count_publishers(self) -> int:
        with self._lock:
            return len(self._load_raw(self._publishers_path))
