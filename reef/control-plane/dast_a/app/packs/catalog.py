"""Attack-pack catalog storage.

The catalog persists to a JSON file under ``REEF_DAST_A_DATA_DIR/packs.json``.
Writes are mutex-protected; reads are list copies so callers can mutate
freely. The store is intentionally simple — no SQLite, no migrations — so
the demo path works on a fresh checkout without setup.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
from pathlib import Path
from typing import Iterable, Optional

from app.packs.schema import AttackPack

logger = logging.getLogger("dast_a.packs")


class PackNotFound(LookupError):
    """Raised by :meth:`PackCatalog.get` when an id doesn't exist."""


@dataclasses.dataclass
class PackCatalogStats:
    total: int
    by_source: dict[str, int]
    by_blocked_status: dict[str, int]


class PackCatalog:
    """Mutex-protected pack store with JSON-file persistence."""

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        self._lock = threading.RLock()
        self._data_dir = Path(
            data_dir
            or os.environ.get("REEF_DAST_A_DATA_DIR", "./data")
        ).resolve()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._path = self._data_dir / "packs.json"
        self._packs: dict[str, AttackPack] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public mutators / queries
    # ------------------------------------------------------------------
    def put(self, pack: AttackPack) -> None:
        with self._lock:
            self._packs[pack.pack_id] = pack
            self._persist()

    def put_if_absent(self, pack: AttackPack) -> bool:
        with self._lock:
            if pack.pack_id in self._packs:
                return False
            self._packs[pack.pack_id] = pack
            self._persist()
            return True

    def upsert_many(self, packs: Iterable[AttackPack]) -> int:
        count = 0
        with self._lock:
            for pack in packs:
                self._packs[pack.pack_id] = pack
                count += 1
            self._persist()
        return count

    def get(self, pack_id: str) -> AttackPack:
        with self._lock:
            try:
                return self._packs[pack_id]
            except KeyError as exc:  # pragma: no cover - exercised by tests
                raise PackNotFound(pack_id) from exc

    def list(
        self, *, page: int = 1, page_size: int = 100
    ) -> tuple[list[AttackPack], int]:
        """Return ``(page_of_packs, total)``.

        Pages are 1-indexed. ``page_size`` must be in ``[1, 1000]``.
        """
        if page < 1:
            raise ValueError("page must be >= 1")
        if page_size < 1 or page_size > 1000:
            raise ValueError("page_size must be between 1 and 1000")
        with self._lock:
            sorted_packs = sorted(
                self._packs.values(),
                key=lambda p: p.discovered_at,
                reverse=True,
            )
            total = len(sorted_packs)
            start = (page - 1) * page_size
            end = start + page_size
            return sorted_packs[start:end], total

    def signatures(self) -> tuple[str, ...]:
        """Return the canonical payload signatures across all packs.

        Used by the gym env's LP diversity penalty so RL doesn't keep
        rediscovering already-catalogued attacks.
        """
        with self._lock:
            return tuple(
                p.evidence.payload_signature
                for p in self._packs.values()
                if p.evidence and p.evidence.payload_signature
            )

    def stats(self) -> PackCatalogStats:
        with self._lock:
            by_source: dict[str, int] = {}
            by_block: dict[str, int] = {}
            for p in self._packs.values():
                by_source[p.source.value] = by_source.get(p.source.value, 0) + 1
                key = "blocked" if p.blocked_by_reef else "unblocked"
                by_block[key] = by_block.get(key, 0) + 1
            return PackCatalogStats(
                total=len(self._packs),
                by_source=by_source,
                by_blocked_status=by_block,
            )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                return
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "pack catalog at %s unreadable (%r); starting empty",
                self._path,
                exc,
            )
            return
        if not isinstance(data, list):
            logger.warning(
                "pack catalog at %s has unexpected shape; ignoring",
                self._path,
            )
            return
        for entry in data:
            try:
                pack = AttackPack.model_validate(entry)
            except Exception as exc:  # noqa: BLE001 - surface in log, keep going
                logger.warning(
                    "skipping malformed pack entry: %r (%r)", entry, exc
                )
                continue
            self._packs[pack.pack_id] = pack

    def _persist(self) -> None:
        # Atomic write via tmp+rename to avoid half-written files on crash.
        tmp = self._path.with_suffix(".json.tmp")
        payload = [p.model_dump(mode="json") for p in self._packs.values()]
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)
