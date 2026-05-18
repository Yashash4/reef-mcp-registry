"""File-backed JSONL bundle store.

Append-only — one JSON record per line. The newest record per
(scope_key, version) wins; older records are kept for audit history.
On startup we replay the file into an in-memory index for O(1) lookup.

Concurrency: asyncio.Lock around the writer + an asyncio Event the
service uses to wake idle Subscribe streams when a new bundle lands.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Iterator

from app.models.bundle import BundleRecord, BundleScope


class BundleStore:
    """JSONL bundle store with subscribe-side fan-out support."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        self._lock = asyncio.Lock()
        # In-memory index: bundle_id → record. Multiple records with the
        # same bundle_id (e.g. a re-publish) are kept by retaining the
        # most recent.
        self._by_bundle_id: dict[str, BundleRecord] = {}
        # bundles_in_order keeps insertion order for replay; the
        # Subscribe stream iterates this to find applicable bundles.
        self._in_order: list[str] = []
        # version_seq is the monotonic sequence number a Subscribe stream
        # uses to detect newer bundles after it's already mid-flight.
        self._version_seq: int = 0
        # New-bundle event for fan-out.
        self._new_bundle_event = asyncio.Event()
        self._replay()

    # ---- Replay ----------------------------------------------------------

    def _replay(self) -> None:
        if not self._path.exists():
            return
        text = self._path.read_text(encoding="utf-8")
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                raw = json.loads(ln)
                rec = BundleRecord(**raw)
            except (json.JSONDecodeError, ValueError) as e:
                # A corrupt line is surfaced loudly rather than silently
                # discarded — the bus operator needs to investigate.
                raise RuntimeError(
                    f"bundle store: corrupt line in {self._path}: {e}: {ln[:80]}"
                ) from e
            if rec.bundle_id not in self._by_bundle_id:
                self._in_order.append(rec.bundle_id)
            self._by_bundle_id[rec.bundle_id] = rec
            self._version_seq += 1

    # ---- Mutators --------------------------------------------------------

    async def add(self, record: BundleRecord) -> None:
        """Append a new bundle record and wake Subscribe streams."""
        async with self._lock:
            line = json.dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                ensure_ascii=False,
            )
            # Synchronous write — write_text is acceptable here because the
            # bundles file is tiny and admin Publishes are rare.
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
            if record.bundle_id not in self._by_bundle_id:
                self._in_order.append(record.bundle_id)
            self._by_bundle_id[record.bundle_id] = record
            self._version_seq += 1
            # Wake any sleeping Subscribe streams.
            self._new_bundle_event.set()
            self._new_bundle_event = asyncio.Event()

    def increment_recipient_applied(self, bundle_id: str) -> None:
        rec = self._by_bundle_id.get(bundle_id)
        if rec is None:
            return
        rec.recipients_applied += 1

    def increment_recipient_failed(self, bundle_id: str) -> None:
        rec = self._by_bundle_id.get(bundle_id)
        if rec is None:
            return
        rec.recipients_failed += 1

    def increment_recipient_targeted(self, bundle_id: str) -> None:
        rec = self._by_bundle_id.get(bundle_id)
        if rec is None:
            return
        rec.recipients_targeted += 1

    # ---- Read accessors --------------------------------------------------

    def get(self, bundle_id: str) -> BundleRecord | None:
        return self._by_bundle_id.get(bundle_id)

    def all(self) -> list[BundleRecord]:
        return [self._by_bundle_id[bid] for bid in self._in_order]

    def count(self) -> int:
        return len(self._by_bundle_id)

    def version_seq(self) -> int:
        return self._version_seq

    def applicable_for(
        self,
        scope_identity,
        current_version: str,
    ) -> Iterator[BundleRecord]:
        """Yield all bundles whose scope matches scope_identity AND whose
        version != current_version (the simplest "newer than" semantics —
        version strings are operator-controlled, so we use !=).

        Yields in publish order.
        """
        for bid in self._in_order:
            rec = self._by_bundle_id[bid]
            if rec.status not in ("active",):
                continue
            if rec.is_expired():
                continue
            if not rec.scope.matches(scope_identity):
                continue
            if rec.version == current_version:
                continue
            yield rec

    def latest_applicable(
        self,
        scope_identity,
        current_version: str,
    ) -> BundleRecord | None:
        """Return the most recently published applicable bundle (or None)."""
        latest: BundleRecord | None = None
        for rec in self.applicable_for(scope_identity, current_version):
            latest = rec
        return latest

    # ---- Subscribe wake-up -----------------------------------------------

    def wait_event(self) -> asyncio.Event:
        """Return the current wake-up event. Callers use as
        ``ev = store.wait_event(); await ev.wait()``."""
        return self._new_bundle_event

    @property
    def path(self) -> Path:
        return self._path
