"""File-backed JSON fleet store.

Persists the 49-node demo fleet (7 sites × 7 nodes × 3 regions × prod-fleet)
plus each node's last-ack metadata so the Stage UI (A-11) can paint the
stadium-wave grid. The store is small (50-ish records) so we hold all of
it in memory and rewrite the JSON file atomically on each mutation.

Concurrency: asyncio.Lock around the writer. Reads are lock-free off the
in-memory map.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from app.models.fleet import (
    AckStatus,
    FleetSnapshot,
    NodeIdentity,
    NodeRecord,
)


def default_seed_nodes(
    fleet_id: str = "prod-fleet",
    regions: tuple[str, ...] = ("us-east", "us-west", "eu-west"),
    sites_per_fleet: int = 7,
    nodes_per_site: int = 7,
) -> list[NodeRecord]:
    """Build the 49-node stadium-wave demo fleet.

    7 sites × 7 nodes = 49 nodes, distributed across the given regions
    round-robin. Each site sits in one region. The Stage UI (A-11) renders
    these as a 7×7 grid; the demo's "stadium wave" animation is the order
    in which nodes ack a freshly-published bundle.
    """
    nodes: list[NodeRecord] = []
    for site_idx in range(sites_per_fleet):
        region = regions[site_idx % len(regions)]
        site_id = f"site-{site_idx + 1:02d}"
        for node_idx in range(nodes_per_site):
            node_id = f"node-{site_idx + 1:02d}-{node_idx + 1:02d}"
            ident = NodeIdentity(
                fleet_id=fleet_id,
                region_id=region,
                site_id=site_id,
                node_id=node_id,
                svid_subject=f"spiffe://reef/{fleet_id}/{region}/{site_id}/{node_id}",
            )
            nodes.append(
                NodeRecord(
                    identity=ident,
                    last_applied_version="",
                    last_applied_bundle_id="",
                    last_ack_status="unknown",
                    last_ack_unix=0,
                    last_subscribe_unix=0,
                    online=False,
                )
            )
    return nodes


class FleetStore:
    """In-memory + JSON-file-backed fleet store."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        # key = NodeIdentity.key()
        self._by_key: dict[str, NodeRecord] = {}
        self._load()

    # ---- Persistence -----------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        text = self._path.read_text(encoding="utf-8")
        if not text.strip():
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"fleet store: corrupt JSON at {self._path}: {e}") from e
        if not isinstance(data, list):
            raise RuntimeError(f"fleet store: top-level must be array at {self._path}")
        for row in data:
            rec = NodeRecord(**row)
            self._by_key[rec.identity.key()] = rec

    async def _persist_unlocked(self) -> None:
        # Write tmp + atomic replace so a crash mid-write doesn't corrupt.
        rows = [rec.model_dump(mode="json") for rec in self._by_key.values()]
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(rows, sort_keys=True, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)

    # ---- Seed ------------------------------------------------------------

    async def seed_if_empty(self, nodes: list[NodeRecord]) -> int:
        async with self._lock:
            if self._by_key:
                return 0
            for rec in nodes:
                self._by_key[rec.identity.key()] = rec
            await self._persist_unlocked()
            return len(nodes)

    # ---- Read accessors --------------------------------------------------

    def get(self, identity: NodeIdentity) -> NodeRecord | None:
        return self._by_key.get(identity.key())

    def all(self) -> list[NodeRecord]:
        return sorted(
            self._by_key.values(),
            key=lambda r: (
                r.identity.fleet_id,
                r.identity.region_id,
                r.identity.site_id,
                r.identity.node_id,
            ),
        )

    def snapshot(self, fleet_id: str | None = None) -> FleetSnapshot:
        nodes = self.all()
        if fleet_id is not None:
            nodes = [n for n in nodes if n.identity.fleet_id == fleet_id]
        regions = {n.identity.region_id for n in nodes}
        sites = {(n.identity.region_id, n.identity.site_id) for n in nodes}
        return FleetSnapshot(
            fleet_id=fleet_id or (nodes[0].identity.fleet_id if nodes else ""),
            region_count=len(regions),
            site_count=len(sites),
            node_count=len(nodes),
            nodes=nodes,
        )

    def count(self) -> int:
        return len(self._by_key)

    # ---- Mutators --------------------------------------------------------

    async def upsert(self, identity: NodeIdentity) -> NodeRecord:
        """Insert the node if absent; refresh svid_subject if changed."""
        async with self._lock:
            key = identity.key()
            existing = self._by_key.get(key)
            if existing is None:
                rec = NodeRecord(identity=identity)
                self._by_key[key] = rec
                await self._persist_unlocked()
                return rec
            # Refresh svid_subject — the rest of the identity is the key.
            if existing.identity.svid_subject != identity.svid_subject:
                existing.identity = identity
                await self._persist_unlocked()
            return existing

    async def mark_subscribed(self, identity: NodeIdentity) -> None:
        async with self._lock:
            rec = self._by_key.get(identity.key())
            if rec is None:
                # Auto-register on first Subscribe so unrecognised nodes
                # show up in the dashboard.
                rec = NodeRecord(identity=identity)
                self._by_key[identity.key()] = rec
            rec.last_subscribe_unix = int(time.time())
            rec.online = True
            await self._persist_unlocked()

    async def mark_disconnected(self, identity: NodeIdentity) -> None:
        async with self._lock:
            rec = self._by_key.get(identity.key())
            if rec is None:
                return
            rec.online = False
            await self._persist_unlocked()

    async def record_ack(
        self,
        identity: NodeIdentity,
        bundle_id: str,
        applied_version: str,
        status: AckStatus,
        detail: str,
    ) -> NodeRecord:
        async with self._lock:
            rec = self._by_key.get(identity.key())
            if rec is None:
                rec = NodeRecord(identity=identity)
                self._by_key[identity.key()] = rec
            rec.last_ack_status = status
            rec.last_ack_detail = detail
            rec.last_ack_unix = int(time.time())
            if status == "applied":
                rec.last_applied_version = applied_version
                rec.last_applied_bundle_id = bundle_id
            await self._persist_unlocked()
            return rec

    @property
    def path(self) -> Path:
        return self._path
