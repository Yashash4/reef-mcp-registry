"""Tests for app.store.fleet_store.FleetStore + default_seed_nodes."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.fleet import NodeIdentity
from app.store.fleet_store import FleetStore, default_seed_nodes


def test_default_seed_nodes_count() -> None:
    nodes = default_seed_nodes()
    assert len(nodes) == 49  # 7 sites × 7 nodes
    fleets = {n.identity.fleet_id for n in nodes}
    assert fleets == {"prod-fleet"}
    regions = {n.identity.region_id for n in nodes}
    assert regions == {"us-east", "us-west", "eu-west"}
    sites = {n.identity.site_id for n in nodes}
    assert len(sites) == 7
    assert all(n.online is False for n in nodes)


def test_default_seed_nodes_have_svid_subject() -> None:
    nodes = default_seed_nodes()
    for n in nodes:
        assert n.identity.svid_subject.startswith("spiffe://reef/prod-fleet/")


@pytest.mark.asyncio
async def test_seed_if_empty_idempotent(tmp_path: Path) -> None:
    store = FleetStore(tmp_path / "fleet.json")
    n1 = await store.seed_if_empty(default_seed_nodes())
    assert n1 == 49
    n2 = await store.seed_if_empty(default_seed_nodes())
    assert n2 == 0  # already seeded
    assert store.count() == 49


@pytest.mark.asyncio
async def test_mark_subscribed_then_disconnected(tmp_path: Path) -> None:
    store = FleetStore(tmp_path / "fleet.json")
    await store.seed_if_empty(default_seed_nodes())
    ident = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    await store.mark_subscribed(ident)
    rec = store.get(ident)
    assert rec is not None
    assert rec.online is True
    assert rec.last_subscribe_unix > 0
    await store.mark_disconnected(ident)
    rec = store.get(ident)
    assert rec is not None
    assert rec.online is False


@pytest.mark.asyncio
async def test_record_ack_applied(tmp_path: Path) -> None:
    store = FleetStore(tmp_path / "fleet.json")
    await store.seed_if_empty(default_seed_nodes())
    ident = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    rec = await store.record_ack(ident, "bundle-1", "v1", "applied", "OK")
    assert rec.last_applied_version == "v1"
    assert rec.last_applied_bundle_id == "bundle-1"
    assert rec.last_ack_status == "applied"
    assert rec.last_ack_unix > 0


@pytest.mark.asyncio
async def test_record_ack_verify_failed_does_not_update_applied(tmp_path: Path) -> None:
    """verify_failed acks must NOT bump last_applied_* — that's the
    fail-safe contract for the 3-node propagation test."""
    store = FleetStore(tmp_path / "fleet.json")
    await store.seed_if_empty(default_seed_nodes())
    ident = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    await store.record_ack(ident, "bundle-1", "v1", "applied", "OK")
    await store.record_ack(ident, "bundle-2", "v2", "verify_failed", "bad sig")
    rec = store.get(ident)
    assert rec is not None
    assert rec.last_applied_version == "v1"  # unchanged
    assert rec.last_applied_bundle_id == "bundle-1"
    assert rec.last_ack_status == "verify_failed"


@pytest.mark.asyncio
async def test_snapshot_filter_by_fleet(tmp_path: Path) -> None:
    store = FleetStore(tmp_path / "fleet.json")
    await store.seed_if_empty(default_seed_nodes())
    snap = store.snapshot("prod-fleet")
    assert snap.fleet_id == "prod-fleet"
    assert snap.node_count == 49
    assert snap.region_count == 3
    assert snap.site_count == 7

    snap_empty = store.snapshot("nonexistent")
    assert snap_empty.node_count == 0


@pytest.mark.asyncio
async def test_upsert_unknown_node(tmp_path: Path) -> None:
    """An unknown identity submitted via Subscribe is auto-added."""
    store = FleetStore(tmp_path / "fleet.json")
    ident = NodeIdentity(
        fleet_id="new-fleet",
        region_id="apac",
        site_id="site-tokyo",
        node_id="node-tokyo-01",
    )
    rec = await store.upsert(ident)
    assert rec.identity == ident
    assert store.count() == 1


@pytest.mark.asyncio
async def test_persist_round_trip(tmp_path: Path) -> None:
    """Records persisted to disk are reloaded on a fresh FleetStore."""
    p = tmp_path / "fleet.json"
    store1 = FleetStore(p)
    await store1.seed_if_empty(default_seed_nodes())
    ident = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    await store1.record_ack(ident, "bundle-1", "v1", "applied", "OK")

    store2 = FleetStore(p)
    assert store2.count() == 49
    rec = store2.get(ident)
    assert rec is not None
    assert rec.last_applied_version == "v1"
