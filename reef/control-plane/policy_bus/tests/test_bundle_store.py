"""Tests for app.store.bundle_store.BundleStore."""

from __future__ import annotations

import base64
import time
from pathlib import Path

import pytest

from app.models.bundle import BundleRecord, BundleScope
from app.models.fleet import NodeIdentity
from app.store.bundle_store import BundleStore


def _make_record(
    bundle_id: str = "bundle-1",
    version: str = "v1",
    scope: BundleScope | None = None,
    yaml: bytes = b"version: '1.0'\n",
) -> BundleRecord:
    return BundleRecord(
        bundle_id=bundle_id,
        version=version,
        scope=scope or BundleScope(),
        bundle_yaml_b64=base64.b64encode(yaml).decode("ascii"),
        signature_b64=base64.b64encode(b"x" * 64).decode("ascii"),
        signer_key_id="prod-signer",
        published_at_unix=int(time.time()),
    )


@pytest.mark.asyncio
async def test_add_and_get(tmp_path: Path) -> None:
    store = BundleStore(tmp_path / "bundles.jsonl")
    await store.add(_make_record("bundle-1", "v1"))
    rec = store.get("bundle-1")
    assert rec is not None
    assert rec.version == "v1"
    assert store.count() == 1


@pytest.mark.asyncio
async def test_replay_on_restart(tmp_path: Path) -> None:
    """Records persisted on disk are replayed into the in-memory index."""
    p = tmp_path / "bundles.jsonl"
    store1 = BundleStore(p)
    await store1.add(_make_record("bundle-1", "v1"))
    await store1.add(_make_record("bundle-2", "v2"))

    # New store instance over the same file.
    store2 = BundleStore(p)
    assert store2.count() == 2
    assert store2.get("bundle-1") is not None
    assert store2.get("bundle-2") is not None


@pytest.mark.asyncio
async def test_applicable_for_full_fleet_scope(tmp_path: Path) -> None:
    """A bundle with empty scope (full fleet) applies to every node."""
    store = BundleStore(tmp_path / "bundles.jsonl")
    await store.add(_make_record("global", "v1", scope=BundleScope()))
    identity = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    applicable = list(store.applicable_for(identity, current_version=""))
    assert len(applicable) == 1
    assert applicable[0].bundle_id == "global"


@pytest.mark.asyncio
async def test_applicable_for_region_scope(tmp_path: Path) -> None:
    """Region-scoped bundle applies only to that region."""
    store = BundleStore(tmp_path / "bundles.jsonl")
    await store.add(
        _make_record(
            "us-east-only",
            "v1",
            scope=BundleScope(fleet_id="prod-fleet", region_id="us-east"),
        )
    )

    in_scope = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    out_scope = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-west",
        site_id="site-04",
        node_id="node-04-01",
    )

    assert len(list(store.applicable_for(in_scope, ""))) == 1
    assert len(list(store.applicable_for(out_scope, ""))) == 0


@pytest.mark.asyncio
async def test_applicable_for_skip_current_version(tmp_path: Path) -> None:
    """A node already at the bundle's version is NOT re-sent."""
    store = BundleStore(tmp_path / "bundles.jsonl")
    await store.add(_make_record("global", "v7"))
    identity = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    assert len(list(store.applicable_for(identity, "v7"))) == 0
    assert len(list(store.applicable_for(identity, "v6"))) == 1


@pytest.mark.asyncio
async def test_new_bundle_wakes_event(tmp_path: Path) -> None:
    """Subscribers waiting on the event are woken by a new publish."""
    store = BundleStore(tmp_path / "bundles.jsonl")
    ev = store.wait_event()
    assert not ev.is_set()
    await store.add(_make_record("bundle-1", "v1"))
    # The event we captured fired (was .set() before being replaced).
    assert ev.is_set()


@pytest.mark.asyncio
async def test_recipient_counters(tmp_path: Path) -> None:
    store = BundleStore(tmp_path / "bundles.jsonl")
    await store.add(_make_record("bundle-1"))
    store.increment_recipient_targeted("bundle-1")
    store.increment_recipient_targeted("bundle-1")
    store.increment_recipient_applied("bundle-1")
    store.increment_recipient_failed("bundle-1")
    rec = store.get("bundle-1")
    assert rec is not None
    assert rec.recipients_targeted == 2
    assert rec.recipients_applied == 1
    assert rec.recipients_failed == 1


@pytest.mark.asyncio
async def test_expired_bundle_filtered_out(tmp_path: Path) -> None:
    """Bundles past expires_at_unix are not yielded."""
    store = BundleStore(tmp_path / "bundles.jsonl")
    expired = BundleRecord(
        bundle_id="expired-1",
        version="v0",
        scope=BundleScope(),
        bundle_yaml_b64=base64.b64encode(b"yaml: ok\n").decode("ascii"),
        signature_b64=base64.b64encode(b"x" * 64).decode("ascii"),
        signer_key_id="prod-signer",
        published_at_unix=int(time.time()) - 7200,
        expires_at_unix=int(time.time()) - 3600,
    )
    await store.add(expired)
    identity = NodeIdentity(
        fleet_id="prod-fleet",
        region_id="us-east",
        site_id="site-01",
        node_id="node-01-01",
    )
    assert len(list(store.applicable_for(identity, ""))) == 0


def test_corrupt_jsonl_surfaces(tmp_path: Path) -> None:
    """A non-JSON line in the file surfaces as RuntimeError, not silently."""
    p = tmp_path / "bundles.jsonl"
    p.write_text("this is not json\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="corrupt"):
        BundleStore(p)
