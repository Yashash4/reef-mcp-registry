"""Seed tests — 47/2/1 split must reproduce on every run."""

from __future__ import annotations

from app.policy import is_vulnerable_sdk
from app.seed import seed_demo


def test_seed_produces_47_2_1(tmp_paths, store):
    counts = seed_demo(store, tmp_paths["keys"])
    assert counts["verified"] == 47
    assert counts["quarantined"] == 2
    assert counts["poisoned"] == 1


def test_seed_is_idempotent(tmp_paths, store):
    seed_demo(store, tmp_paths["keys"])
    first = store.count_entries()
    seed_demo(store, tmp_paths["keys"])
    second = store.count_entries()
    assert first == second == 50


def test_poisoned_entry_uses_vulnerable_sdk(tmp_paths, store):
    seed_demo(store, tmp_paths["keys"])
    poisoned = [e for e in store.list_entries() if e.status == "poisoned"]
    assert len(poisoned) == 1
    p = poisoned[0]
    assert p.manifest.mcpName == "com.attacker-example/evil-server"
    assert p.manifest.version == "0.5.0"
    assert "0.5.0" in p.manifest.sdk_version
    assert is_vulnerable_sdk(p.manifest.sdk_version)
    assert "sdk_version_policy" in p.checks_failed


def test_quarantined_entries_have_reasons(tmp_paths, store):
    seed_demo(store, tmp_paths["keys"])
    q = [e for e in store.list_entries() if e.status == "quarantined"]
    assert len(q) == 2
    for e in q:
        assert e.quarantined_reason


def test_verified_entries_pass_publisher_provenance(tmp_paths, store):
    seed_demo(store, tmp_paths["keys"])
    from app.crypto import verify_manifest_signature

    publishers = {p.publisher_id: p for p in store.list_publishers()}
    for e in store.list_entries():
        if e.status != "verified":
            continue
        pub = publishers[e.publisher_id]
        ok = verify_manifest_signature(
            e.manifest.model_dump(mode="json"),
            e.signature_hex,
            pub.public_key_hex,
        )
        assert ok, f"signature did not verify for {e.registry_id}"


def test_seed_logs_fingerprint(tmp_paths, store, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="atlas-test")
    logger = logging.getLogger("atlas-test")
    seed_demo(store, tmp_paths["keys"], logger=logger)
    matched = [r for r in caplog.records if "seeded 47 verified" in r.getMessage()]
    assert matched, f"missing seed log line; saw {[r.message for r in caplog.records]}"
