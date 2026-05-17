"""FileStore tests — atomic writes, mutex protection, lookup semantics."""

from __future__ import annotations

import threading

from app.crypto import generate_keypair
from app.models import Manifest, Publisher, RegistryEntry, Tool
from app.store import FileStore


def _make_publisher(idx: int = 0) -> Publisher:
    _, pk = generate_keypair()
    return Publisher(
        publisher_id=f"pub-{idx}",
        display_name=f"Publisher {idx}",
        public_key_hex=pk,
        scopes=[f"com.example.pub{idx}.*"],
        created_at="2026-05-18T00:00:00+00:00",
        revoked=False,
        fingerprint=pk[:16],
    )


def _make_entry(idx: int = 0, mcp_name: str = "com.example/weather-mcp", version: str = "1.0.0") -> RegistryEntry:
    return RegistryEntry(
        registry_id=f"reg-{idx:04d}",
        manifest=Manifest(
            mcpName=mcp_name,
            version=version,
            transports=["http"],
            tools=[Tool(name="ping")],
            capabilities=["tools"],
            sdk_version="@modelcontextprotocol/sdk@1.29.0",
        ),
        publisher_id=f"pub-{idx}",
        signature_hex="ab" * 32,
        status="verified",
        registered_at="2026-05-18T00:00:00+00:00",
        checks_passed=["publisher_provenance"],
        checks_failed=[],
    )


def test_store_creates_files_on_init(tmp_path):
    s = FileStore(tmp_path / "data")
    assert (tmp_path / "data" / "registry.json").exists()
    assert (tmp_path / "data" / "publishers.json").exists()
    assert s.count_entries() == 0
    assert s.count_publishers() == 0


def test_publisher_roundtrip(tmp_path):
    s = FileStore(tmp_path / "data")
    p = _make_publisher(0)
    s.upsert_publisher(p)
    again = s.get_publisher(p.publisher_id)
    assert again is not None
    assert again.public_key_hex == p.public_key_hex


def test_entry_roundtrip(tmp_path):
    s = FileStore(tmp_path / "data")
    e = _make_entry(0)
    s.upsert_entry(e)
    found = s.find_entry(e.manifest.mcpName, e.manifest.version)
    assert found is not None
    assert found.registry_id == e.registry_id


def test_find_any_version_returns_all_versions(tmp_path):
    s = FileStore(tmp_path / "data")
    s.upsert_entry(_make_entry(0, version="1.0.0"))
    s.upsert_entry(_make_entry(1, version="2.0.0"))
    others = s.find_any_version("com.example/weather-mcp")
    assert {e.manifest.version for e in others} == {"1.0.0", "2.0.0"}


def test_concurrent_writes_dont_corrupt(tmp_path):
    s = FileStore(tmp_path / "data")
    N = 64

    def writer(i: int):
        s.upsert_entry(_make_entry(i, mcp_name=f"com.example/server-{i}", version="1.0.0"))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = s.list_entries()
    # Every distinct mcpName should appear exactly once.
    names = {e.manifest.mcpName for e in entries}
    assert len(names) == N, f"missing entries; got {len(names)} != {N}"


def test_corrupt_store_surfaces(tmp_path):
    s = FileStore(tmp_path / "data")
    s.upsert_entry(_make_entry(0))
    (tmp_path / "data" / "registry.json").write_text("not json", encoding="utf-8")
    import pytest

    with pytest.raises(RuntimeError):
        s.list_entries()


def test_upsert_replaces_same_key(tmp_path):
    s = FileStore(tmp_path / "data")
    a = _make_entry(0)
    s.upsert_entry(a)
    b = _make_entry(0)
    b = b.model_copy(update={"signature_hex": "cd" * 32})
    s.upsert_entry(b)
    found = s.find_entry(a.manifest.mcpName, a.manifest.version)
    assert found is not None
    assert found.signature_hex == "cd" * 32
    assert s.count_entries() == 1
