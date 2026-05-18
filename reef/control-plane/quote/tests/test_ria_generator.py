"""Unit tests for the RIA generator entrypoint."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.data_sources.audit_root import SignedMerkleRoot, stub_signed_merkle_root
from app.ria_generator import (
    RIAArtifact,
    RIAGenerateOptions,
    SampleUnderwriterAgent,
    ensure_sample_ria,
    generate_ria,
)
from app.ria_signer import RIASigner


def _stub_payloads():
    atlas = {
        "healthz": {
            "registry_entries": {"verified": 47, "quarantined": 2, "poisoned": 1},
            "total_entries": 50,
            "publishers": 4,
        },
        "entries": [],
        "publishers": [],
    }
    bus = {
        "healthz": {"status": "ok"},
        "fleet": {"fleet_id": "prod-fleet", "nodes": []},
        "bundles": [
            {
                "bundle_id": "b1",
                "version": "v1",
                "signer_key_id": "pub-prod",
                "published_at_unix": 1_715_731_200,
                "scope": {"fleet_id": "prod-fleet"},
                "bundle_yaml": (
                    "ingress_rules:\n- name: markdown_exfil_modify\n"
                    "- name: mcp_bind_denied_by_registry\n"
                ),
            }
        ],
    }
    dast = {
        "total": 1,
        "packs": [
            {
                "pack_id": "MCP-RCE-26.04",
                "name": "MCP STDIO Command Execution",
                "discovered_by": "DAST-A | OX Security (April 2026 disclosure)",
                "owasp_asi": ["ASI09", "ASI10"],
                "mitre_atlas": ["AML.T0010", "AML.T0050"],
                "blocked_by_reef": True,
                "ox_security_citation": (
                    "OX Security disclosed April 16 2026. 7,000+ vulnerable servers."
                ),
            }
        ],
    }
    return atlas, bus, dast


def _opts(tmp_path: Path) -> RIAGenerateOptions:
    atlas, bus, dast = _stub_payloads()
    signer = RIASigner(
        priv_key_path=str(tmp_path / "k.key"),
        pub_key_path=str(tmp_path / "k.pub"),
        signer_key_id="test-signer",
    )
    return RIAGenerateOptions(
        fleet_id="prod-fleet",
        audit_window_days=5,
        coverage_amount_usd=5_000_000,
        data_dir=str(tmp_path / "data"),
        signer=signer,
        underwriter=SampleUnderwriterAgent(coverage_amount_usd=5_000_000),
        atlas_payload_override=atlas,
        policy_bus_payload_override=bus,
        dast_a_payload_override=dast,
        merkle_override=stub_signed_merkle_root(),
        force_sample_mode=True,
    )


def test_generate_ria_returns_artifact_with_signed_pdf(tmp_path: Path) -> None:
    artifact = generate_ria(_opts(tmp_path))
    assert isinstance(artifact, RIAArtifact)
    assert artifact.pdf_path.exists()
    assert artifact.sig_path.exists()
    assert artifact.pdf_bytes.startswith(b"%PDF")
    # 64-byte signature → 128 hex chars.
    assert len(artifact.signature_hex) == 128
    # The detached .sig file matches the artifact's b64.
    sig_text = artifact.sig_path.read_text(encoding="ascii").strip()
    assert sig_text == artifact.signature_b64


def test_generate_ria_uses_underwriter_output_for_pdf(tmp_path: Path) -> None:
    opts = _opts(tmp_path)
    artifact = generate_ria(opts)
    # The sample agent returns Tier B+.
    assert artifact.score.reef_risk_tier == "B+"
    # And the signature truncates cleanly.
    assert len(artifact.signature_hex) == 128


def test_generate_ria_sets_sample_mode_flag(tmp_path: Path) -> None:
    opts = _opts(tmp_path)
    artifact = generate_ria(opts)
    assert artifact.sample_mode is True


def test_ensure_sample_ria_writes_committed_sample(tmp_path: Path) -> None:
    samples = tmp_path / "samples"
    artifact = ensure_sample_ria(samples_dir=samples)
    sample_pdf = samples / "sample-ria.pdf"
    sample_sig = samples / "sample-ria.pdf.sig"
    assert sample_pdf.exists()
    assert sample_sig.exists()
    assert artifact.pdf_path == sample_pdf
    assert artifact.sig_path == sample_sig
    assert artifact.score.reef_risk_tier == "B+"
    assert artifact.sample_mode is True


def test_ensure_sample_ria_overwrites_existing(tmp_path: Path) -> None:
    samples = tmp_path / "samples"
    samples.mkdir()
    target = samples / "sample-ria.pdf"
    target.write_bytes(b"%PDF stale")
    ensure_sample_ria(samples_dir=samples)
    assert target.read_bytes().startswith(b"%PDF")
    assert target.read_bytes() != b"%PDF stale"


def test_generate_ria_rejects_when_no_fallback_and_live_data_missing(tmp_path: Path) -> None:
    # No overrides + no env Atlas → AtlasUnreachable surfaces.
    from app.data_sources import AtlasUnreachable
    opts = RIAGenerateOptions(
        fleet_id="prod-fleet",
        data_dir=str(tmp_path / "data"),
        signer=RIASigner(
            priv_key_path=str(tmp_path / "k.key"),
            pub_key_path=str(tmp_path / "k.pub"),
        ),
        underwriter=SampleUnderwriterAgent(),
        merkle_override=stub_signed_merkle_root(),
        fallback_on_data_source_error=False,
    )
    with pytest.raises(AtlasUnreachable):
        generate_ria(opts)
