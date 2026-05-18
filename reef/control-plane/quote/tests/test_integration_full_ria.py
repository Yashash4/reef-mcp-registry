"""End-to-end integration test for the RIA generator.

Follows the 9-step assertion list in the A-10 spec:

1. Stub Atlas /registry/entries to return 47 + 2 + 1 entries
2. Stub policy bus /fleet to return 49 nodes
3. Stub policy bus /bundles to return current version + hash
4. Stub DAST-A /packs to return 4 seed packs
5. Stub the Merkle root (real signed-root tested in audit_root_test.go)
6. Generate RIA → assert PDF generates without errors, 6 pages,
   ed25519 signature embedded + detached `.sig` file
7. Verify signature
8. Assert PDF text contains the required honest-framing strings
9. Assert PDF text does NOT contain forbidden strings
"""
from __future__ import annotations

from pathlib import Path

import pypdf
import pytest

from app.data_sources.audit_root import SignedMerkleRoot
from app.ria_generator import (
    RIAArtifact,
    RIAGenerateOptions,
    SampleUnderwriterAgent,
    generate_ria,
)
from app.ria_signer import RIASigner


# ---------------------------------------------------------------------------
# Stubs (steps 1–5)
# ---------------------------------------------------------------------------


def _atlas_stub_47_2_1() -> dict:
    entries = []
    publishers = [
        {
            "publisher_id": "modelcontextprotocol",
            "fingerprint": "fp-mcp",
            "scopes": ["io.github.modelcontextprotocol.*"],
        }
    ]
    # 47 verified
    for i in range(47):
        entries.append(
            {
                "registry_id": f"reg-{i}",
                "manifest": {
                    "mcpName": f"io.example/svr-{i:02d}",
                    "version": "1.0.0",
                    "transports": ["stdio"],
                    "sdk_version": "@mcp/sdk@1.29.0",
                },
                "publisher_id": "modelcontextprotocol",
                "status": "verified",
                "registered_at": "2026-05-01T00:00:00+00:00",
            }
        )
    # 2 quarantined
    for i in range(2):
        entries.append(
            {
                "registry_id": f"reg-q-{i}",
                "manifest": {
                    "mcpName": f"io.example/q-{i:02d}",
                    "version": "1.0.0",
                    "transports": ["stdio"],
                    "sdk_version": "@mcp/sdk@1.29.0",
                },
                "publisher_id": "modelcontextprotocol",
                "status": "quarantined",
                "registered_at": "2026-04-30T00:00:00+00:00",
            }
        )
    # 1 poisoned
    entries.append(
        {
            "registry_id": "reg-p-0",
            "manifest": {
                "mcpName": "com.attacker/evil",
                "version": "0.5.0",
                "transports": ["stdio"],
                "sdk_version": "@mcp/sdk@0.5.0",
            },
            "publisher_id": "modelcontextprotocol",
            "status": "poisoned",
            "registered_at": "2026-04-16T00:00:00+00:00",
            "poisoned_reason": "MCP-RCE-26.04 vulnerable SDK",
        }
    )
    return {
        "healthz": {
            "status": "ok",
            "registry_entries": {"verified": 47, "quarantined": 2, "poisoned": 1},
            "total_entries": 50,
            "publishers": 1,
        },
        "entries": entries,
        "publishers": publishers,
    }


def _policy_bus_stub_49_nodes() -> dict:
    nodes = []
    for site in range(1, 8):  # 7 sites
        for node in range(1, 8):  # 7 nodes per site
            nodes.append(
                {
                    "identity": {
                        "fleet_id": "prod-fleet",
                        "region_id": ("us-east", "us-west", "eu-west")[site % 3],
                        "site_id": f"site-{site:02d}",
                        "node_id": f"node-{site:02d}-{node:02d}",
                    },
                    "online": True,
                    "last_ack_status": "applied",
                    "last_applied_version": "v1",
                    "last_applied_bundle_id": "bundle-int-test",
                }
            )
    bundle_yaml = (
        "ingress_rules:\n"
        "- name: block_prompt_injection\n"
        "- name: review_high_asi_ewma\n"
        "- name: mcp_bind_denied_by_registry\n"
        "- name: markdown_exfil_modify\n"
        "- name: svid_required\n"
        "- name: rate_limit_per_identity\n"
    )
    return {
        "healthz": {
            "status": "ok",
            "active_subscribers": 49,
            "active_bundles": 1,
            "fleet_node_count": 49,
        },
        "fleet": {"fleet_id": "prod-fleet", "nodes": nodes},
        "bundles": [
            {
                "bundle_id": "bundle-int-test",
                "version": "v1",
                "signer_key_id": "publisher-prod",
                "published_at_unix": 1_715_731_200,
                "scope": {"fleet_id": "prod-fleet"},
                "bundle_yaml": bundle_yaml,
                "bundle_hash_sha256": "deadbeef" * 8,
            }
        ],
    }


def _dast_a_stub_4_seed_packs() -> dict:
    return {
        "total": 4,
        "page": 1,
        "page_size": 100,
        "packs": [
            {
                "pack_id": "MCP-RCE-26.04",
                "name": "MCP STDIO Command Execution",
                "discovered_by": "DAST-A | OX Security (April 2026 disclosure)",
                "owasp_asi": ["ASI09", "ASI10"],
                "mitre_atlas": ["AML.T0010", "AML.T0050"],
                "blocked_by_reef": True,
                "ox_security_citation": (
                    "OX Security disclosed April 16 2026. 7,000+ vulnerable MCP servers, "
                    "150 million+ downloads at risk."
                ),
            },
            {
                "pack_id": "EchoLeak-26.05",
                "name": "EchoLeak — Zero-Click Copilot Markdown Exfil",
                "discovered_by": "DAST-A | Aim Labs (CVE-2025-32711 disclosure, June 2025)",
                "owasp_asi": ["ASI09", "ASI02"],
                "mitre_atlas": ["AML.T0051"],
                "blocked_by_reef": True,
            },
            {
                "pack_id": "MarkdownExfil-26.05",
                "name": "URL-Encoded Markdown Exfil (DAST-A synthetic)",
                "discovered_by": "DAST-A (synthetic — RL search against test fixture)",
                "owasp_asi": ["ASI09"],
                "mitre_atlas": ["AML.T0051"],
                "blocked_by_reef": True,
            },
            {
                "pack_id": "ToolChain-Drift-26.04",
                "name": "Multi-Turn Tool-Chain Drift (DAST-A synthetic)",
                "discovered_by": "DAST-A (synthetic — RL search against test fixture)",
                "owasp_asi": ["ASI01", "ASI05"],
                "mitre_atlas": ["AML.T0051"],
                "blocked_by_reef": True,
            },
        ],
    }


def _merkle_stub() -> SignedMerkleRoot:
    return SignedMerkleRoot(
        root_hex="11" * 32,
        signature_b64="aGVsbG93b3JsZA==",  # decorative
        count=4321,
        timestamp_iso="2026-05-18T01:23:45Z",
        signed=True,
        dir="/tmp/audit-int-test",
    )


# ---------------------------------------------------------------------------
# The 9 assertions
# ---------------------------------------------------------------------------


@pytest.fixture
def signer(tmp_path: Path) -> RIASigner:
    return RIASigner(
        priv_key_path=str(tmp_path / "signer.key"),
        pub_key_path=str(tmp_path / "signer.pub"),
        signer_key_id="reef-int-test-signer",
    )


@pytest.fixture
def artifact(tmp_path: Path, signer: RIASigner) -> RIAArtifact:
    opts = RIAGenerateOptions(
        fleet_id="prod-fleet",
        audit_window_days=30,
        coverage_amount_usd=5_000_000,
        data_dir=str(tmp_path / "data"),
        signer=signer,
        underwriter=SampleUnderwriterAgent(coverage_amount_usd=5_000_000),
        atlas_payload_override=_atlas_stub_47_2_1(),
        policy_bus_payload_override=_policy_bus_stub_49_nodes(),
        dast_a_payload_override=_dast_a_stub_4_seed_packs(),
        merkle_override=_merkle_stub(),
        include_demo_seed_telemetry=True,
        force_sample_mode=True,
    )
    return generate_ria(opts)


def _extract_text(artifact: RIAArtifact) -> str:
    reader = pypdf.PdfReader(str(artifact.pdf_path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_step6_pdf_generates_with_6_pages_and_detached_sig(artifact: RIAArtifact) -> None:
    assert artifact.pdf_path.exists()
    assert artifact.sig_path.exists()
    assert artifact.sig_path.name.endswith(".pdf.sig")
    assert artifact.pdf_bytes.startswith(b"%PDF")
    reader = pypdf.PdfReader(str(artifact.pdf_path))
    assert len(reader.pages) == 6
    # ed25519 signature surface.
    assert len(artifact.signature_hex) == 128
    assert len(artifact.signature_b64) > 40  # rough — base64 of 64 raw bytes


def test_step7_signature_verifies(artifact: RIAArtifact, signer: RIASigner) -> None:
    pdf_bytes = artifact.pdf_path.read_bytes()
    sig_b64 = artifact.sig_path.read_text(encoding="ascii").strip()
    assert signer.verify(pdf_bytes, sig_b64) is True


def test_step8_pdf_text_contains_required_strings(artifact: RIAArtifact) -> None:
    text = _extract_text(artifact)
    # Required strings per spec.
    assert "Reef Risk Tier" in text
    assert "Munich Re aiSure axes" in text
    assert "Mosaic" in text and "Munich Re" in text and "$15" in text
    # Some PDF text extractors lose the punctuation between "ESTIMATED" and "RANGE".
    assert "ESTIMATED RANGE" in text or "ESTIMATED  RANGE" in text
    assert "not Munich-Re-published" in text
    assert "Phase 2 integrates real broker API" in text or (
        "Phase 2" in text and "broker API" in text
    )
    # OX Security April 2026 citation. pypdf may not preserve "April 16 2026"
    # exactly across line wraps, so we assert on substrings the wrapping
    # cannot scramble.
    assert "OX Security" in text
    assert "April" in text and "2026" in text


def test_step9_pdf_does_not_contain_forbidden_strings(artifact: RIAArtifact) -> None:
    text = _extract_text(artifact)
    # Must NOT appear (positive context).
    assert "Klaimee-grounded" not in text
    assert "Lloyd's quote" not in text or "not a Lloyd's quote" in text
    assert "Munich-Re-approved control" not in text


def test_score_summary_is_tier_b_plus_premium_42_54k(artifact: RIAArtifact) -> None:
    score = artifact.score
    assert score.reef_risk_tier == "B+"
    assert score.estimated_premium_range_usd_annual.low == 42_000
    assert score.estimated_premium_range_usd_annual.high == 54_000
    assert score.estimated_premium_range_usd_annual.coverage_amount_usd == 5_000_000


def test_sample_watermark_is_emitted_when_sample_mode(artifact: RIAArtifact) -> None:
    # The sample watermark "SAMPLE" word is drawn on the canvas. pypdf's
    # extract_text() picks it up on every page; that's the auditor's view.
    text = _extract_text(artifact)
    assert "SAMPLE" in text
    # The header_ctx mode hint must also surface (page 1 "Mode" row).
    assert "SAMPLE (no live Gemini API key)" in text


def test_artifact_envelope_carries_all_fields(artifact: RIAArtifact) -> None:
    assert artifact.fleet_id == "prod-fleet"
    assert artifact.signer_key_id == "reef-int-test-signer"
    assert artifact.pdf_sha256_hex == _sha256_hex(artifact.pdf_path.read_bytes())
    assert artifact.merkle.root_hex == "11" * 32
    assert artifact.merkle.count == 4321


def _sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()
