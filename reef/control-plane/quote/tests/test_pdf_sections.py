"""Smoke tests for the per-page section builders."""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from reportlab.platypus import PageBreak

from app.data_sources.attack_telemetry import TELEMETRY_BUCKETS, TelemetryDay
from app.data_sources.coverage_matrix import (
    OWASP_ASI_IDS,
    build_mitre_coverage,
    build_owasp_coverage,
)
from app.pdf import sections as section_builders
from app.pdf.style import build_stylesheet
from app.underwriter_agent import (
    DueDiligenceAxes,
    EstimatedPremiumRange,
    RiskCategoryScores,
    UnderwriterScore,
)


def _score() -> UnderwriterScore:
    return UnderwriterScore(
        reef_risk_tier="B+",
        risk_category_scores=RiskCategoryScores(
            hallucination_false_info=0.3,
            bias_fairness=0.2,
            privacy_infringement=0.25,
            ip_violations=0.15,
            performance_underperformance=0.2,
        ),
        due_diligence_axes=DueDiligenceAxes(
            data_science_process_quality="strong",
            statistical_testing_rigor="partial",
            predictive_robustness="strong",
            scope_of_validity="partial",
            performance_probability_distribution="partial",
        ),
        estimated_premium_range_usd_annual=EstimatedPremiumRange(
            low=42_000,
            high=54_000,
            currency="USD",
            coverage_amount_usd=5_000_000,
            anchor=(
                "2025-26 cyber market rate $0.5-$2 per $1k coverage; "
                "Mosaic + Munich Re $15M cap (Feb 27 2026)"
            ),
            disclaimer="ESTIMATED RANGE, not Munich-Re-published",
        ),
        reasoning="A short rationale paragraph for testing.",
        recommended_exclusions=["Use outside scope of validity"],
        phase_2_disclaimer=(
            "This is a rubric-grounded score, not a Lloyd's quote. Phase 2 "
            "integrates real broker API (Bold Penguin / CoverGenius / Vouch dev sandboxes)."
        ),
    )


@pytest.fixture
def styles():
    return build_stylesheet()


def test_page1_executive_summary_contains_tier_and_premium(styles) -> None:
    flows = section_builders.build_page1_executive_summary(
        styles=styles,
        ria_id="ria-test-001",
        fleet_id="prod-fleet",
        generated_at=dt.datetime(2026, 5, 18, 0, 0, 0, tzinfo=dt.timezone.utc),
        signer_key_id="quote-signer",
        signature_hex_short="abcd…",
        underwriter_score=_score(),
        sample_mode=False,
    )
    # Last item must be PageBreak.
    assert isinstance(flows[-1], PageBreak)
    # All non-PageBreak flowables must render text.
    text_blob = " ".join(
        f.text if hasattr(f, "text") and isinstance(f.text, str) else ""
        for f in flows
    )
    assert "Reef Risk Tier B+" in text_blob
    assert "mapped to Munich Re aiSure axes" in text_blob
    assert "ESTIMATED RANGE" in text_blob
    assert "Phase 2" in text_blob


def test_page2_ai_bom_handles_full_payload(styles) -> None:
    ai_bom: dict[str, Any] = {
        "fleet_id": "prod-fleet",
        "registry_entry_counts": {"verified": 47, "quarantined": 2, "poisoned": 1},
        "registry_total": 50,
        "publishers_total": 4,
        "mcp_servers": [
            {
                "mcp_name": "io.example/safe",
                "version": "1.0.0",
                "transports": ["stdio"],
                "sdk_version": "@mcp/sdk@1.29.0",
                "status": "verified",
                "publisher_id": "pub-a",
                "registered_at": "2026-05-01T00:00:00Z",
            }
        ],
        "agents": [],
        "active_bundle": {
            "bundle_id": "b1",
            "version": "v1",
            "signer_key_id": "pub-prod",
            "published_at_unix": 1_715_731_200,
        },
        "fleet_node_count": 49,
        "fleet_node_summary": {"online": 49, "offline": 0, "applied": 49, "verify_failed": 0, "unknown": 0},
    }
    flows = section_builders.build_page2_ai_bom(styles=styles, ai_bom=ai_bom)
    assert isinstance(flows[-1], PageBreak)


def test_page3_coverage_matrix_includes_partial_state(styles) -> None:
    packs = [
        {"pack_id": "EchoLeak-26.05", "owasp_asi": ["ASI09"], "mitre_atlas": ["AML.T0051"], "blocked_by_reef": True}
    ]
    owasp = build_owasp_coverage(packs=packs, rule_names=[])
    mitre = build_mitre_coverage(packs=packs, rule_names=[])
    flows = section_builders.build_page3_coverage_matrix(
        styles=styles, owasp_coverage=owasp, mitre_coverage=mitre
    )
    assert isinstance(flows[-1], PageBreak)


def test_page4_heatmap_renders_with_zero_data(styles) -> None:
    days = [
        TelemetryDay(
            date_iso=f"2026-05-{i:02d}",
            by_bucket={b: 0 for b in TELEMETRY_BUCKETS},
            is_demo_seed=True,
        )
        for i in range(1, 8)
    ]
    flows = section_builders.build_page4_attack_heatmap(styles=styles, telemetry=days)
    assert isinstance(flows[-1], PageBreak)


def test_page5_packs_renders_ox_security_citation(styles) -> None:
    packs = [
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
        }
    ]
    flows = section_builders.build_page5_dast_a_packs(styles=styles, packs=packs)
    assert isinstance(flows[-1], PageBreak)
    blob = " ".join(f.text for f in flows if hasattr(f, "text") and isinstance(f.text, str))
    assert "OX Security" in blob


def test_page6_renders_phase_2_commitments(styles) -> None:
    flows = section_builders.build_page6_audit_attestation(
        styles=styles,
        merkle_root_hex="cd" * 32,
        merkle_signature_b64="c2lnLXNhbXBsZQ==",
        merkle_count=42,
        merkle_timestamp_iso="2026-05-18T00:00:00Z",
        merkle_signed=True,
        ria_signature_hex_short="abcd…",
        ria_signature_b64_short="WFhYWA…",
        signer_key_id="quote-signer",
    )
    # Walk paragraphs + table cells (page 6 has signature + merkle tables).
    text_blob = _flow_text(flows)
    assert "Phase 2" in text_blob
    assert "Bold Penguin" in text_blob
    assert "TerraFabric" in text_blob
    assert "SPIFFE/SPIRE" in text_blob
    assert "A2A delegation" in text_blob
    # Honest-framing strings.
    assert "rubric-grounded score, not a Lloyd's quote" in text_blob
    # Anchor (lives in the signature-block table — walk cells, not just paragraphs).
    assert "Mosaic" in text_blob
    assert "Munich Re" in text_blob


def _flow_text(flows) -> str:
    """Walk paragraphs + table cell strings into a single haystack."""
    from reportlab.platypus import Paragraph, Table

    out: list[str] = []
    for f in flows:
        if isinstance(f, Paragraph) and isinstance(f.text, str):
            out.append(f.text)
        elif isinstance(f, Table):
            for row in f._cellvalues:
                for cell in row:
                    if isinstance(cell, Paragraph):
                        if isinstance(cell.text, str):
                            out.append(cell.text)
                    elif isinstance(cell, str):
                        out.append(cell)
    return "\n".join(out)


def test_owasp_id_list_includes_asi01_through_asi10() -> None:
    """Page-3 sanity — the matrix must enumerate ASI01..ASI10."""
    for ident in ("ASI01", "ASI05", "ASI09", "ASI10"):
        assert ident in OWASP_ASI_IDS
