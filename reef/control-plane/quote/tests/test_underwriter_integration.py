"""Integration tests for the underwriter agent — full flow with mocked SDK."""
from __future__ import annotations

import json
from typing import Any

import pytest

from app.underwriter_agent import (
    InvalidUnderwriterOutput,
    UnderwriterAgent,
    UnderwriterScore,
)


def _profile(level: str) -> dict[str, Any]:
    base = {
        "ai_bom": {
            "agents": [],
            "models": [],
            "mcp_servers": [],
            "tools": [],
            "policy_versions": ["v1"],
        },
        "audit_window": {
            "days": 30,
            "merkle_root_sha256": "ab" * 32,
            "total_events": 0,
            "denied": 0,
        },
        "owasp_coverage": {},
        "mitre_atlas_coverage": {},
        "attack_pack_list": [],
    }
    if level == "low":
        base["ai_bom"]["agents"] = ["compliant-summarizer"]
        base["ai_bom"]["mcp_servers"] = [{"name": "trusted", "signed": True}]
        base["owasp_coverage"] = {f"ASI0{i}": "covered" for i in range(1, 8)}
        base["attack_pack_list"] = [
            {"pack_id": "MCP-RCE-26.04"},
            {"pack_id": "EchoLeak-26.05"},
        ]
    elif level == "medium":
        base["ai_bom"]["agents"] = ["partial-coverage"]
        base["ai_bom"]["mcp_servers"] = [{"name": "mixed", "signed": False}]
        base["owasp_coverage"] = {f"ASI0{i}": "partial" for i in range(1, 8)}
        base["attack_pack_list"] = [{"pack_id": "MCP-RCE-26.04"}]
    else:  # high
        base["ai_bom"]["agents"] = ["unaudited"]
        base["ai_bom"]["mcp_servers"] = [{"name": "untrusted", "signed": False}]
    return base


def _output_for_level(level: str) -> dict[str, Any]:
    tier_map = {"low": "A-", "medium": "B", "high": "C-"}
    cat_map = {
        "low": (0.1, 0.1, 0.1, 0.1, 0.1),
        "medium": (0.4, 0.4, 0.4, 0.4, 0.4),
        "high": (0.8, 0.8, 0.8, 0.8, 0.8),
    }
    axis_map = {
        "low": "strong",
        "medium": "partial",
        "high": "weak",
    }
    price_map = {"low": (5000, 18000), "medium": (18000, 55000), "high": (60000, 110000)}
    return {
        "reef_risk_tier": tier_map[level],
        "risk_category_scores": {
            "hallucination_false_info": cat_map[level][0],
            "bias_fairness": cat_map[level][1],
            "privacy_infringement": cat_map[level][2],
            "ip_violations": cat_map[level][3],
            "performance_underperformance": cat_map[level][4],
        },
        "due_diligence_axes": {
            "data_science_process_quality": axis_map[level],
            "statistical_testing_rigor": axis_map[level],
            "predictive_robustness": axis_map[level],
            "scope_of_validity": axis_map[level],
            "performance_probability_distribution": axis_map[level],
        },
        "estimated_premium_range_usd_annual": {
            "low": price_map[level][0],
            "high": price_map[level][1],
            "currency": "USD",
            "coverage_amount_usd": 5_000_000,
            "anchor": (
                "2025-26 cyber market rate $0.5-$2 per $1k coverage; "
                "Mosaic + Munich Re $15M cap (Feb 27 2026)"
            ),
            "disclaimer": "ESTIMATED RANGE, not Munich-Re-published",
        },
        "reasoning": f"This is a synthetic {level}-risk profile.",
        "recommended_exclusions": ["Use outside scope of validity"],
        "phase_2_disclaimer": (
            "This is a rubric-grounded score, not a Lloyd's quote. Phase 2 "
            "integrates real broker API (Bold Penguin / CoverGenius / Vouch "
            "dev sandboxes)."
        ),
    }


class FakeProClient:
    def __init__(self, *, responses_by_level: dict[str, dict[str, Any]]) -> None:
        self.responses_by_level = responses_by_level
        self.calls: list[dict[str, Any]] = []
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def generate_score(
        self, *, system_prompt: str, user_message: str
    ) -> dict[str, Any]:
        self._call_count += 1
        self.calls.append({"system_prompt": system_prompt, "user_message": user_message})
        # Pick a response based on whether the user_message names "compliant",
        # "partial-coverage" or "unaudited" — keeps the integration realistic.
        if "compliant-summarizer" in user_message:
            return self.responses_by_level["low"]
        if "partial-coverage" in user_message:
            return self.responses_by_level["medium"]
        return self.responses_by_level["high"]


@pytest.fixture()
def fake_client() -> FakeProClient:
    return FakeProClient(
        responses_by_level={
            "low": _output_for_level("low"),
            "medium": _output_for_level("medium"),
            "high": _output_for_level("high"),
        }
    )


class TestEndToEnd:
    def test_three_risk_levels_each_return_validated_scores(
        self, fake_client: FakeProClient
    ) -> None:
        agent = UnderwriterAgent(pro_client=fake_client)
        results: list[UnderwriterScore] = []
        for level in ("low", "medium", "high"):
            score = agent.score(**_profile(level))
            results.append(score)
        assert {r.reef_risk_tier for r in results} == {"A-", "B", "C-"}
        assert fake_client.call_count == 3

    def test_all_three_outputs_carry_phase_2_disclaimer(
        self, fake_client: FakeProClient
    ) -> None:
        agent = UnderwriterAgent(pro_client=fake_client)
        for level in ("low", "medium", "high"):
            score = agent.score(**_profile(level))
            assert "Phase 2" in score.phase_2_disclaimer
            assert "broker API" in score.phase_2_disclaimer
            assert "rubric-grounded" in score.phase_2_disclaimer.lower()

    def test_all_three_outputs_use_mapped_to_munich_re_aisure_axes(
        self, fake_client: FakeProClient
    ) -> None:
        agent = UnderwriterAgent(pro_client=fake_client)
        for level in ("low", "medium", "high"):
            score = agent.score(**_profile(level))
            assert "mapped to Munich Re aiSure axes" in score.tier_label_with_framing
            assert score.reef_risk_tier in {"A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-"}

    def test_all_three_outputs_anchor_on_mosaic_munich_re_cap(
        self, fake_client: FakeProClient
    ) -> None:
        agent = UnderwriterAgent(pro_client=fake_client)
        for level in ("low", "medium", "high"):
            score = agent.score(**_profile(level))
            anchor = score.estimated_premium_range_usd_annual.anchor
            assert "Mosaic" in anchor
            assert "Munich Re" in anchor
            assert "15M" in anchor

    def test_user_message_contains_all_inputs(
        self, fake_client: FakeProClient
    ) -> None:
        agent = UnderwriterAgent(pro_client=fake_client)
        agent.score(**_profile("medium"))
        last_call = fake_client.calls[-1]
        user = last_call["user_message"]
        snapshot = json.loads(user.split("DEPLOYMENT SNAPSHOT:")[-1].strip())
        assert "ai_bom" in snapshot
        assert "audit_window" in snapshot
        assert "owasp_coverage" in snapshot
        assert "mitre_atlas_coverage" in snapshot
        assert "attack_pack_list" in snapshot
        assert "mosaic_munich_re_cap_anchor_usd" in snapshot
        assert snapshot["mosaic_munich_re_cap_anchor_usd"] == 15_000_000


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class _MalformedPro:
    def __init__(self, *, payload: dict[str, Any]) -> None:
        self.payload = payload
        self._calls = 0

    @property
    def call_count(self) -> int:
        return self._calls

    def generate_score(self, **kw: Any) -> dict[str, Any]:
        self._calls += 1
        return self.payload


class TestFailureModes:
    def test_missing_axis_raises_invalid_output(self) -> None:
        bad = _output_for_level("low")
        del bad["due_diligence_axes"]["scope_of_validity"]
        agent = UnderwriterAgent(pro_client=_MalformedPro(payload=bad))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_profile("low"))

    def test_missing_risk_category_raises(self) -> None:
        bad = _output_for_level("medium")
        del bad["risk_category_scores"]["privacy_infringement"]
        agent = UnderwriterAgent(pro_client=_MalformedPro(payload=bad))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_profile("medium"))

    def test_negative_premium_low_raises(self) -> None:
        bad = _output_for_level("high")
        bad["estimated_premium_range_usd_annual"]["low"] = -1
        agent = UnderwriterAgent(pro_client=_MalformedPro(payload=bad))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_profile("high"))
