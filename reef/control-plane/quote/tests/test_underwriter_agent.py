"""Unit tests for the Munich Re-grounded underwriter agent."""
from __future__ import annotations

from typing import Any

import pytest

from app.underwriter_agent import (
    DEFAULT_COVERAGE_AMOUNT_USD,
    DUE_DILIGENCE_AXES,
    GeminiCallFailed,
    InvalidUnderwriterOutput,
    MissingGeminiAPIKey,
    MissingGeminiProModel,
    MOSAIC_MUNICH_RE_CAP_USD,
    PHASE_2_DISCLAIMER,
    RISK_CATEGORIES,
    UnderwriterAgent,
    UnderwriterScore,
    VALID_TIERS,
    _enforce_constraints,
    _enforce_post_validation_invariants,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _golden_low_risk_output() -> dict[str, Any]:
    return {
        "reef_risk_tier": "A-",
        "risk_category_scores": {
            "hallucination_false_info": 0.12,
            "bias_fairness": 0.18,
            "privacy_infringement": 0.10,
            "ip_violations": 0.15,
            "performance_underperformance": 0.08,
        },
        "due_diligence_axes": {
            "data_science_process_quality": "strong",
            "statistical_testing_rigor": "strong",
            "predictive_robustness": "strong",
            "scope_of_validity": "partial",
            "performance_probability_distribution": "strong",
        },
        "estimated_premium_range_usd_annual": {
            "low": 5000,
            "high": 18000,
            "currency": "USD",
            "coverage_amount_usd": 5_000_000,
            "anchor": (
                "2025-26 cyber market rate $0.5-$2 per $1k coverage; "
                "Mosaic + Munich Re $15M cap (Feb 27 2026)"
            ),
            "disclaimer": "ESTIMATED RANGE, not Munich-Re-published",
        },
        "reasoning": (
            "Strong evidence on the data-science-process axis, statistical-"
            "testing rigor robust, predictive robustness confirmed via "
            "30-day attack telemetry. Scope of validity partial — the "
            "deployment is narrowly scoped to summarization-class workloads."
        ),
        "recommended_exclusions": [
            "Use outside summarization-class workloads",
            "Use without Reef policy attached",
        ],
        "phase_2_disclaimer": PHASE_2_DISCLAIMER,
    }


def _golden_medium_risk_output() -> dict[str, Any]:
    out = _golden_low_risk_output()
    out.update(
        {
            "reef_risk_tier": "B",
            "risk_category_scores": {
                "hallucination_false_info": 0.45,
                "bias_fairness": 0.40,
                "privacy_infringement": 0.55,
                "ip_violations": 0.30,
                "performance_underperformance": 0.40,
            },
            "due_diligence_axes": {
                "data_science_process_quality": "partial",
                "statistical_testing_rigor": "partial",
                "predictive_robustness": "partial",
                "scope_of_validity": "partial",
                "performance_probability_distribution": "weak",
            },
        }
    )
    out["estimated_premium_range_usd_annual"]["low"] = 18000
    out["estimated_premium_range_usd_annual"]["high"] = 55000
    return out


def _golden_high_risk_output() -> dict[str, Any]:
    out = _golden_low_risk_output()
    out.update(
        {
            "reef_risk_tier": "C-",
            "risk_category_scores": {
                "hallucination_false_info": 0.80,
                "bias_fairness": 0.75,
                "privacy_infringement": 0.92,
                "ip_violations": 0.70,
                "performance_underperformance": 0.85,
            },
            "due_diligence_axes": {
                "data_science_process_quality": "weak",
                "statistical_testing_rigor": "weak",
                "predictive_robustness": "weak",
                "scope_of_validity": "weak",
                "performance_probability_distribution": "weak",
            },
        }
    )
    out["estimated_premium_range_usd_annual"]["low"] = 60000
    out["estimated_premium_range_usd_annual"]["high"] = 110000
    return out


class FakeProClient:
    def __init__(self, *, responses: list[dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def generate_score(
        self, *, system_prompt: str, user_message: str
    ) -> dict[str, Any]:
        self._call_count += 1
        self.calls.append((system_prompt, user_message))
        if not self._responses:
            return _golden_low_risk_output()
        return self._responses.pop(0)


def _make_inputs() -> dict[str, Any]:
    return {
        "ai_bom": {
            "agents": ["copilot-clone"],
            "models": ["gemini-2.0-flash-exp"],
            "mcp_servers": [{"name": "victim-mcp-server", "signed": True}],
            "tools": ["summarize_inbox", "fetch_url"],
            "policy_versions": ["v1.0"],
        },
        "audit_window": {
            "days": 30,
            "merkle_root_sha256": "deadbeef" * 8,
            "total_events": 1234,
            "denied": 5,
        },
        "owasp_coverage": {
            "ASI01": "covered",
            "ASI02": "covered",
            "ASI05": "covered",
            "ASI06": "covered",
        },
        "mitre_atlas_coverage": {
            "AML.T0010": "MCP-RCE-26.04",
            "AML.T0051": "EchoLeak-26.05",
        },
        "attack_pack_list": [
            {"pack_id": "MCP-RCE-26.04"},
            {"pack_id": "EchoLeak-26.05"},
        ],
    }


# ---------------------------------------------------------------------------
# Score outputs — schema + tier framing + Munich Re grounding
# ---------------------------------------------------------------------------


class TestScoreShape:
    def test_low_risk_score_validates(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        score = agent.score(**_make_inputs())
        assert isinstance(score, UnderwriterScore)
        assert score.reef_risk_tier == "A-"
        assert (
            score.tier_label_with_framing
            == "Reef Risk Tier A- mapped to Munich Re aiSure axes"
        )

    def test_medium_risk_score_validates(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_medium_risk_output()])
        )
        score = agent.score(**_make_inputs())
        assert score.reef_risk_tier == "B"
        assert score.due_diligence_axes.performance_probability_distribution == "weak"

    def test_high_risk_score_validates(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_high_risk_output()])
        )
        score = agent.score(**_make_inputs())
        assert score.reef_risk_tier == "C-"
        assert score.risk_category_scores.privacy_infringement > 0.5

    def test_all_three_risk_levels_carry_disclaimer(self) -> None:
        for payload in (
            _golden_low_risk_output(),
            _golden_medium_risk_output(),
            _golden_high_risk_output(),
        ):
            agent = UnderwriterAgent(
                pro_client=FakeProClient(responses=[payload])
            )
            score = agent.score(**_make_inputs())
            assert "Phase 2" in score.phase_2_disclaimer
            assert "broker API" in score.phase_2_disclaimer

    def test_premium_range_anchor_references_mosaic_munich_re_cap(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_medium_risk_output()])
        )
        score = agent.score(**_make_inputs())
        anchor = score.estimated_premium_range_usd_annual.anchor
        assert "Mosaic" in anchor
        assert "Munich Re" in anchor
        assert "15M" in anchor
        assert "Feb 27 2026" in anchor

    def test_premium_range_carries_estimated_disclaimer(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        score = agent.score(**_make_inputs())
        assert (
            score.estimated_premium_range_usd_annual.disclaimer
            == "ESTIMATED RANGE, not Munich-Re-published"
        )

    def test_tier_label_always_uses_munich_re_aisure_axes_framing(self) -> None:
        for payload in (
            _golden_low_risk_output(),
            _golden_medium_risk_output(),
            _golden_high_risk_output(),
        ):
            agent = UnderwriterAgent(
                pro_client=FakeProClient(responses=[payload])
            )
            score = agent.score(**_make_inputs())
            assert "mapped to Munich Re aiSure axes" in score.tier_label_with_framing


# ---------------------------------------------------------------------------
# Validation — invalid Pro outputs must raise
# ---------------------------------------------------------------------------


class TestValidation:
    def test_invalid_tier_letter_rejected(self) -> None:
        payload = _golden_low_risk_output()
        payload["reef_risk_tier"] = "ZZ"
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_invalid_axis_rating_rejected(self) -> None:
        payload = _golden_low_risk_output()
        payload["due_diligence_axes"]["scope_of_validity"] = "bogus"
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_axis_synonym_coerced_to_canonical_label(self) -> None:
        payload = _golden_low_risk_output()
        payload["due_diligence_axes"]["scope_of_validity"] = "Medium"
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        score = agent.score(**_make_inputs())
        assert score.due_diligence_axes.scope_of_validity == "partial"

    def test_risk_category_out_of_range_rejected(self) -> None:
        payload = _golden_low_risk_output()
        payload["risk_category_scores"]["bias_fairness"] = 1.5
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_premium_disclaimer_must_state_estimated_range(self) -> None:
        payload = _golden_low_risk_output()
        payload["estimated_premium_range_usd_annual"]["disclaimer"] = (
            "Per Munich Re tier B+"  # forbidden phrasing
        )
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_phase2_disclaimer_required(self) -> None:
        payload = _golden_low_risk_output()
        payload["phase_2_disclaimer"] = "no commitment"
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_premium_anchor_must_reference_mosaic_and_munich_re(self) -> None:
        payload = _golden_low_risk_output()
        payload["estimated_premium_range_usd_annual"]["anchor"] = (
            "Generic SaaS cyber pricing band"
        )
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_premium_low_greater_than_high_rejected(self) -> None:
        payload = _golden_low_risk_output()
        payload["estimated_premium_range_usd_annual"]["low"] = 100000
        payload["estimated_premium_range_usd_annual"]["high"] = 50000
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        with pytest.raises(InvalidUnderwriterOutput):
            agent.score(**_make_inputs())

    def test_tolerates_tier_with_extra_framing_text(self) -> None:
        payload = _golden_low_risk_output()
        payload["reef_risk_tier"] = "Reef Risk Tier B+ mapped to Munich Re aiSure axes"
        agent = UnderwriterAgent(pro_client=FakeProClient(responses=[payload]))
        score = agent.score(**_make_inputs())
        assert score.reef_risk_tier == "B+"


# ---------------------------------------------------------------------------
# Env-var guards
# ---------------------------------------------------------------------------


class TestEnvGuards:
    def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        from app.underwriter_agent import GoogleGenAIProClient

        with pytest.raises(MissingGeminiAPIKey):
            GoogleGenAIProClient()

    def test_missing_pro_model_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "stub-key-for-test")
        monkeypatch.delenv("GEMINI_PRO_MODEL", raising=False)
        from app.underwriter_agent import GoogleGenAIProClient

        with pytest.raises(MissingGeminiProModel):
            GoogleGenAIProClient()


# ---------------------------------------------------------------------------
# Other invariants
# ---------------------------------------------------------------------------


class TestAgentConfig:
    def test_default_coverage_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("REEF_UNDERWRITER_COVERAGE_AMOUNT_USD", raising=False)
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        assert agent.coverage_amount_usd == DEFAULT_COVERAGE_AMOUNT_USD

    def test_env_overrides_coverage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REEF_UNDERWRITER_COVERAGE_AMOUNT_USD", "12000000")
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        assert agent.coverage_amount_usd == 12_000_000

    def test_explicit_argument_overrides_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REEF_UNDERWRITER_COVERAGE_AMOUNT_USD", "12000000")
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()]),
            coverage_amount_usd=999_000,
        )
        assert agent.coverage_amount_usd == 999_000

    def test_invalid_env_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REEF_UNDERWRITER_COVERAGE_AMOUNT_USD", "not-a-number")
        with pytest.raises(Exception):
            UnderwriterAgent(
                pro_client=FakeProClient(responses=[_golden_low_risk_output()])
            )

    def test_system_prompt_contains_verbatim_risk_categories(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        prompt = agent.system_prompt
        # Verbatim Munich Re risk category names from the task spec.
        assert "Hallucination / false information" in prompt
        assert "Bias / fairness" in prompt
        assert "Privacy infringement" in prompt
        assert "IP violations" in prompt
        assert "Performance underperformance" in prompt

    def test_system_prompt_contains_verbatim_due_diligence_axes(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        prompt = agent.system_prompt
        assert "Data-science-process quality" in prompt
        assert "Statistical-testing rigor" in prompt
        assert "Predictive robustness" in prompt
        assert "Scope of validity" in prompt
        assert "Performance probability distribution" in prompt

    def test_system_prompt_bakes_in_anti_patterns(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        prompt = agent.system_prompt
        assert "Munich-Re-approved" in prompt
        assert "Tier A" in prompt or "Tier A/B/C" in prompt
        assert "ESTIMATED RANGE" in prompt

    def test_pro_call_invoked_with_full_snapshot(self) -> None:
        client = FakeProClient(responses=[_golden_low_risk_output()])
        agent = UnderwriterAgent(pro_client=client)
        agent.score(**_make_inputs())
        assert client.call_count == 1
        system_prompt, user_message = client.calls[0]
        assert "Munich Re" in system_prompt
        assert "aiSure" in system_prompt
        assert "ai_bom" in user_message
        assert "audit_window" in user_message
        assert "owasp_coverage" in user_message
        assert "mitre_atlas_coverage" in user_message
        assert "attack_pack_list" in user_message
        assert "mosaic_munich_re_cap_anchor_usd" in user_message


# ---------------------------------------------------------------------------
# Munich Re grounding hygiene
# ---------------------------------------------------------------------------


class TestMunichReGroundingHygiene:
    def test_klaimee_only_appears_in_negative_context(self) -> None:
        agent = UnderwriterAgent(
            pro_client=FakeProClient(responses=[_golden_low_risk_output()])
        )
        prompt = agent.system_prompt
        # Klaimee is allowed in the prompt ONLY as a market-demand signal /
        # explicit "do NOT use as grounding source" warning. It is NEVER
        # allowed as a positive grounding instruction.
        # Per D-007: Munich Re is the SOLE grounding source.
        # We check by line — every line that mentions Klaimee must also
        # contain at least one of these negation/market-signal tokens.
        negative_tokens = (
            "market",
            "NOT",
            "do not",
            "demand signal",
            "demand-signal",
            "grounding source",
            "lloyd",  # the original list of carriers
            "klaimee-grounded",  # appears in the anti-patterns line
        )
        for line in prompt.splitlines():
            if "Klaimee" in line:
                lower_line = line.lower()
                assert any(
                    tok.lower() in lower_line for tok in negative_tokens
                ), (
                    f"Klaimee mentioned outside of an explicit "
                    f"market-signal/anti-pattern context: {line!r}"
                )

    def test_constants_are_verbatim_munich_re_axis_names(self) -> None:
        # If anyone renames these to "Reef-flavored" labels we lose the
        # Munich Re grounding. Lock the alphabet here.
        assert RISK_CATEGORIES == (
            "hallucination_false_info",
            "bias_fairness",
            "privacy_infringement",
            "ip_violations",
            "performance_underperformance",
        )
        assert DUE_DILIGENCE_AXES == (
            "data_science_process_quality",
            "statistical_testing_rigor",
            "predictive_robustness",
            "scope_of_validity",
            "performance_probability_distribution",
        )

    def test_mosaic_cap_anchor_is_15m(self) -> None:
        assert MOSAIC_MUNICH_RE_CAP_USD == 15_000_000

    def test_constraints_helper_fills_default_premium_disclaimer(self) -> None:
        raw = _golden_low_risk_output()
        # Strip the field; the constraint helper must replace it.
        del raw["estimated_premium_range_usd_annual"]["disclaimer"]
        _enforce_constraints(raw, default_coverage_usd=5_000_000)
        assert (
            raw["estimated_premium_range_usd_annual"]["disclaimer"]
            == "ESTIMATED RANGE, not Munich-Re-published"
        )

    def test_post_validation_invariant_helper_catches_phase_2_omission(self) -> None:
        from pydantic import ValidationError

        payload = _golden_low_risk_output()
        payload["phase_2_disclaimer"] = ""
        # Field is required & non-empty? pydantic allows empty strings here
        # so we must rely on the post-validation invariant helper.
        score = UnderwriterScore.model_validate(payload)
        with pytest.raises(InvalidUnderwriterOutput):
            _enforce_post_validation_invariants(score)
