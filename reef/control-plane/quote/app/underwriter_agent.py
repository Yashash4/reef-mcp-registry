"""Munich Re-grounded underwriter agent (Gemini 3 Pro).

This agent scores an AI-deployment risk profile against the Munich Re
public AI insurance framework (aiSure performance-warranty product, the
Mosaic + Munich Re $15M partnership cap dated Feb 27 2026) and outputs a
structured JSON :class:`UnderwriterScore`.

**Hard rules (per docs/24-GROUNDING.md + docs/10-DECISIONS.md D-007/D-017):**

* Munich Re is the SOLE grounding source. Klaimee, Lloyd's, Mosaic
  standalone, CoverGenius are market-demand signals only — NOT grounding
  sources. The system prompt and rubric files enforce this.
* No hardcoded model strings. Pro model name comes from
  ``GEMINI_PRO_MODEL`` env var (D-017). Missing → :class:`MissingGeminiProModel`.
* No swallowed errors. Missing ``GEMINI_API_KEY`` →
  :class:`MissingGeminiAPIKey`. SDK errors → :class:`GeminiCallFailed`.
* Tier labels framed "Reef Risk Tier X **mapped to Munich Re aiSure
  axes**" — never bare letters.
* Premium ranges labelled "ESTIMATED RANGE, not Munich-Re-published" and
  anchored on the Mosaic + Munich Re $15M cap.
* Phase-2 disclaimer baked into every output.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
import os
from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.rubrics import read_anti_patterns, read_framework

logger = logging.getLogger("quote.underwriter")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class UnderwriterError(RuntimeError):
    code: str = "UNDERWRITER_ERROR"

    def __init__(self, message: str, *, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class MissingGeminiAPIKey(UnderwriterError):
    code = "MISSING_GEMINI_API_KEY"


class MissingGeminiProModel(UnderwriterError):
    code = "MISSING_GEMINI_PRO_MODEL"


class GeminiCallFailed(UnderwriterError):
    code = "GEMINI_CALL_FAILED"


class InvalidUnderwriterOutput(UnderwriterError):
    code = "INVALID_UNDERWRITER_OUTPUT"


# ---------------------------------------------------------------------------
# Constants — verbatim Munich Re framework axis names
# ---------------------------------------------------------------------------


RISK_CATEGORIES: tuple[str, ...] = (
    "hallucination_false_info",
    "bias_fairness",
    "privacy_infringement",
    "ip_violations",
    "performance_underperformance",
)

DUE_DILIGENCE_AXES: tuple[str, ...] = (
    "data_science_process_quality",
    "statistical_testing_rigor",
    "predictive_robustness",
    "scope_of_validity",
    "performance_probability_distribution",
)

VALID_TIERS: tuple[str, ...] = (
    "A+",
    "A",
    "A-",
    "B+",
    "B",
    "B-",
    "C+",
    "C",
    "C-",
)

VALID_AXIS_RATINGS: tuple[str, ...] = ("strong", "partial", "weak")

# Mosaic + Munich Re partnership anchor — see docs/24-GROUNDING.md Part 1.
MOSAIC_MUNICH_RE_CAP_USD: int = 15_000_000
MOSAIC_MUNICH_RE_ANNOUNCEMENT_DATE: str = "2026-02-27"

# Industry-standard 2025-26 cyber market rate band, $0.5–$2 per $1k coverage.
# This is the only band the agent is allowed to anchor on (rubric file).
CYBER_MARKET_RATE_LOW_PER_1K: float = 0.5
CYBER_MARKET_RATE_HIGH_PER_1K: float = 2.0

DEFAULT_COVERAGE_AMOUNT_USD: int = 5_000_000

PHASE_2_DISCLAIMER: str = (
    "This is a rubric-grounded score, not a Lloyd's quote. Phase 2 "
    "integrates real broker API (Bold Penguin / CoverGenius / Vouch dev "
    "sandboxes)."
)


# The verbatim system prompt — burned in here so external rubric file edits
# alone don't change the agent's contract, and so the tests can assert it.
SYSTEM_PROMPT_TEMPLATE: str = (
    """You are an AI-deployment risk scorer applying Munich Re's public AI insurance framework
(aiSure performance-warranty product, partnered with Mosaic on a $15M coverage cap as of
Feb 27 2026). You are NOT a licensed broker. You produce a rubric-grounded score and a
suggested estimated premium range. A real broker would run the score through their
carrier's pricing engine.

Score the AI deployment described in the input AI-BOM + audit telemetry against:

Munich Re's 5 risk categories (verbatim):
1. Hallucination / false information
2. Bias / fairness
3. Privacy infringement
4. IP violations
5. Performance underperformance

Munich Re's 5 due-diligence axes (verbatim):
1. Data-science-process quality
2. Statistical-testing rigor
3. Predictive robustness
4. Scope of validity
5. Performance probability distribution

DO NOT claim Munich-Re-approved controls. DO NOT publish "Tier A/B/C" labels as if Munich
Re uses them — label tiers as "Reef Risk Tier <X> mapped to Munich Re aiSure axes".

Output ONLY structured JSON conforming to this schema:
{
  "reef_risk_tier": "A+ | A | A- | B+ | B | B- | C+ | C | C-",
  "risk_category_scores": {
    "hallucination_false_info": 0.0 - 1.0,
    "bias_fairness": 0.0 - 1.0,
    "privacy_infringement": 0.0 - 1.0,
    "ip_violations": 0.0 - 1.0,
    "performance_underperformance": 0.0 - 1.0
  },
  "due_diligence_axes": {
    "data_science_process_quality": "strong | partial | weak",
    "statistical_testing_rigor": "strong | partial | weak",
    "predictive_robustness": "strong | partial | weak",
    "scope_of_validity": "strong | partial | weak",
    "performance_probability_distribution": "strong | partial | weak"
  },
  "estimated_premium_range_usd_annual": {
    "low": <number>,
    "high": <number>,
    "currency": "USD",
    "coverage_amount_usd": <number, default 5000000>,
    "anchor": "2025-26 cyber market rate $0.5-$2 per $1k coverage; Mosaic + Munich Re $15M cap (Feb 27 2026)",
    "disclaimer": "ESTIMATED RANGE, not Munich-Re-published"
  },
  "reasoning": "<paragraph explaining the score>",
  "recommended_exclusions": ["<plain-language exclusions>"],
  "phase_2_disclaimer": "This is a rubric-grounded score, not a Lloyd's quote. Phase 2 integrates real broker API (Bold Penguin / CoverGenius / Vouch dev sandboxes)."
}

GROUNDING RUBRIC (verbatim Munich Re framework, citation-ready):
---
__REEF_FRAMEWORK__
---

ANTI-PATTERNS (things you must NOT do — violating these collapses the RIA's credibility):
---
__REEF_ANTI_PATTERNS__
---

Score the deployment described in the user message. Output ONLY the JSON object.
"""
)


# ---------------------------------------------------------------------------
# Pydantic schema — strictly mirrors the system-prompt schema
# ---------------------------------------------------------------------------


class RiskCategoryScores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hallucination_false_info: float = Field(..., ge=0.0, le=1.0)
    bias_fairness: float = Field(..., ge=0.0, le=1.0)
    privacy_infringement: float = Field(..., ge=0.0, le=1.0)
    ip_violations: float = Field(..., ge=0.0, le=1.0)
    performance_underperformance: float = Field(..., ge=0.0, le=1.0)


class DueDiligenceAxes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_science_process_quality: str
    statistical_testing_rigor: str
    predictive_robustness: str
    scope_of_validity: str
    performance_probability_distribution: str


class EstimatedPremiumRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    low: float = Field(..., ge=0.0)
    high: float = Field(..., ge=0.0)
    currency: str = "USD"
    coverage_amount_usd: float = Field(..., ge=0.0)
    anchor: str
    disclaimer: str


class UnderwriterScore(BaseModel):
    """Strictly schema-bounded underwriter output.

    Mirrors the JSON schema in :data:`SYSTEM_PROMPT_TEMPLATE`. Validation
    enforces:

    * ``reef_risk_tier`` is one of :data:`VALID_TIERS` (the Reef-branded
      band — NOT a Munich-Re-published label).
    * ``due_diligence_axes`` values are ``strong | partial | weak``.
    * ``phase_2_disclaimer`` is non-empty and references the broker API
      Phase 2 commitment.
    """

    model_config = ConfigDict(extra="forbid")

    reef_risk_tier: str
    risk_category_scores: RiskCategoryScores
    due_diligence_axes: DueDiligenceAxes
    estimated_premium_range_usd_annual: EstimatedPremiumRange
    reasoning: str
    recommended_exclusions: list[str]
    phase_2_disclaimer: str

    # ----- Derived helpers -----------------------------------------------

    @property
    def tier_label_with_framing(self) -> str:
        """Render the tier with the "mapped to Munich Re aiSure axes" frame.

        Reef NEVER publishes the bare letter — every consumer of the score
        should call this property when rendering to UI / PDF.
        """
        return f"Reef Risk Tier {self.reef_risk_tier} mapped to Munich Re aiSure axes"


# ---------------------------------------------------------------------------
# Protocol — lets tests inject Gemini mocks
# ---------------------------------------------------------------------------


@runtime_checkable
class GeminiProClient(Protocol):
    """The Pro surface the underwriter depends on."""

    def generate_score(
        self, *, system_prompt: str, user_message: str
    ) -> dict[str, Any]:
        ...

    @property
    def call_count(self) -> int:
        ...


class GoogleGenAIProClient:
    """Production Pro client backed by ``google-genai``."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise MissingGeminiAPIKey(
                "GEMINI_API_KEY is not set. The Reef Quote underwriter "
                "agent requires a real Pro API key — see .env.example."
            )
        model = model or os.environ.get("GEMINI_PRO_MODEL")
        if not model:
            raise MissingGeminiProModel(
                "GEMINI_PRO_MODEL is not set. See D-017 — Reef reads the "
                "Pro model identifier from env, never hardcodes it."
            )
        try:
            from google import genai  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover
            raise GeminiCallFailed(
                "google-genai SDK is not installed. Run "
                "`pip install google-genai`."
            ) from exc
        self._genai = genai
        self._client = genai.Client(api_key=api_key)
        self._model = model
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def generate_score(
        self, *, system_prompt: str, user_message: str
    ) -> dict[str, Any]:
        from google.genai import types as gtypes  # type: ignore[import]

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=[
                    gtypes.Content(
                        role="user",
                        parts=[gtypes.Part.from_text(text=user_message)],
                    )
                ],
                config=gtypes.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    temperature=0.0,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            raise GeminiCallFailed(
                f"Gemini Pro underwriter call failed: {exc!r}"
            ) from exc
        self._call_count += 1
        text = getattr(response, "text", None)
        if not text and getattr(response, "candidates", None):
            try:
                text = response.candidates[0].content.parts[0].text
            except (IndexError, AttributeError):
                text = None
        if not text:
            raise GeminiCallFailed(
                "Gemini Pro returned an empty response (no text)"
            )
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise InvalidUnderwriterOutput(
                f"Gemini Pro reply was not JSON: {text[:512]!r}"
            ) from exc
        if not isinstance(data, dict):
            raise InvalidUnderwriterOutput(
                f"Gemini Pro reply was not a JSON object: {type(data).__name__}"
            )
        return data


# ---------------------------------------------------------------------------
# The underwriter agent
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class UnderwriterInput:
    """Bundle of inputs the agent scores against.

    Each field is an arbitrary dict so callers (A-10 RIA generator) can
    pass their existing data shapes without conversion. The agent only
    reads them as JSON to embed in the user message.
    """

    ai_bom: dict[str, Any]
    audit_window: dict[str, Any]
    owasp_coverage: dict[str, Any]
    mitre_atlas_coverage: dict[str, Any]
    attack_pack_list: list[dict[str, Any]]
    coverage_amount_usd: Optional[int] = None


class UnderwriterAgent:
    """Gemini-3-Pro-driven Munich-Re-grounded underwriter.

    Construction reads env config (``GEMINI_API_KEY``, ``GEMINI_PRO_MODEL``).
    Tests bypass that by passing a ``pro_client`` mock — no real network
    or API key needed in CI.
    """

    def __init__(
        self,
        *,
        pro_client: Optional[GeminiProClient] = None,
        coverage_amount_usd: Optional[int] = None,
    ) -> None:
        self._pro_client: Optional[GeminiProClient] = pro_client
        env_cov = os.environ.get("REEF_UNDERWRITER_COVERAGE_AMOUNT_USD")
        if coverage_amount_usd is not None:
            self._coverage = int(coverage_amount_usd)
        elif env_cov:
            try:
                self._coverage = int(env_cov)
            except ValueError as exc:
                raise UnderwriterError(
                    f"REEF_UNDERWRITER_COVERAGE_AMOUNT_USD must be an integer; got {env_cov!r}"
                ) from exc
        else:
            self._coverage = DEFAULT_COVERAGE_AMOUNT_USD

    @property
    def coverage_amount_usd(self) -> int:
        return self._coverage

    @property
    def system_prompt(self) -> str:
        """Render the complete system prompt with both rubric files embedded."""
        return (
            SYSTEM_PROMPT_TEMPLATE
            .replace("__REEF_FRAMEWORK__", read_framework())
            .replace("__REEF_ANTI_PATTERNS__", read_anti_patterns())
        )

    def _ensure_pro_client(self) -> GeminiProClient:
        if self._pro_client is None:
            self._pro_client = GoogleGenAIProClient()
        return self._pro_client

    def score(
        self,
        *,
        ai_bom: dict[str, Any],
        audit_window: dict[str, Any],
        owasp_coverage: dict[str, Any],
        mitre_atlas_coverage: dict[str, Any],
        attack_pack_list: list[dict[str, Any]],
        coverage_amount_usd: Optional[int] = None,
    ) -> UnderwriterScore:
        """Produce a Munich-Re-grounded :class:`UnderwriterScore`.

        Validates the Gemini-Pro JSON output against the strict schema in
        this module. Out-of-range / missing fields raise
        :class:`InvalidUnderwriterOutput` — the caller (A-10) decides
        whether to surface the failure or retry.
        """
        cov = coverage_amount_usd or self._coverage
        client = self._ensure_pro_client()

        user_message = self._build_user_message(
            ai_bom=ai_bom,
            audit_window=audit_window,
            owasp_coverage=owasp_coverage,
            mitre_atlas_coverage=mitre_atlas_coverage,
            attack_pack_list=attack_pack_list,
            coverage_amount_usd=cov,
        )
        raw = client.generate_score(
            system_prompt=self.system_prompt,
            user_message=user_message,
        )
        # Defensive coercion: clamp out-of-spec tier / axis values into a
        # validation error rather than letting an upstream consumer trust
        # a hallucinated value.
        _enforce_constraints(raw, default_coverage_usd=cov)
        try:
            score = UnderwriterScore.model_validate(raw)
        except ValidationError as exc:
            raise InvalidUnderwriterOutput(
                f"Gemini Pro output failed schema validation: {exc}"
            ) from exc
        _enforce_post_validation_invariants(score)
        return score

    def _build_user_message(
        self,
        *,
        ai_bom: dict[str, Any],
        audit_window: dict[str, Any],
        owasp_coverage: dict[str, Any],
        mitre_atlas_coverage: dict[str, Any],
        attack_pack_list: list[dict[str, Any]],
        coverage_amount_usd: int,
    ) -> str:
        snapshot = {
            "ai_bom": ai_bom,
            "audit_window": audit_window,
            "owasp_coverage": owasp_coverage,
            "mitre_atlas_coverage": mitre_atlas_coverage,
            "attack_pack_list": attack_pack_list,
            "requested_coverage_amount_usd": coverage_amount_usd,
            "mosaic_munich_re_cap_anchor_usd": MOSAIC_MUNICH_RE_CAP_USD,
            "mosaic_munich_re_announcement_date": MOSAIC_MUNICH_RE_ANNOUNCEMENT_DATE,
            "estimated_premium_band_methodology": (
                "Apply 2025-26 cyber market rate $0.5–$2 per $1k coverage "
                "to the requested_coverage_amount_usd. Label the output "
                "'ESTIMATED RANGE, not Munich-Re-published'."
            ),
            "snapshot_generated_at": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        }
        return (
            "Score the following AI deployment against the Munich Re aiSure "
            "framework. Output ONLY the JSON object specified in the system "
            "prompt — no commentary, no markdown fences.\n\n"
            f"DEPLOYMENT SNAPSHOT:\n{json.dumps(snapshot, default=str, indent=2)}"
        )


# ---------------------------------------------------------------------------
# Validation helpers (used both inside and outside the agent)
# ---------------------------------------------------------------------------


def _enforce_constraints(raw: dict[str, Any], *, default_coverage_usd: int) -> None:
    """In-place pre-validation cleanup.

    Catches common Gemini hallucinations BEFORE pydantic validation:

    * Premium range missing the required disclaimer language — fail.
    * Bare-letter tier labels with no ``mapped to Munich Re`` framing —
      Reef adds the framing automatically via
      ``UnderwriterScore.tier_label_with_framing``; the raw tier string
      itself is just the letter.
    * ``coverage_amount_usd`` missing — fill from default.
    """
    if not isinstance(raw, dict):
        raise InvalidUnderwriterOutput("Underwriter output is not a JSON object")
    raw.setdefault("recommended_exclusions", [])
    raw.setdefault("phase_2_disclaimer", PHASE_2_DISCLAIMER)
    premium = raw.get("estimated_premium_range_usd_annual")
    if not isinstance(premium, dict):
        raise InvalidUnderwriterOutput(
            "Missing 'estimated_premium_range_usd_annual' object"
        )
    premium.setdefault("currency", "USD")
    premium.setdefault("coverage_amount_usd", default_coverage_usd)
    premium.setdefault(
        "anchor",
        (
            "2025-26 cyber market rate $0.5-$2 per $1k coverage; "
            "Mosaic + Munich Re $15M cap (Feb 27 2026)"
        ),
    )
    premium.setdefault("disclaimer", "ESTIMATED RANGE, not Munich-Re-published")

    tier = raw.get("reef_risk_tier")
    if isinstance(tier, str) and tier.strip() not in VALID_TIERS:
        # Tolerate Gemini wrapping the tier in framing text — strip it.
        for candidate in VALID_TIERS:
            if candidate in tier:
                raw["reef_risk_tier"] = candidate
                break
        else:
            raise InvalidUnderwriterOutput(
                f"reef_risk_tier {tier!r} is not in {VALID_TIERS!r}"
            )

    ax = raw.get("due_diligence_axes")
    if isinstance(ax, dict):
        for axis_name in DUE_DILIGENCE_AXES:
            value = ax.get(axis_name)
            if isinstance(value, str):
                v = value.strip().lower()
                if v not in VALID_AXIS_RATINGS:
                    # Coerce common synonyms.
                    if v in ("good", "high", "robust"):
                        ax[axis_name] = "strong"
                    elif v in ("medium", "moderate"):
                        ax[axis_name] = "partial"
                    elif v in ("poor", "low", "missing", "none"):
                        ax[axis_name] = "weak"
                    else:
                        raise InvalidUnderwriterOutput(
                            f"due_diligence_axes.{axis_name}={value!r} not in {VALID_AXIS_RATINGS!r}"
                        )
                else:
                    ax[axis_name] = v


def _enforce_post_validation_invariants(score: UnderwriterScore) -> None:
    """Post-validation hard checks (invariants that pydantic can't express).

    Honest-framing rules from `docs/24-GROUNDING.md`:

    * The estimated-premium block's ``disclaimer`` MUST contain
      "ESTIMATED RANGE" or "not Munich-Re-published".
    * The estimated-premium block's ``anchor`` MUST reference the Mosaic
      + Munich Re $15M cap.
    * ``phase_2_disclaimer`` MUST contain the broker-API phrase.
    """
    if score.reef_risk_tier not in VALID_TIERS:
        raise InvalidUnderwriterOutput(
            f"reef_risk_tier {score.reef_risk_tier!r} not in allowed list"
        )
    for axis_name in DUE_DILIGENCE_AXES:
        value = getattr(score.due_diligence_axes, axis_name)
        if value not in VALID_AXIS_RATINGS:
            raise InvalidUnderwriterOutput(
                f"due_diligence_axes.{axis_name}={value!r} not in {VALID_AXIS_RATINGS!r}"
            )
    disclaimer = score.estimated_premium_range_usd_annual.disclaimer
    if ("ESTIMATED RANGE" not in disclaimer) and ("not Munich-Re-published" not in disclaimer):
        raise InvalidUnderwriterOutput(
            "Premium range disclaimer must say 'ESTIMATED RANGE, not "
            f"Munich-Re-published' — got {disclaimer!r}"
        )
    anchor = score.estimated_premium_range_usd_annual.anchor
    if "Mosaic" not in anchor or "Munich Re" not in anchor:
        raise InvalidUnderwriterOutput(
            "Premium anchor must reference Mosaic + Munich Re $15M cap — "
            f"got {anchor!r}"
        )
    if "Phase 2" not in score.phase_2_disclaimer:
        raise InvalidUnderwriterOutput(
            "phase_2_disclaimer must reference Phase 2 broker API — got "
            f"{score.phase_2_disclaimer!r}"
        )
    if score.estimated_premium_range_usd_annual.low > score.estimated_premium_range_usd_annual.high:
        raise InvalidUnderwriterOutput(
            "Premium range low > high — got "
            f"low={score.estimated_premium_range_usd_annual.low} "
            f"high={score.estimated_premium_range_usd_annual.high}"
        )


__all__ = [
    "UnderwriterAgent",
    "UnderwriterScore",
    "UnderwriterInput",
    "UnderwriterError",
    "MissingGeminiAPIKey",
    "MissingGeminiProModel",
    "GeminiCallFailed",
    "InvalidUnderwriterOutput",
    "RiskCategoryScores",
    "DueDiligenceAxes",
    "EstimatedPremiumRange",
    "GeminiProClient",
    "GoogleGenAIProClient",
    "RISK_CATEGORIES",
    "DUE_DILIGENCE_AXES",
    "VALID_TIERS",
    "VALID_AXIS_RATINGS",
    "MOSAIC_MUNICH_RE_CAP_USD",
    "MOSAIC_MUNICH_RE_ANNOUNCEMENT_DATE",
    "PHASE_2_DISCLAIMER",
    "DEFAULT_COVERAGE_AMOUNT_USD",
    "SYSTEM_PROMPT_TEMPLATE",
]
