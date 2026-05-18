# Reef Quote — Underwriter Layer (Layer 7)

The Reef Quote service produces the **Reef Insurance Artifact (RIA)** — the
third-act categorical separator of the Reef demo. It contains:

* The signed AI-BOM (agents, models, MCP servers, tools, policy versions).
* OWASP Agentic Top 10 coverage matrix.
* MITRE ATLAS map.
* Merkle audit root.
* 30-day attack heatmap from DAST-A.
* **A Gemini-3-Pro-generated risk tier + estimated premium range, grounded
  on Munich Re's public AI insurance framework.**

This package owns the underwriter agent. The RIA PDF generator (reportlab)
is the responsibility of A-10; A-10 imports
`quote.app.underwriter_agent.UnderwriterAgent` to obtain the scored JSON
that becomes the rendered RIA's risk-tier section.

## Honest scope

Munich Re does **not** publish numeric premium tables. They do **not**
publish "Tier A/B/C" labels. They do **not** publicly endorse Reef. The
underwriter agent therefore:

* Frames tiers as **"Reef Risk Tier X mapped to Munich Re aiSure axes"** —
  never as Munich-Re-published tiers.
* Treats the **$15M Mosaic + Munich Re partnership cap (Feb 27 2026)** as
  the only public pricing anchor; all premium ranges are **estimated bands
  labelled "ESTIMATED RANGE, not Munich-Re-published."**
* Bakes a disclaimer into every output: *"This is a rubric-grounded score,
  not a Lloyd's quote. Phase 2 integrates real broker API (Bold Penguin /
  CoverGenius / Vouch dev sandboxes)."*

The five risk categories + five due-diligence axes used by the agent are
**verbatim Munich Re terminology** sourced from `docs/24-GROUNDING.md`
Part 1 — see `app/rubrics/munich_re_framework.md` for the in-package
canonical copy that Gemini Pro is grounded on.

## Configuration

The underwriter agent reads:

* `GEMINI_API_KEY` — required (Google AI Studio key).
* `GEMINI_PRO_MODEL` — required, e.g. `gemini-2.0-pro-exp` (per D-017
  Reef NEVER hardcodes the model name).
* `REEF_UNDERWRITER_COVERAGE_AMOUNT_USD` — default coverage cap to size
  the estimated premium band against (default 5,000,000 USD).
* `REEF_UNDERWRITER_RUBRIC` — override path for the framework markdown
  rubric (default ships in-package).

If `GEMINI_API_KEY` or `GEMINI_PRO_MODEL` is missing, the agent raises
`MissingGeminiAPIKey` / `MissingGeminiProModel` and the calling HTTP
handler returns 503. **No mocked output — fail closed.**

## Usage

```python
from quote.app.underwriter_agent import UnderwriterAgent

agent = UnderwriterAgent()  # reads env-config at construction time
score = agent.score(
    ai_bom=ai_bom_dict,
    audit_window=audit_window_dict,
    owasp_coverage=owasp_coverage_dict,
    mitre_atlas_coverage=mitre_atlas_dict,
    attack_pack_list=packs_list,
)
print(score.reef_risk_tier)              # "B+"
print(score.estimated_premium_range_usd_annual["low"])
print(score.phase_2_disclaimer)
```

## See also

* `app/rubrics/munich_re_framework.md` — the rubric Gemini Pro grounds on.
* `app/rubrics/munich_re_anti_patterns.md` — the "do NOT claim X" guard
  rails baked into the system prompt.
* `docs/24-GROUNDING.md` — the upstream source-of-truth grounding doc.
* `docs/10-DECISIONS.md` — D-007 (Munich Re sole grounding) and D-017
  (Gemini model split).
