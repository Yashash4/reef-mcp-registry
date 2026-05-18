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
* `GEMINI_PRO_MODEL` — required, GA model identifier (e.g.
  `gemini-2.5-pro`). Per D-017 Reef NEVER hardcodes the model name; per
  the CISO veto on Phase B round 1 the `.env.example` default MUST be a
  GA identifier (not `*-exp` / `*-preview`) so the model_attestation
  block on RIA page 6 records an identifier the auditor can verify
  against Google's release notes.
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

## Sample RIA — offline verification

The committed `samples/sample-ria.pdf` ships with a detached
`samples/sample-ria.pdf.sig`, the public key in `samples/sample-signer.pub`,
and (Phase B round 1 R-1) the demo-only `samples/sample-signer.key` so
any auditor cloning the repo can verify the artifact end-to-end without
running a Reef service:

```bash
python reef/control-plane/quote/samples/verify_sample.py
# verify_sample: OK
#   pdf        = .../samples/sample-ria.pdf
#   pdf_sha256 = ...
#   signature  = ed25519(...) [verified]
```

Exit code 0 means the committed PDF + signature + public key are in
lockstep. Non-zero means the artifact triplet drifted — `pytest -k
test_sample_ria_signature` fails the CI build in that case.

**Wire format.** `sig = ed25519_sign(priv, SHA-256(pdf_bytes))` — same
contract as `lobstertrap-reef/pkg/policysync/cosign.go` so the Go
verifier accepts the same `.sig` file.

**The committed `sample-signer.key` is DEMO-ONLY** — clearly marked as
such, used only to regenerate the public sample artifact. Operator
deployments load their own signer key from `REEF_QUOTE_SIGNER_PRIV_KEY`
(see `.env.example`).

## Page-6 model attestation (NYDFS Part 500 / OCC SR-21-14)

Every RIA includes a `model_attestation` block on page 6 recording:

- `underwriter_model_id` — the GA Gemini model identifier the score
  came from (read from `GEMINI_PRO_MODEL` env at score time).
- `rubric_file_sha256 (framework)` / `(anti-patterns)` — sha256 of
  every rubric markdown file the system prompt embedded.
- `ria_generated_at_unix` + `ria_generator_version` — provenance of
  the RIA build itself.
- `sample_mode` — `true` when the artifact came out of the
  deterministic sample stub instead of a live Gemini call.

This block is the model-risk-management artifact the CISO's auditor
verifies against the bank's NYDFS Part 500 / OCC SR-21-14 model
inventory. The `.env.example` defaults to GA model IDs (no `*-exp` /
`*-preview`) so the attestation never records an experimental identifier.

## Page-6 D-018 invariant scan

Per D-018 (advisory only, never auto-apply), the RIA scans the policy
bus audit JSONL for any `policy_bundle_applied` event whose
`source == "gemini_blue_draft"` and surfaces a red banner on page 6 if
ANY such event lacks a non-empty `human_review.approval_id`. A clean
scan reports `0 violations` so the auditor can tell the scan ran.

## See also

* `app/rubrics/munich_re_framework.md` — the rubric Gemini Pro grounds on.
* `app/rubrics/munich_re_anti_patterns.md` — the "do NOT claim X" guard
  rails baked into the system prompt.
* `docs/24-GROUNDING.md` — the upstream source-of-truth grounding doc.
* `docs/10-DECISIONS.md` — D-007 (Munich Re sole grounding) and D-017
  (Gemini model split).
