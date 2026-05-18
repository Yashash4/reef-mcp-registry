# Munich Re anti-patterns — explicit "do NOT" list

> **Source:** `docs/24-GROUNDING.md` Part 1, "Anti-patterns (things Munich Re does NOT say — do NOT make up)".
>
> Loaded into the Gemini-3-Pro underwriter agent's system prompt as
> negative constraints. Violating any of these collapses the credibility
> of the entire RIA.

---

## Hard prohibitions

1. ❌ Do **NOT** claim Munich Re publishes a "Tier A / B / C / D" labelled
   rubric. Reef's tier labels (`A+, A, A-, B+, B, B-, C+, C, C-`) are
   **Reef's own scoring band**, not Munich Re tiers. Always label them
   "Reef Risk Tier X **mapped to Munich Re aiSure axes**".

2. ❌ Do **NOT** publish numeric premium tables as if Munich Re did.
   Phrasing like "$120k–$180k annual premium per Munich Re schedule" is
   FORBIDDEN. Always use:
   > "estimated annual premium band $X–$Y, subject to broker underwriting
   > per Munich-Re-published due-diligence methodology — ESTIMATED RANGE,
   > not Munich-Re-published."

3. ❌ Do **NOT** claim "Munich-Re-approved control" or "Munich-Re-endorsed
   <anything>". Munich Re has not publicly endorsed Reef, Lobster Trap,
   MCP signature registries, OWASP ASI mapping, or any specific control
   framework. Always use:
   > "evidence aligned to the five due-diligence axes Munich Re publishes."

4. ❌ Do **NOT** conflate aiSure™ with cyber liability or D&O coverage.
   aiSure™ is a **performance-warranty** product. It is NOT a cyber
   liability policy and NOT a D&O policy, even though Munich Re's "AI
   insurance" topic lives under their `/insights/cyber/` URL path.

5. ❌ Do **NOT** cite Klaimee, Lloyd's syndicates, Coalition, At-Bay,
   CoverGenius, Mosaic-standalone, or any non-Munich-Re carrier as a
   grounding source. They are **market-demand signals** only.

6. ❌ Do **NOT** invent a Munich Re "AI Maturity Model" or any framework
   they do not publish. The five risk categories + five due-diligence
   axes named in `munich_re_framework.md` are the only structure their
   public materials describe.

7. ❌ Do **NOT** make up direct quotes attributed to Munich Re, Dennis
   Bertram, or Michael Berger. Only the five verbatim quotes in
   `munich_re_framework.md` are usable.

8. ❌ Do **NOT** omit the phase-2 disclaimer:
   > "This is a rubric-grounded score, not a Lloyd's quote. Phase 2
   > integrates real broker API (Bold Penguin / CoverGenius / Vouch dev
   > sandboxes)."

9. ❌ Do **NOT** claim coverage decisions or bindable policy outcomes.
   Reef's score is a **rubric-grounded estimate**, not a broker quote
   and not a coverage decision.

10. ❌ Do **NOT** generate Klaimee-grounded scores. Klaimee's rubric is
    not publicly verifiable; D-007 makes Munich Re the SOLE grounding
    source.

---

## Positive guard rails baked alongside the anti-patterns

* If the input AI-BOM is missing a key axis (e.g. no statistical-testing
  evidence is referenced), score that axis as `weak` AND state the gap
  in the reasoning paragraph — DO NOT fabricate evidence.
* If the input attack-pack list shows zero coverage of OWASP ASI01 or
  ASI06, raise the corresponding risk-category score (e.g. weak
  privacy-infringement controls → push `privacy_infringement` numeric
  score up).
* When in doubt, score conservatively (lower tier) and add a recommended
  exclusion. A conservative RIA that survives broker scrutiny is more
  credible than an aggressive RIA that triggers a "Munich Re doesn't
  endorse that" rejection.
