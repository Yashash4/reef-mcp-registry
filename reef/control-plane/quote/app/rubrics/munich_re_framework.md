# Munich Re aiSure framework — Reef Quote rubric (verbatim)

> **Source:** `docs/24-GROUNDING.md` Part 1, verified live 2026-05-18.
> **Hard rule:** Munich Re is the SOLE grounding source for Reef RIA risk
> scoring (decision D-007 in `docs/10-DECISIONS.md`). Klaimee, Lloyd's,
> Mosaic standalone, CoverGenius are market-demand signals only — never
> grounding sources.

This file is loaded into the Gemini-3-Pro underwriter agent's prompt on
**every** call. The agent must ground every score on these axes and these
quotes — never invent new "Munich Re says" content.

---

## Five risk categories (verbatim from Munich Re's aiSure product positioning)

> "aiSure™ provides comprehensive coverage for AI systems addressing a wide
> area of AI-related risks including **hallucination, misleading content
> and false information**; **bias and fairness risks** leading to
> discrimination; **privacy infringement** following the leakage of private
> or sensitive information; and **intellectual property violations** by
> models trained on copyright-protected material."

Reef's RIA scores against these five named risk categories (use the
schema-keyed snake-case identifiers in scoring output):

1. `hallucination_false_info` — Hallucination / misleading content / false information
2. `bias_fairness` — Bias and fairness risks (discrimination)
3. `privacy_infringement` — Privacy infringement (leakage of private or sensitive information)
4. `ip_violations` — Intellectual property violations by models trained on copyright-protected material
5. `performance_underperformance` — Performance underperformance (the aiSure parametric trigger — "AI model fails to meet clearly defined performance standards")

---

## Five due-diligence axes (verbatim Munich Re language)

> "The technical due diligence process that underpins aiSure™ is a deep
> and rigorous assessment conducted by a multidisciplinary team including
> at least one research scientist to validate data science methodologies
> and multiple domain experts—such as cybersecurity specialists, engineers,
> or medical doctors—to evaluate the specific application context and its
> associated risks."

> "The assessment includes their risk assessment of the data science
> process, their evaluation of a statistically-sound testing procedure for
> the machine learning model, and they are interested in how the
> probability distribution for this metric varies, with the guarantee
> threshold depending on finding a good representation of this probability
> distribution."

Reef scores the AI deployment against these five axes
(`strong | partial | weak`):

1. `data_science_process_quality` — quality of the data-science process behind the model
2. `statistical_testing_rigor` — statistically-sound testing procedure for the machine learning model
3. `predictive_robustness` — predictive robustness assessment of AI models (from Computer Weekly summary)
4. `scope_of_validity` — "the scope of validity regarding where the AI model is valid" (Michael Berger, Munich Re)
5. `performance_probability_distribution` — how the probability distribution for the performance metric varies

---

## Premium-range methodology (Munich Re does NOT publish exact pricing)

> "aiSure™ is model-agnostic, so any type of model, including GenAI, is
> insurable, with the **quality of the model and its performance stability
> determining the premium**."

> "up to EUR/USD/CAD **15 million** in initial coverage to protect AI
> developers and vendors worldwide against financial losses stemming from
> defined AI performance failures." — Mosaic + Munich Re partnership,
> 27 Feb 2026.

> Dennis Bertram (Head of AI Underwriting, Mosaic):
> "Our underwriting focuses on the **AI model itself, what it does, how
> its outputs are used**, rather than the insured's respective industry."

> The aiSure structure: "**parametric-like structure** allowing claims to
> be settled quickly, based on **measurable performance data**, without
> lengthy investigations."

**Implication for Reef estimated premium range.** Munich Re does not
publish "policies with $X premium per tier." Reef's estimated premium
range is an estimated band the underwriter agent infers from:

* The **2025-26 cyber market rate of $0.5–$2 per $1,000 of coverage** for
  SMB-equivalent risk (industry standard reference band, not a Munich Re
  rate).
* The **Mosaic + Munich Re $15M cap (Feb 27 2026)** as the only public
  Munich-Re-adjacent pricing anchor.

Reef labels every estimated range "**ESTIMATED RANGE, not
Munich-Re-published**". The phrase "Munich Re will charge $X" must not
appear in any output.

---

## Direct quotes the agent is allowed to use (citation-ready, verbatim)

1. (Risk-category scope, aiSure™ page)
   > "aiSure™ provides comprehensive coverage for AI systems addressing a
   > wide area of AI-related risks including hallucination, misleading
   > content and false information; bias and fairness risks leading to
   > discrimination; privacy infringement following the leakage of private
   > or sensitive information; and intellectual property violations by
   > models trained on copyright-protected material."

2. (Due-diligence framework, aiSure™ page)
   > "The technical due diligence process that underpins aiSure™ is a deep
   > and rigorous assessment conducted by a multidisciplinary team
   > including at least one research scientist to validate data science
   > methodologies and multiple domain experts—such as cybersecurity
   > specialists, engineers, or medical doctors—to evaluate the specific
   > application context and its associated risks."

3. (Premium driver, aiSure™ page)
   > "aiSure™ is model-agnostic, so any type of model, including GenAI, is
   > insurable, with the quality of the model and its performance
   > stability determining the premium."

4. (Underwriting focus, Dennis Bertram — Mosaic Head of AI Underwriting,
   27 Feb 2026)
   > "Our underwriting focuses on the AI model itself, what it does, how
   > its outputs are used, rather than the insured's respective industry."

5. (Coverage limit precedent, Mosaic + Munich Re partnership,
   27 Feb 2026)
   > "up to EUR/USD/CAD 15 million in initial coverage to protect AI
   > developers and vendors worldwide against financial losses stemming
   > from defined AI performance failures."

---

## Honest framing the agent must include in every output

* Tier labels: "Reef Risk Tier X **mapped to Munich Re aiSure axes**" —
  never bare "Tier X" or "Munich Re Tier X".
* Premium ranges: "ESTIMATED RANGE, not Munich-Re-published" + the
  Mosaic + Munich Re $15M cap anchor.
* Phase-2 disclaimer: "This is a rubric-grounded score, not a Lloyd's
  quote. Phase 2 integrates real broker API (Bold Penguin / CoverGenius /
  Vouch dev sandboxes)."
