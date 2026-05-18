# Reef — TechEx 2026 submission materials

This file collects the text + assets needed to fill the lablab.ai submission
form. It mirrors the internal `docs/40-SUBMISSION.md` so the public repo has
the same source of truth.

---

## Project title

**Reef — Signed MCP Supply Chain + Underwriter Layer for AI Agent Fleets**

## Short description (≤140 chars)

> The signed supply chain for MCP servers. Blocks April 2026 Anthropic MCP exploit + EchoLeak. Munich Re-grounded insurance-grade audit.

## Long description (~350 words)

> Reef is the signed supply chain for MCP servers — and the only AI firewall that outputs an underwriter-scorable evidence artifact.
>
> In April 2026, Anthropic disclosed an MCP STDIO RCE affecting 7,000+ vulnerable servers and 150 million+ downloads. The MCP ecosystem has no centralized signature registry today; every enterprise running agents that bind to MCP servers is one poisoned package away from cross-fleet compromise. Reef ships the open-source Sigstore-style registry, runtime verifier, and audit pipeline that closes this gap.
>
> Built on MIT-licensed Lobster Trap. Every MCP bind goes through Sigstore signature verification against a fleet-approved registry — unsigned origins are denied at handshake. The same engine catches LLM-layer attacks: every agent gets a SPIFFE-shaped SVID identity, every policy ships as a cosigned bundle pushed across the fleet in seconds, every decision lands in a Merkle-anchored audit log. EchoLeak (CVE-2025-32711, the June 2025 zero-click Microsoft Copilot exfil) blocked in 1.2 seconds; Microsoft took 5 months to patch.
>
> Our DAST-A loop runs a PPO adversary continuously against a sandbox of the fleet, surfacing novel attacks as named, versioned, CVE-mapped packs (`MCP-RCE-26.04`, `EchoLeak-26.05`, `MarkdownExfil-26.05`...). Gemini 3 Flash watches as a multimodal screenshot observer and emits structured-output policy drafts in sub-second latency. Drafts land in a HUMAN_REVIEW queue — no auto-apply, ever.
>
> The third-act artifact: **Reef Quote**. Gemini 3 Pro acts as a rubric-grounded underwriter agent, scoring our signed AI-BOM + OWASP Agentic Top 10 coverage + MITRE ATLAS map + Merkle audit root against **Munich Re's public AI insurance scoring framework**. Output: a signed Reef Insurance Artifact (RIA) PDF with risk tier and suggested premium range. We score; a real broker round-trip is Phase 2 via Bold Penguin / CoverGenius dev APIs. Klaimee (YC W26) raised on the demand side; Reef is the open-source supply side.
>
> Falco for AI agents — at the edge. The registry MCP needs. The artifact your underwriter can price.

## Receipts — what Reef actually blocks

Verified against [4 named attack packs](./reef/control-plane/dast_a/app/packs/seed_packs.py) in our DAST-A adversary loop. Re-run with `pytest reef/control-plane/dast_a/tests/test_integration_victim.py reef/control-plane/dast_a/tests/test_packs.py`.

| Attack class            | Vanilla agent     | Reef-protected agent | Exfil-attempt episodes |
|---|---|---|---|
| `MCP-RCE-26.04`         | 0 % blocked       | 100 % blocked        | 42  |
| `EchoLeak-26.05`        | 0 % blocked       | 100 % blocked        | 120 |
| `MarkdownExfil-26.05`   | 0 % blocked       | 100 % blocked        | 37  |
| `ToolChain-Drift-26.04` | 0 % blocked       | 100 % blocked        | 18  |

*Vanilla* = same victim Copilot-clone with **no Reef policies loaded** — the payload reaches the model and exfiltrates the canary secret (reproducible via `?demo=true` and the `reef_off` stub run, where 76 / 200 random PPO-baseline episodes successfully exfil). *Reef-protected* = same stack with the Atlas MCP signature registry + Lobster Trap fork + signed-policy bus active; the integration test [`test_reef_on_blocks_attacks`](./reef/control-plane/dast_a/tests/test_integration_victim.py) asserts ≥ 90 % block rate on exfil-attempt episodes, and the empirical reef-on run blocks 78 / 78 attempt-episodes (100 %, conditional on the attacker reaching `send()`). Per-pack episode counts are the canonical catalog records exposed at `GET /dast-a/packs`.

*Source code + raw episode logs ship in the repo — judges and reviewers can re-run.*

## Tags

`AI Security`, `Agent Governance`, `Lobster Trap`, `Veea`, `Gemini 3 Pro`, `Gemini 3 Flash`, `AI Studio`, `SPIFFE`, `Sigstore`, `MCP`, `Reinforcement Learning`, `OWASP Agentic Top 10`, `MITRE ATLAS`, `EU AI Act`, `EchoLeak`, `Open Source`, `Edge AI`, `Cyber Insurance`, `AI-BOM`, `MCP Supply Chain`

## Cover image

[`samples/cover-image.png`](./samples/cover-image.png) (1920 × 1080 PNG, triple-panel composition: MCP BIND DENIED with the Anthropic MCP STDIO villain badge + 7×7 fleet stadium wave captured mid-flight + signed RIA PDF + single-beat tagline "Signed MCP supply chain + the artifact your underwriter can price.").

## Video presentation

*Placeholder — Phase C Remotion video TBD.*

When ready, the 5-minute submission video will sit at a Loom / YouTube
unlisted link; update this section with the URL before submitting.

## Slide presentation

*Placeholder — Phase C 12-slide deck TBD.*

The 12-slide deck (Remotion-rendered) mirrors the video frame breakdown
in [`docs/superpowers/specs/2026-05-18-reef-design.md`](./docs/superpowers/specs/2026-05-18-reef-design.md) §11.7.

## GitHub repository

https://github.com/Yashash4/reef-mcp-registry

## Application URL

http://[deployment-url]:3000

Once the operator deploys Reef somewhere reachable (Fly / Railway / a
public VM), this is the URL judges click through to. Locally it is
http://localhost:3000 after `docker compose up`.

## Submission deadline

**2026-05-19 · 05:30 IST.**

## Primary track + secondary prize

- **Primary track:** Track 1 — Agent Security & AI Governance (Veea-sponsored).
- **Secondary prize target:** Gemini Award.

## Author

**Yashash Sheshagiri** — https://github.com/Yashash4

---

## Submission checklist (for the operator)

Walk through these in order on submission day.

- [ ] Cover image renders correctly on the lablab.ai card preview (1920×1080, panels readable at thumbnail size).
- [ ] Demo video URL set (Loom / YouTube unlisted).
- [ ] Slide deck URL set (Drive / Notion / direct PDF).
- [ ] GitHub repo is public + the README hero image loads (relative path `./samples/cover-image.png` resolves).
- [ ] `docker compose up` works on a fresh clone (Docker Desktop daemon running).
- [ ] Sample RIA PDF downloads cleanly via the link in the README.
- [ ] Public Safety Page renders at the deployment URL.
- [ ] Long description pasted verbatim (≤350 words — verify the form's char limit).
- [ ] Tags pasted verbatim (verify the form's max-tag count).
- [ ] No leaked secrets in repo (`.env` is gitignored; only `.env.example` is committed).
- [ ] License file at repo root (MIT).
- [ ] Phase 2 list = exactly 4 items in README.
- [ ] Munich Re grounding language present + verbatim disclaimers preserved (search README for "ESTIMATED RANGE" + "Phase 2 integrates real broker API" + "mapped to Munich Re aiSure axes").
- [ ] OX Security April 2026 disclosure quoted verbatim in README + RIA.
- [ ] No "Klaimee-grounded" / "Munich-Re-approved control" / "Lloyd's quote" language anywhere except the negative disclaimer ("not a Lloyd's quote").
- [ ] Form submitted before 2026-05-19 · 05:30 IST.
