"""End-to-end RIA PDF generator.

Workflow:

1. Resolve service URLs / signer / signer key from env or explicit args.
2. Query the 5 upstream data sources:
   * Atlas registry (entries + healthz)
   * Policy bus (fleet + bundles)
   * DAST-A (packs)
   * Lobster Trap audit (signed Merkle root via Go CLI)
   * UnderwriterAgent (Gemini 3 Pro — or :class:`SampleUnderwriterAgent`
     when ``GEMINI_API_KEY`` is missing).
3. Compute model_attestation block (Gemini model IDs + rubric file
   sha256 digests + ria_generator version) per Phase B round 1 R-3.
4. Scan the policy bus audit JSONL for D-018 invariant violations
   (R-6: any ``policy_bundle_applied`` event whose source is
   ``gemini_blue_draft`` MUST carry a non-empty
   ``human_review.approval_id``).
5. Build the 6 sections, render to PDF bytes in memory.
6. Sign the PDF bytes (ed25519 over SHA-256) + write the detached `.sig`.
7. Persist ``<data_dir>/ria/<ria_id>.pdf`` and return the
   :class:`RIAArtifact` envelope.

Single function entrypoint :func:`generate_ria` keeps callers (API handler,
boot-time sample generator, integration test) simple.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import io
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Iterable, Optional

import httpx
from reportlab.platypus import Flowable

from app.data_sources.ai_bom import (
    ServiceURLs,
    assemble_ai_bom,
    query_atlas_registry,
    query_dast_a_packs,
    query_policy_bus,
    resolve_service_urls_from_env,
)
from app.data_sources.attack_telemetry import (
    aggregate_heatmap,
    telemetry_to_audit_window,
)
from app.data_sources.audit_root import (
    SignedMerkleRoot,
    fetch_signed_merkle_root,
    stub_signed_merkle_root,
)
from app.data_sources.coverage_matrix import (
    build_mitre_coverage,
    build_owasp_coverage,
    extract_policy_rule_names_from_bundles,
)
from app.data_sources import (
    AtlasUnreachable,
    AuditRootError,
    DastAUnreachable,
    PolicyBusUnreachable,
)
from app.pdf import sections as section_builders
from app.pdf.layout import RIADocTemplate, RIAHeaderContext
from app.pdf.style import build_stylesheet
from app.ria_signer import RIASigner, SignedPDFRecord
from app.rubrics import ANTI_PATTERNS_PATH, FRAMEWORK_PATH
from app.underwriter_agent import (
    DueDiligenceAxes,
    EstimatedPremiumRange,
    MissingGeminiAPIKey,
    MissingGeminiProModel,
    PHASE_2_DISCLAIMER,
    RiskCategoryScores,
    UnderwriterAgent,
    UnderwriterScore,
)

logger = logging.getLogger("quote.ria_generator")


# ---------------------------------------------------------------------------
# Sample / stub underwriter for boot-time sample without GEMINI_API_KEY
# ---------------------------------------------------------------------------


class SampleUnderwriterAgent:
    """Deterministic stub that produces a realistic-looking Tier B+ score.

    Used ONLY when ``GEMINI_API_KEY`` (or ``GEMINI_PRO_MODEL``) is missing
    and the caller has opted into sample mode. Live RIAs always go
    through the real :class:`UnderwriterAgent` — this stub never replaces
    a live call.
    """

    def __init__(self, *, coverage_amount_usd: int = 5_000_000) -> None:
        self._coverage = coverage_amount_usd

    @property
    def coverage_amount_usd(self) -> int:
        return self._coverage

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
        # Deterministic premium band for the documented sample-RIA spec:
        # $42k–$54k for $5M coverage.
        return UnderwriterScore(
            reef_risk_tier="B+",
            risk_category_scores=RiskCategoryScores(
                hallucination_false_info=0.35,
                bias_fairness=0.20,
                privacy_infringement=0.30,
                ip_violations=0.18,
                performance_underperformance=0.28,
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
                coverage_amount_usd=coverage_amount_usd or self._coverage,
                anchor=(
                    "2025-26 cyber market rate $0.5-$2 per $1k coverage; "
                    "Mosaic + Munich Re $15M cap (Feb 27 2026)"
                ),
                disclaimer="ESTIMATED RANGE, not Munich-Re-published",
            ),
            reasoning=(
                "Reef-evidenced control surface maps to strong data-science-process "
                "quality (signed MCP supply chain reduces the bias/IP attack surface) "
                "and partial statistical-testing rigor (the 30-day audit window in "
                "this sample is mostly synthetic seed data). Estimated premium band "
                "follows the 2025-26 cyber market rate of $0.5-$2 per $1k coverage "
                "applied to the requested $5M coverage anchor — anchored on the "
                "Mosaic + Munich Re $15M cap announced Feb 27 2026 — and the band "
                "is labelled an ESTIMATED RANGE, not a Munich-Re-published quote. "
                "A real broker would run this rubric output through their carrier's "
                "pricing engine."
            ),
            recommended_exclusions=[
                "Use of the AI outside the declared scope of validity",
                "Multi-agent collusion / A2A delegation chains (Phase 2)",
                "Live network egress to denylisted domains",
            ],
            phase_2_disclaimer=PHASE_2_DISCLAIMER,
        )


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ModelAttestation:
    """Page-6 model attestation block (R-3).

    Records the GA Gemini model IDs the underwriter agent was configured
    against + the sha256 of each rubric file that grounded the call so a
    NYDFS Part 500 / OCC SR-21-14 auditor can verify which model + which
    rubric produced the score. ``underwriter_model_build_hash`` is best-
    effort — the Google generative AI SDK does not expose model build
    hashes today, so this defaults to ``"unspecified"`` rather than a
    fabricated value.
    """

    underwriter_model_id: str
    underwriter_model_build_hash: str
    rubric_file_sha256_framework: str
    rubric_file_sha256_antipatterns: str
    ria_generated_at_unix: int
    ria_generator_version: str
    sample_mode: bool

    def as_table_rows(self) -> list[tuple[str, str]]:
        return [
            ("underwriter_model_id", self.underwriter_model_id),
            ("underwriter_model_build_hash", self.underwriter_model_build_hash),
            ("rubric_file_sha256 (framework)", self.rubric_file_sha256_framework),
            ("rubric_file_sha256 (anti-patterns)", self.rubric_file_sha256_antipatterns),
            ("ria_generated_at_unix", str(self.ria_generated_at_unix)),
            ("ria_generator_version", self.ria_generator_version),
            ("sample_mode", "true" if self.sample_mode else "false"),
        ]


@dataclasses.dataclass
class AuditInvariantViolation:
    """One audit event that breaks the D-018 advisory-only invariant.

    Per R-6: any ``policy_bundle_applied`` event whose
    ``source == "gemini_blue_draft"`` MUST carry a non-empty
    ``human_review.approval_id`` field — otherwise a Gemini-Flash-drafted
    bundle was applied without operator approval, which violates D-018.
    """

    event_id: str
    bundle_id: str
    timestamp_iso: str
    reason: str


@dataclasses.dataclass
class AuditInvariantReport:
    """Result of the D-018 advisory-only invariant scan."""

    scanned_event_count: int
    draft_applied_event_count: int
    violations: list[AuditInvariantViolation]
    scanned_path: Optional[str]

    @property
    def has_violations(self) -> bool:
        return bool(self.violations)


@dataclasses.dataclass
class RIAArtifact:
    """Envelope returned by :func:`generate_ria`."""

    ria_id: str
    pdf_path: Path
    sig_path: Path
    pdf_bytes: bytes
    pdf_sha256_hex: str
    signature_b64: str
    signature_hex: str
    signer_key_id: str
    score: UnderwriterScore
    ai_bom: dict[str, Any]
    owasp_coverage: dict[str, dict[str, Any]]
    mitre_coverage: dict[str, dict[str, Any]]
    merkle: SignedMerkleRoot
    sample_mode: bool
    fleet_id: str
    generated_at: dt.datetime
    model_attestation: ModelAttestation
    audit_invariant_report: AuditInvariantReport


@dataclasses.dataclass
class RIAGenerateOptions:
    """Construction options for :func:`generate_ria`.

    All fields are optional — defaults read from env. Tests pass explicit
    URLs / paths so they don't depend on the network or the Go binary.
    """

    fleet_id: str = "prod-fleet"
    audit_window_days: int = 30
    coverage_amount_usd: Optional[int] = None
    data_dir: Optional[str] = None
    service_urls: Optional[ServiceURLs] = None
    signer: Optional[RIASigner] = None
    underwriter: Optional[Any] = None  # UnderwriterAgent | SampleUnderwriterAgent
    include_demo_seed_telemetry: bool = True
    force_sample_mode: bool = False
    # Test overrides — used by unit + integration tests.
    atlas_payload_override: Optional[dict[str, Any]] = None
    policy_bus_payload_override: Optional[dict[str, Any]] = None
    dast_a_payload_override: Optional[dict[str, Any]] = None
    merkle_override: Optional[SignedMerkleRoot] = None
    additional_agents: Optional[list[dict[str, Any]]] = None
    additional_models: Optional[list[dict[str, Any]]] = None
    additional_tools: Optional[list[dict[str, Any]]] = None
    # Override for R-6 audit invariant scan — tests pass a list of audit
    # events directly so they don't need to materialise a JSONL fixture.
    policy_bus_audit_override: Optional[list[dict[str, Any]]] = None
    # When True, queries that raise transport errors are swallowed into the
    # sample-mode fallback. Production live mode keeps this False so the
    # operator sees the failure rather than getting silent stub output.
    fallback_on_data_source_error: bool = False


def generate_ria(opts: RIAGenerateOptions) -> RIAArtifact:
    """Produce + persist the signed RIA PDF artifact."""
    now = dt.datetime.now(tz=dt.timezone.utc)
    ria_id = "ria-" + now.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    data_dir = Path(opts.data_dir or os.environ.get("REEF_QUOTE_DATA_DIR") or "./data").resolve()
    ria_dir = data_dir / "ria"
    ria_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = ria_dir / f"{ria_id}.pdf"

    urls = opts.service_urls or resolve_service_urls_from_env()

    # ---- 1. Data sources (3 upstream HTTP + 1 audit subprocess) ----------
    atlas_payload = _resolve_atlas_payload(opts, urls)
    policy_bus_payload = _resolve_policy_bus_payload(opts, urls)
    dast_a_payload = _resolve_dast_a_payload(opts, urls)
    merkle = _resolve_merkle_root(opts)
    policy_bus_audit_for_invariants = opts.policy_bus_audit_override

    # ---- 2. Derive matrices ----------------------------------------------
    rule_names = extract_policy_rule_names_from_bundles(
        policy_bus_payload.get("bundles", [])
    )
    packs = dast_a_payload.get("packs", []) or []
    owasp = build_owasp_coverage(packs=packs, rule_names=rule_names)
    mitre = build_mitre_coverage(packs=packs, rule_names=rule_names)

    ai_bom = assemble_ai_bom(
        fleet_id=opts.fleet_id,
        atlas_payload=atlas_payload,
        policy_bus_payload=policy_bus_payload,
        dast_a_payload=dast_a_payload,
        agents=opts.additional_agents,
        models=opts.additional_models,
        tools=opts.additional_tools,
    )

    # ---- 3. Telemetry heatmap + audit window snapshot --------------------
    policy_bus_audit_path = Path(
        os.environ.get(
            "REEF_POLICY_BUS_AUDIT_FILE",
            str(Path("./reef/control-plane/policy_bus/data/audit.jsonl").resolve()),
        )
    )
    dast_a_audit_path = Path(
        os.environ.get(
            "REEF_DAST_A_AUDIT_FILE",
            str(Path("./reef/control-plane/dast_a/data/audit.jsonl").resolve()),
        )
    )
    telemetry = aggregate_heatmap(
        policy_bus_audit=policy_bus_audit_path,
        dast_a_audit=dast_a_audit_path,
        window_days=opts.audit_window_days,
        include_demo_seed=opts.include_demo_seed_telemetry,
    )
    audit_window = telemetry_to_audit_window(
        telemetry,
        merkle_root_hex=merkle.root_hex,
        merkle_count=merkle.count,
        fleet_id=opts.fleet_id,
    )

    # ---- 4. Underwriter agent --------------------------------------------
    underwriter, sample_mode = _resolve_underwriter(opts)
    score = underwriter.score(
        ai_bom=ai_bom,
        audit_window=audit_window,
        owasp_coverage=owasp,
        mitre_atlas_coverage=mitre,
        attack_pack_list=packs,
        coverage_amount_usd=opts.coverage_amount_usd,
    )

    # ---- 4b. Model attestation block (R-3) ------------------------------
    model_attestation = build_model_attestation(
        sample_mode=sample_mode, generated_at=now
    )

    # ---- 4c. D-018 audit invariant scan (R-6) ---------------------------
    invariant_report = scan_audit_for_invariants(
        policy_bus_audit_path=policy_bus_audit_path,
        events_override=policy_bus_audit_for_invariants,
    )

    # ---- 5. Signer (constructed after sample-mode is resolved so the env
    #         can still set the signer key id) ------------------------------
    signer = opts.signer or RIASigner()

    # ---- 6. Build PDF -----------------------------------------------------
    # We render in two passes: once to produce signature-free bytes, sign
    # those, then render once more with the signature block embedded on
    # page 6. The verifier should still hash + verify the FINAL bytes — so
    # we compute the signature over the FINAL PDF bytes (re-render after
    # signing once, then the signature for the published artifact is over
    # the final PDF, which is also what the verifier hashes).
    #
    # We do this by:
    #   (a) Build a "placeholder" PDF with the signature block visible but
    #       showing placeholder hex/base64 strings.
    #   (b) Sign the placeholder PDF bytes — this produces the actual sig.
    #   (c) Re-render the PDF with the real signature hex+base64 shown.
    #   (d) Re-sign the FINAL PDF bytes (since they changed) and return
    #       THAT signature as the published artifact.
    #
    # In practice the displayed sig in the PDF text is "truncated for
    # display"; the binding signature is the one in the .sig file +
    # X-Reef-RIA-Signature header. So step (c)/(d) just produces consistent
    # bytes for the verifier; the truncated display hex stays the same
    # across (b) and (c) because we only display the prefix.
    placeholder = SignedPDFRecord(
        pdf_bytes=b"",
        sha256_hex="0" * 64,
        signature_b64="placeholder" * 8,
        signature_hex="00" * 32,
        signer_key_id=signer.signer_key_id,
        signer_pub_pem=signer.public_key_pem,
    )
    pre_bytes = _render_pdf(
        ria_id=ria_id,
        fleet_id=opts.fleet_id,
        generated_at=now,
        signer_key_id=signer.signer_key_id,
        signed=placeholder,
        score=score,
        ai_bom=ai_bom,
        owasp_coverage=owasp,
        mitre_coverage=mitre,
        telemetry=telemetry,
        packs=packs,
        merkle=merkle,
        sample_mode=sample_mode,
        model_attestation=model_attestation,
        invariant_report=invariant_report,
    )

    pre_signed = signer.sign_pdf_bytes(pre_bytes)
    final_bytes = _render_pdf(
        ria_id=ria_id,
        fleet_id=opts.fleet_id,
        generated_at=now,
        signer_key_id=signer.signer_key_id,
        signed=pre_signed,
        score=score,
        ai_bom=ai_bom,
        owasp_coverage=owasp,
        mitre_coverage=mitre,
        telemetry=telemetry,
        packs=packs,
        merkle=merkle,
        sample_mode=sample_mode,
        model_attestation=model_attestation,
        invariant_report=invariant_report,
    )
    final_signed = signer.sign_pdf_bytes(final_bytes)

    # Persist PDF + detached signature.
    pdf_path.write_bytes(final_bytes)
    sig_path = signer.write_detached_signature(pdf_path=pdf_path, signed=final_signed)

    return RIAArtifact(
        ria_id=ria_id,
        pdf_path=pdf_path,
        sig_path=sig_path,
        pdf_bytes=final_bytes,
        pdf_sha256_hex=final_signed.sha256_hex,
        signature_b64=final_signed.signature_b64,
        signature_hex=final_signed.signature_hex,
        signer_key_id=signer.signer_key_id,
        score=score,
        ai_bom=ai_bom,
        owasp_coverage=owasp,
        mitre_coverage=mitre,
        merkle=merkle,
        sample_mode=sample_mode,
        fleet_id=opts.fleet_id,
        generated_at=now,
        model_attestation=model_attestation,
        audit_invariant_report=invariant_report,
    )


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------


def _resolve_atlas_payload(opts: RIAGenerateOptions, urls: ServiceURLs) -> dict[str, Any]:
    if opts.atlas_payload_override is not None:
        return opts.atlas_payload_override
    try:
        return query_atlas_registry(urls)
    except AtlasUnreachable:
        if opts.fallback_on_data_source_error or opts.force_sample_mode:
            return _stub_atlas_payload()
        raise


def _resolve_policy_bus_payload(opts: RIAGenerateOptions, urls: ServiceURLs) -> dict[str, Any]:
    if opts.policy_bus_payload_override is not None:
        return opts.policy_bus_payload_override
    try:
        return query_policy_bus(urls)
    except PolicyBusUnreachable:
        if opts.fallback_on_data_source_error or opts.force_sample_mode:
            return _stub_policy_bus_payload(opts.fleet_id)
        raise


def _resolve_dast_a_payload(opts: RIAGenerateOptions, urls: ServiceURLs) -> dict[str, Any]:
    if opts.dast_a_payload_override is not None:
        return opts.dast_a_payload_override
    try:
        return query_dast_a_packs(urls)
    except DastAUnreachable:
        if opts.fallback_on_data_source_error or opts.force_sample_mode:
            return _stub_dast_a_payload()
        raise


def _resolve_merkle_root(opts: RIAGenerateOptions) -> SignedMerkleRoot:
    if opts.merkle_override is not None:
        return opts.merkle_override
    try:
        return fetch_signed_merkle_root()
    except AuditRootError as exc:
        if opts.fallback_on_data_source_error or opts.force_sample_mode:
            logger.info("audit_root subprocess failed (%s) — falling back to stub root", exc)
            return stub_signed_merkle_root()
        raise


def _resolve_underwriter(opts: RIAGenerateOptions) -> tuple[Any, bool]:
    if opts.underwriter is not None:
        # Caller picked the agent explicitly. Sample mode = the caller-set
        # class is a SampleUnderwriterAgent.
        sample = isinstance(opts.underwriter, SampleUnderwriterAgent)
        return opts.underwriter, sample
    if opts.force_sample_mode:
        return SampleUnderwriterAgent(
            coverage_amount_usd=opts.coverage_amount_usd or 5_000_000
        ), True
    # Best-effort live path. If fallback is enabled AND Gemini env vars
    # are missing, swap to the sample agent BEFORE we hit the lazy SDK
    # construction at .score() time (UnderwriterAgent itself doesn't
    # touch env at __init__).
    gemini_env_present = bool(os.environ.get("GEMINI_API_KEY")) and bool(
        os.environ.get("GEMINI_PRO_MODEL")
    )
    if opts.fallback_on_data_source_error and not gemini_env_present:
        logger.info(
            "UnderwriterAgent: GEMINI_API_KEY/GEMINI_PRO_MODEL missing — "
            "falling back to sample mode (allow_sample_fallback=True)"
        )
        return SampleUnderwriterAgent(
            coverage_amount_usd=opts.coverage_amount_usd or 5_000_000
        ), True
    try:
        return UnderwriterAgent(coverage_amount_usd=opts.coverage_amount_usd), False
    except (MissingGeminiAPIKey, MissingGeminiProModel) as exc:
        if opts.fallback_on_data_source_error:
            logger.info(
                "UnderwriterAgent missing Gemini env (%s) — falling back to sample mode",
                exc,
            )
            return SampleUnderwriterAgent(
                coverage_amount_usd=opts.coverage_amount_usd or 5_000_000
            ), True
        raise


# ---------------------------------------------------------------------------
# Stub payloads for sample-mode fallback
# ---------------------------------------------------------------------------


def _stub_atlas_payload() -> dict[str, Any]:
    return {
        "healthz": {
            "status": "ok",
            "registry_entries": {"verified": 47, "quarantined": 2, "poisoned": 1},
            "total_entries": 50,
            "publishers": 5,
        },
        "entries": [
            {
                "registry_id": "reg-sample-trusted",
                "manifest": {
                    "mcpName": "io.github.modelcontextprotocol/server-filesystem",
                    "version": "0.6.3",
                    "transports": ["stdio"],
                    "sdk_version": "@modelcontextprotocol/sdk@1.29.0",
                },
                "publisher_id": "modelcontextprotocol",
                "status": "verified",
                "registered_at": "2026-05-15T00:00:00+00:00",
            },
            {
                "registry_id": "reg-sample-quar",
                "manifest": {
                    "mcpName": "io.example/sample-quarantined",
                    "version": "1.0.0",
                    "transports": ["stdio"],
                    "sdk_version": "@modelcontextprotocol/sdk@1.28.0",
                },
                "publisher_id": "example-publisher",
                "status": "quarantined",
                "registered_at": "2026-04-30T00:00:00+00:00",
                "quarantined_reason": "STDIO transport declared without stdio_entrypoint_hash",
            },
            {
                "registry_id": "reg-sample-poisoned",
                "manifest": {
                    "mcpName": "com.attacker-example/evil-server",
                    "version": "0.5.0",
                    "transports": ["stdio"],
                    "sdk_version": "@modelcontextprotocol/sdk@0.5.0",
                },
                "publisher_id": "unknown",
                "status": "poisoned",
                "registered_at": "2026-04-16T00:00:00+00:00",
                "poisoned_reason": "Vulnerable SDK version (MCP-RCE-26.04)",
            },
        ],
        "publishers": [
            {
                "publisher_id": "modelcontextprotocol",
                "name": "Model Context Protocol",
                "fingerprint": "stub-fp-mcp",
                "scopes": ["io.github.modelcontextprotocol.*"],
                "revoked": False,
            }
        ],
    }


def _stub_policy_bus_payload(fleet_id: str) -> dict[str, Any]:
    return {
        "healthz": {
            "status": "ok",
            "active_subscribers": 49,
            "active_bundles": 1,
            "fleet_node_count": 49,
        },
        "fleet": {
            "fleet_id": fleet_id,
            "nodes": [
                {
                    "identity": {
                        "fleet_id": fleet_id,
                        "region_id": "us-east",
                        "site_id": f"site-{i:02d}",
                        "node_id": f"node-{i:02d}-01",
                    },
                    "online": True,
                    "last_ack_status": "applied",
                    "last_applied_version": "v1",
                    "last_applied_bundle_id": "bundle-sample",
                }
                for i in range(1, 8)
            ],
        },
        "bundles": [
            {
                "bundle_id": "bundle-sample",
                "version": "v1",
                "signer_key_id": "publisher-prod",
                "published_at_unix": 1715731200,
                "scope": {"fleet_id": fleet_id},
                "bundle_yaml": (
                    "ingress_rules:\n"
                    "- name: block_prompt_injection\n"
                    "- name: review_high_asi_ewma\n"
                    "- name: mcp_bind_denied_by_registry\n"
                    "- name: markdown_exfil_modify\n"
                    "- name: svid_required\n"
                    "- name: rate_limit_per_identity\n"
                ),
            }
        ],
    }


def _stub_dast_a_payload() -> dict[str, Any]:
    # Mirrors A-8 seed_packs.py for the visible-in-RIA fields. Pulled here
    # so the sample is self-contained (no live DAST-A call needed).
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
                    "OX Security disclosed April 16 2026. Approximately 7,000 "
                    "publicly-accessible vulnerable MCP servers, 150 million+ "
                    "downloads at risk. No CVE assigned to MCP protocol itself — "
                    "Anthropic declined to patch, treats STDIO command execution "
                    "as expected default."
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


# ---------------------------------------------------------------------------
# Generator version constant — also stamped on every RIA's page-6
# model_attestation block (R-3).
# ---------------------------------------------------------------------------


REEF_VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# Model attestation + audit invariant helpers (Phase B round 1 R-3 + R-6)
# ---------------------------------------------------------------------------


def _file_sha256_hex(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, or 'unavailable' if missing.

    Used by the model_attestation block. Missing rubric files would be a
    serious operational error in production but we surface the string
    "unavailable" rather than raising so the RIA still renders + the
    auditor sees the gap on page 6.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        logger.warning("rubric file missing for model_attestation: %s", path)
        return "unavailable"


def build_model_attestation(
    *,
    sample_mode: bool,
    generated_at: dt.datetime,
    pro_model_env_var: str = "GEMINI_PRO_MODEL",
    framework_path: Optional[Path] = None,
    anti_patterns_path: Optional[Path] = None,
) -> ModelAttestation:
    """Compose the page-6 model_attestation block (R-3).

    Reads the Pro model identifier from env (D-017 — never hardcoded). In
    sample mode the underwriter is the deterministic stub, so the model
    field records ``"sample-underwriter-stub (no Gemini call)"`` so the
    auditor can tell a sample artifact apart from a live one at a glance.

    The Google generative AI SDK does not expose model build hashes today,
    so ``underwriter_model_build_hash`` records ``"unspecified"`` rather
    than fabricating a value. If a future SDK release exposes that field
    we can populate it here.
    """
    framework_path = framework_path or FRAMEWORK_PATH
    anti_patterns_path = anti_patterns_path or ANTI_PATTERNS_PATH

    if sample_mode:
        underwriter_model_id = "sample-underwriter-stub (no Gemini call)"
    else:
        underwriter_model_id = (
            os.environ.get(pro_model_env_var) or "unspecified"
        )

    return ModelAttestation(
        underwriter_model_id=underwriter_model_id,
        underwriter_model_build_hash="unspecified",
        rubric_file_sha256_framework=_file_sha256_hex(framework_path),
        rubric_file_sha256_antipatterns=_file_sha256_hex(anti_patterns_path),
        ria_generated_at_unix=int(generated_at.timestamp()),
        ria_generator_version=f"reef-quote-v{REEF_VERSION}",
        sample_mode=sample_mode,
    )


def _iter_audit_events_from_path(path: Path) -> Iterable[dict[str, Any]]:
    """Stream audit events from a JSONL file, skipping unparseable lines."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(
                    "audit-invariant scan: malformed line in %s: %r",
                    path,
                    line[:120],
                )
                continue
            if isinstance(row, dict):
                yield row


def scan_audit_for_invariants(
    *,
    policy_bus_audit_path: Path,
    events_override: Optional[list[dict[str, Any]]] = None,
) -> AuditInvariantReport:
    """Scan the policy bus audit JSONL for D-018 invariant violations (R-6).

    Iterates each event with ``kind == "policy_bundle_applied"``. If the
    event's ``source == "gemini_blue_draft"`` and there is no non-empty
    ``human_review.approval_id`` field, append the event to the
    violations list. The page-6 builder renders a red banner when this
    list is non-empty.

    ``events_override`` lets tests inject a synthetic event stream
    without materialising a JSONL fixture. When provided, the
    on-disk path is NOT read.
    """
    violations: list[AuditInvariantViolation] = []
    scanned = 0
    draft_applied = 0

    if events_override is not None:
        source_iter: Iterable[dict[str, Any]] = events_override
        scanned_path: Optional[str] = None
    else:
        source_iter = _iter_audit_events_from_path(policy_bus_audit_path)
        scanned_path = str(policy_bus_audit_path)

    for event in source_iter:
        scanned += 1
        kind = event.get("kind") or event.get("event_kind")
        if kind != "policy_bundle_applied":
            continue
        source = (event.get("source") or event.get("bundle_source") or "").strip()
        if source != "gemini_blue_draft":
            continue
        draft_applied += 1
        human_review = event.get("human_review") or {}
        approval_id = ""
        if isinstance(human_review, dict):
            approval_id = (human_review.get("approval_id") or "").strip()
        if not approval_id:
            violations.append(
                AuditInvariantViolation(
                    event_id=str(event.get("event_id") or event.get("id") or "<unknown>"),
                    bundle_id=str(event.get("bundle_id") or "<unknown>"),
                    timestamp_iso=str(
                        event.get("timestamp")
                        or event.get("ts")
                        or event.get("timestamp_iso")
                        or "<unknown>"
                    ),
                    reason=(
                        "policy_bundle_applied event with "
                        "source=gemini_blue_draft missing "
                        "human_review.approval_id (D-018 violation)"
                    ),
                )
            )

    return AuditInvariantReport(
        scanned_event_count=scanned,
        draft_applied_event_count=draft_applied,
        violations=violations,
        scanned_path=scanned_path,
    )


def _render_pdf(
    *,
    ria_id: str,
    fleet_id: str,
    generated_at: dt.datetime,
    signer_key_id: str,
    signed: SignedPDFRecord,
    score: UnderwriterScore,
    ai_bom: dict[str, Any],
    owasp_coverage: dict[str, dict[str, Any]],
    mitre_coverage: dict[str, dict[str, Any]],
    telemetry: list,
    packs: list[dict[str, Any]],
    merkle: SignedMerkleRoot,
    sample_mode: bool,
    model_attestation: "ModelAttestation",
    invariant_report: "AuditInvariantReport",
) -> bytes:
    """Render the 6-page RIA PDF and return the bytes."""
    buf = io.BytesIO()
    # The footer's "Signed by ..." stamp must agree with the page-6
    # attestation block (R-2). The RIA itself is always ed25519-signed
    # over the FINAL PDF bytes (the .sig file written next to the PDF
    # holds the binding signature); ``ria_is_signed`` is therefore True
    # in every code path that reaches _render_pdf. We pass it explicitly
    # so the footer + page 6 read from the same boolean.
    ria_is_signed = True
    header_ctx = RIAHeaderContext(
        fleet_id=fleet_id,
        ria_id=ria_id,
        generated_at=generated_at,
        signer_key_id=signer_key_id,
        reef_version=REEF_VERSION,
        is_sample=sample_mode,
        ria_is_signed=ria_is_signed,
    )
    doc = RIADocTemplate(buf, header_ctx)
    styles = build_stylesheet()

    flows: list[Flowable] = []
    flows.extend(
        section_builders.build_page1_executive_summary(
            styles=styles,
            ria_id=ria_id,
            fleet_id=fleet_id,
            generated_at=generated_at,
            signer_key_id=signer_key_id,
            signature_hex_short=signed.signature_hex_short,
            underwriter_score=score,
            sample_mode=sample_mode,
        )
    )
    flows.extend(
        section_builders.build_page2_ai_bom(
            styles=styles,
            ai_bom=ai_bom,
        )
    )
    flows.extend(
        section_builders.build_page3_coverage_matrix(
            styles=styles,
            owasp_coverage=owasp_coverage,
            mitre_coverage=mitre_coverage,
        )
    )
    flows.extend(
        section_builders.build_page4_attack_heatmap(
            styles=styles,
            telemetry=telemetry,
        )
    )
    flows.extend(
        section_builders.build_page5_dast_a_packs(
            styles=styles,
            packs=packs,
        )
    )
    flows.extend(
        section_builders.build_page6_audit_attestation(
            styles=styles,
            merkle_root_hex=merkle.root_hex,
            merkle_signature_b64=merkle.signature_b64,
            merkle_count=merkle.count,
            merkle_timestamp_iso=merkle.timestamp_iso,
            merkle_signed=merkle.signed,
            ria_signature_hex_short=signed.signature_hex_short,
            ria_signature_b64_short=signed.signature_b64_short,
            ria_is_signed=ria_is_signed,
            signer_key_id=signer_key_id,
            underwriter_score=score,
            model_attestation_rows=model_attestation.as_table_rows(),
            invariant_violations=[
                {
                    "event_id": v.event_id,
                    "bundle_id": v.bundle_id,
                    "timestamp_iso": v.timestamp_iso,
                    "reason": v.reason,
                }
                for v in invariant_report.violations
            ],
            invariant_scanned_event_count=invariant_report.scanned_event_count,
            invariant_draft_applied_event_count=invariant_report.draft_applied_event_count,
        )
    )

    doc.build(flows)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Sample generation (boot-time)
# ---------------------------------------------------------------------------


SAMPLE_RIA_RELATIVE_PATH = Path("samples/sample-ria.pdf")


def ensure_sample_ria(
    *,
    samples_dir: Path,
    coverage_amount_usd: int = 5_000_000,
    signer: Optional[RIASigner] = None,
) -> RIAArtifact:
    """Generate the committed sample RIA into ``<samples_dir>/sample-ria.pdf``.

    Idempotent — re-running over an existing file overwrites it (operator
    can re-run the boot helper to refresh the sample with a new signer
    key). Uses :class:`SampleUnderwriterAgent` + stub data sources so the
    sample never depends on a live Gemini key + live upstream services.

    ``signer`` lets callers (the FastAPI lifespan) pass the operator's
    signer so the runtime ``/quote/ria/sample/verify`` endpoint can verify
    the sample against the live operator key. When ``signer`` is None we
    use a dedicated sample signer (priv key gitignored; pub key committed
    next to ``sample-ria.pdf`` so the public repo's verifier can verify
    the artifact offline).
    """
    samples_dir = Path(samples_dir).resolve()
    samples_dir.mkdir(parents=True, exist_ok=True)
    target = samples_dir / "sample-ria.pdf"

    # When the caller didn't pass a signer, build the public sample-signer
    # so the committed artifact's verifier (.pub) stays stable across
    # builds. BOTH halves of the keypair are committed for the sample so
    # any auditor can offline-verify the committed ``sample-ria.pdf``
    # without trusting a server roundtrip. The committed
    # ``samples/sample-signer.key`` is clearly marked demo-only — the
    # operator's runtime signer is a separate path
    # (``REEF_QUOTE_SIGNER_PRIV_KEY``) per .env.example. Phase B round 1
    # (R-1) replaced the prior gitignored-.keys/ design that produced
    # signature drift between committed PDF + .sig + .pub.
    sample_signer = signer or RIASigner(
        priv_key_path=str(samples_dir / "sample-signer.key"),
        pub_key_path=str(samples_dir / "sample-signer.pub"),
        signer_key_id="reef-sample-signer",
    )
    opts = RIAGenerateOptions(
        fleet_id="prod-fleet",
        audit_window_days=30,
        coverage_amount_usd=coverage_amount_usd,
        data_dir=str(samples_dir / ".working"),
        signer=sample_signer,
        underwriter=SampleUnderwriterAgent(
            coverage_amount_usd=coverage_amount_usd
        ),
        atlas_payload_override=_stub_atlas_payload(),
        policy_bus_payload_override=_stub_policy_bus_payload("prod-fleet"),
        dast_a_payload_override=_stub_dast_a_payload(),
        merkle_override=_sample_merkle_root(signer=sample_signer),
        # The committed sample never reads a live audit JSONL — pass an
        # empty event list so the audit-invariant scan reports zero
        # violations (and zero events scanned) deterministically.
        policy_bus_audit_override=[],
        force_sample_mode=True,
        fallback_on_data_source_error=True,
    )
    artifact = generate_ria(opts)

    # Move the rendered PDF + .sig into the committed sample location.
    target.write_bytes(artifact.pdf_bytes)
    sig_target = Path(str(target) + ".sig")
    sig_target.write_text(artifact.signature_b64 + "\n", encoding="ascii")

    return dataclasses.replace(artifact, pdf_path=target, sig_path=sig_target)


def _sample_merkle_root(*, signer: Optional[RIASigner] = None) -> SignedMerkleRoot:
    """Deterministic root for the committed sample RIA.

    Hashes a fixed string so the sample's audit-attestation page renders
    a non-empty root that's clearly stable across re-renders.

    When ``signer`` is supplied (the boot path for the public sample
    artifact), the merkle root is ALSO ed25519-signed by that signer so
    page 6's audit-attestation block shows a real base64 signature next
    to ``Signed: yes`` rather than the prior "(unsigned — operator did
    not attach a signer key)" message. This is half of R-2 — the other
    half is page 6 + the footer agreeing on the RIA's own signed status.
    """
    fixed = b"reef-sample-merkle-root-2026-05-18"
    root_hex = hashlib.sha256(fixed).hexdigest()
    if signer is not None:
        merkle_sig = signer.sign_pdf_bytes(fixed)
        return SignedMerkleRoot(
            root_hex=root_hex,
            signature_b64=merkle_sig.signature_b64,
            count=4321,
            timestamp_iso="2026-05-18T00:00:00Z",
            signed=True,
            dir="<sample — committed audit log snapshot>",
        )
    return SignedMerkleRoot(
        root_hex=root_hex,
        signature_b64="",
        count=4321,
        timestamp_iso="2026-05-18T00:00:00Z",
        signed=False,
        dir="<sample — committed audit log snapshot>",
    )


__all__ = [
    "RIAArtifact",
    "RIAGenerateOptions",
    "ModelAttestation",
    "AuditInvariantViolation",
    "AuditInvariantReport",
    "SampleUnderwriterAgent",
    "generate_ria",
    "ensure_sample_ria",
    "build_model_attestation",
    "scan_audit_for_invariants",
    "SAMPLE_RIA_RELATIVE_PATH",
    "REEF_VERSION",
]
