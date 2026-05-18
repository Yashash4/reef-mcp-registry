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
3. Build the 6 sections, render to PDF bytes in memory.
4. Sign the PDF bytes (ed25519 over SHA-256) + write the detached `.sig`.
5. Persist ``<data_dir>/ria/<ria_id>.pdf`` and return the
   :class:`RIAArtifact` envelope.

Single function entrypoint :func:`generate_ria` keeps callers (API handler,
boot-time sample generator, integration test) simple.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import io
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Optional

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
# PDF rendering
# ---------------------------------------------------------------------------


REEF_VERSION = "0.1.0"


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
) -> bytes:
    """Render the 6-page RIA PDF and return the bytes."""
    buf = io.BytesIO()
    header_ctx = RIAHeaderContext(
        fleet_id=fleet_id,
        ria_id=ria_id,
        generated_at=generated_at,
        signer_key_id=signer_key_id,
        reef_version=REEF_VERSION,
        is_sample=sample_mode,
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
            signer_key_id=signer_key_id,
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
    # builds. The private key lives in a gitignored ``.keys/`` subdir so
    # re-running the boot helper reuses the same signer rather than
    # rotating on every build.
    sample_signer = signer or RIASigner(
        priv_key_path=str(samples_dir / ".keys" / "sample-signer.key"),
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
        merkle_override=_sample_merkle_root(),
        force_sample_mode=True,
        fallback_on_data_source_error=True,
    )
    artifact = generate_ria(opts)

    # Move the rendered PDF + .sig into the committed sample location.
    target.write_bytes(artifact.pdf_bytes)
    sig_target = Path(str(target) + ".sig")
    sig_target.write_text(artifact.signature_b64 + "\n", encoding="ascii")

    return dataclasses.replace(artifact, pdf_path=target, sig_path=sig_target)


def _sample_merkle_root() -> SignedMerkleRoot:
    """Deterministic root for the committed sample RIA.

    Hashes a fixed string so the sample's audit-attestation page renders
    a non-empty root that's clearly stable across re-renders.
    """
    fixed = b"reef-sample-merkle-root-2026-05-18"
    root_hex = hashlib.sha256(fixed).hexdigest()
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
    "SampleUnderwriterAgent",
    "generate_ria",
    "ensure_sample_ria",
    "SAMPLE_RIA_RELATIVE_PATH",
]
