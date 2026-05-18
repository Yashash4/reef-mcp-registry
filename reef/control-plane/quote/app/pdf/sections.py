"""Section builders — one function per RIA page.

Each function returns a list of reportlab ``Flowable`` objects ready to
hand to the ``BaseDocTemplate.build`` call.

Pages:

1. :func:`build_page1_executive_summary`
2. :func:`build_page2_ai_bom`
3. :func:`build_page3_coverage_matrix`
4. :func:`build_page4_attack_heatmap`
5. :func:`build_page5_dast_a_packs`
6. :func:`build_page6_audit_attestation`

Cross-page divider is a :class:`PageBreak`. Section text is sourced
verbatim from ``docs/24-GROUNDING.md`` + the underwriter agent output so
no claim escapes that wasn't grounded.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.data_sources.attack_telemetry import (
    TELEMETRY_BUCKETS,
    TelemetryDay,
)
from app.data_sources.coverage_matrix import (
    MITRE_ATLAS_IDS,
    MITRE_ATLAS_NAMES,
    OWASP_ASI_IDS,
    OWASP_ASI_NAMES,
)
from app.pdf import style as st
from app.underwriter_agent import (
    MOSAIC_MUNICH_RE_ANNOUNCEMENT_DATE,
    MOSAIC_MUNICH_RE_CAP_USD,
    PHASE_2_DISCLAIMER,
    UnderwriterScore,
)


# ---------------------------------------------------------------------------
# Common Table styles
# ---------------------------------------------------------------------------


def _header_row_style(start_col: int = 0, end_col: int = -1) -> list[tuple]:
    return [
        ("BACKGROUND", (start_col, 0), (end_col, 0), st.COLOR_TABLE_HEADER_BG),
        ("TEXTCOLOR", (start_col, 0), (end_col, 0), st.COLOR_TABLE_HEADER_FG),
        ("FONTNAME", (start_col, 0), (end_col, 0), "Helvetica-Bold"),
        ("FONTSIZE", (start_col, 0), (end_col, 0), 7.6),
        ("ALIGN", (start_col, 0), (end_col, 0), "LEFT"),
        ("VALIGN", (start_col, 0), (end_col, 0), "MIDDLE"),
        ("LEFTPADDING", (start_col, 0), (end_col, 0), 4),
        ("RIGHTPADDING", (start_col, 0), (end_col, 0), 4),
        ("TOPPADDING", (start_col, 0), (end_col, 0), 4),
        ("BOTTOMPADDING", (start_col, 0), (end_col, 0), 4),
    ]


def _zebra_row_style(start_row: int, end_row: int) -> list[tuple]:
    out: list[tuple] = []
    for r in range(start_row, end_row + 1):
        if (r - start_row) % 2 == 1:
            out.append(
                ("BACKGROUND", (0, r), (-1, r), st.COLOR_TABLE_ALT_ROW_BG)
            )
    return out


# ---------------------------------------------------------------------------
# Page 1 — Executive summary
# ---------------------------------------------------------------------------


def build_page1_executive_summary(
    *,
    styles,
    ria_id: str,
    fleet_id: str,
    generated_at: dt.datetime,
    signer_key_id: str,
    signature_hex_short: str,
    underwriter_score: UnderwriterScore,
    sample_mode: bool,
) -> list[Flowable]:
    """Page 1 — Reef Risk Tier headline + reasoning + premium range.

    Verbatim quotes:

    * :attr:`UnderwriterScore.tier_label_with_framing` — the tier headline.
    * ``score.estimated_premium_range_usd_annual.disclaimer`` — the
      "ESTIMATED RANGE, not Munich-Re-published" string.
    * :data:`PHASE_2_DISCLAIMER` — the Phase 2 broker-API commitment.
    """
    out: list[Flowable] = []

    out.append(Paragraph("Reef Insurance Artifact (RIA)", styles["ReefH1"]))
    out.append(
        Paragraph(
            "Signed evidence pack for AI agent fleet underwriting · "
            "rubric-grounded against Munich Re's public AI insurance framework "
            "(aiSure performance-warranty product).",
            styles["ReefBodyMuted"],
        )
    )
    out.append(Spacer(1, 0.12 * inch))

    # Identity card.
    identity_rows = [
        ["RIA ID", ria_id],
        ["Fleet", fleet_id],
        ["Generated", generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Signing identity", signer_key_id],
        ["Sigstore-style signature (truncated)", signature_hex_short],
    ]
    if sample_mode:
        identity_rows.append(["Mode", "SAMPLE (no live Gemini API key)"])
    id_table = Table(
        identity_rows,
        colWidths=[1.8 * inch, 5.0 * inch],
    )
    id_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (0, -1), st.COLOR_INK_MUTED),
                ("TEXTCOLOR", (1, 0), (1, -1), st.COLOR_INK),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BACKGROUND", (0, 0), (-1, -1), st.COLOR_PANEL),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, st.COLOR_PANEL_EDGE),
                ("BOX", (0, 0), (-1, -1), 0.5, st.COLOR_PANEL_EDGE),
            ]
        )
    )
    out.append(id_table)
    out.append(Spacer(1, 0.18 * inch))

    # Headline tier.
    out.append(
        Paragraph(
            underwriter_score.tier_label_with_framing,
            styles["ReefTierHeadline"],
        )
    )
    out.append(Spacer(1, 0.04 * inch))
    # Reasoning paragraph.
    out.append(Paragraph("Underwriter reasoning", styles["ReefH3"]))
    out.append(Paragraph(_escape(underwriter_score.reasoning), styles["ReefBody"]))

    # Premium range.
    premium = underwriter_score.estimated_premium_range_usd_annual
    out.append(Spacer(1, 0.06 * inch))
    out.append(Paragraph("Estimated annual premium range", styles["ReefH3"]))
    premium_text = (
        f"<b>USD ${int(premium.low):,} – ${int(premium.high):,}</b> "
        f"for ${int(premium.coverage_amount_usd):,} aggregate coverage."
    )
    out.append(Paragraph(premium_text, styles["ReefBody"]))
    out.append(
        Paragraph(
            _escape(premium.anchor),
            styles["ReefSmall"],
        )
    )
    out.append(
        Paragraph(
            _escape(premium.disclaimer),
            styles["ReefDisclaimer"],
        )
    )

    # Recommended exclusions.
    if underwriter_score.recommended_exclusions:
        out.append(Spacer(1, 0.04 * inch))
        out.append(Paragraph("Recommended exclusions", styles["ReefH3"]))
        bullet_text = "<br/>".join(
            "• " + _escape(x) for x in underwriter_score.recommended_exclusions
        )
        out.append(Paragraph(bullet_text, styles["ReefBodyDense"]))

    # Phase-2 disclaimer (verbatim).
    out.append(Spacer(1, 0.10 * inch))
    out.append(
        Paragraph(
            _escape(underwriter_score.phase_2_disclaimer),
            styles["ReefDisclaimer"],
        )
    )
    out.append(PageBreak())
    return out


# ---------------------------------------------------------------------------
# Page 2 — AI-BOM tree
# ---------------------------------------------------------------------------


def build_page2_ai_bom(
    *,
    styles,
    ai_bom: dict[str, Any],
) -> list[Flowable]:
    out: list[Flowable] = []
    out.append(Paragraph("AI-BOM — Bill of Materials", styles["ReefH1"]))
    counts = ai_bom.get("registry_entry_counts", {}) or {}
    summary_line = (
        f"{counts.get('verified', 0)} verified MCP servers · "
        f"{counts.get('quarantined', 0)} quarantined · "
        f"{counts.get('poisoned', 0)} poisoned  "
        f"(Atlas total: {ai_bom.get('registry_total', 0)} entries across "
        f"{ai_bom.get('publishers_total', 0)} publishers)"
    )
    out.append(Paragraph(summary_line, styles["ReefBodyMuted"]))
    out.append(Spacer(1, 0.06 * inch))

    # ---- MCP servers ----
    out.append(Paragraph("MCP servers (Atlas registry)", styles["ReefH2"]))
    # Page 2 must fit on a single LETTER page next to the bundle + fleet
    # tables. We surface the highest-signal subset: every non-verified row
    # (poisoned + quarantined are the auditor's primary attention) plus up
    # to N verified rows. The aggregate counts at the top still carry the
    # full picture honestly.
    MCP_TABLE_VERIFIED_CAP = 6
    all_servers = ai_bom.get("mcp_servers", []) or []
    non_verified = [s for s in all_servers if s.get("status") != "verified"]
    verified = [s for s in all_servers if s.get("status") == "verified"]
    displayed = non_verified + verified[:MCP_TABLE_VERIFIED_CAP]
    hidden_count = max(0, len(all_servers) - len(displayed))
    mcp_rows = [
        ["mcpName", "Version", "Transports", "SDK", "Status", "Publisher", "Registered"]
    ]
    for entry in displayed:
        status = entry.get("status", "unknown")
        mcp_rows.append(
            [
                Paragraph(_escape(entry.get("mcp_name", "")), styles["ReefTableCell"]),
                _escape(entry.get("version", "")),
                _escape(",".join(entry.get("transports", []))),
                _escape(entry.get("sdk_version", "")),
                _status_pill(status),
                _escape((entry.get("publisher_id") or "")[:24]),
                _escape((entry.get("registered_at") or "")[:19]),
            ]
        )
    if len(mcp_rows) == 1:
        mcp_rows.append(["—", "—", "—", "—", "—", "—", "—"])
    mcp_table = Table(
        mcp_rows,
        colWidths=[
            2.0 * inch,
            0.55 * inch,
            0.7 * inch,
            0.85 * inch,
            0.7 * inch,
            1.2 * inch,
            0.95 * inch,
        ],
        repeatRows=1,
    )
    mcp_table.setStyle(
        TableStyle(
            _header_row_style()
            + _zebra_row_style(1, len(mcp_rows) - 1)
            + [
                ("FONTSIZE", (0, 1), (-1, -1), 7.2),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 1), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, st.COLOR_PANEL_EDGE),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
            ]
        )
    )
    out.append(mcp_table)
    if hidden_count > 0:
        out.append(
            Paragraph(
                f"… and {hidden_count} additional verified MCP server(s) not listed above. "
                f"Aggregate counts at the top of the page reflect the full inventory.",
                styles["ReefSmall"],
            )
        )

    # ---- Agents ----
    out.append(Spacer(1, 0.08 * inch))
    out.append(Paragraph("Agents (declared via SVID)", styles["ReefH2"]))
    agents = ai_bom.get("agents", []) or []
    if not agents:
        out.append(
            Paragraph(
                "No active agent registry in v1. Phase 2 brings the SPIFFE/SPIRE "
                "identity attestation that populates this table from the live "
                "policy bus subscriber list.",
                styles["ReefBodyDense"],
            )
        )
    else:
        agent_rows = [["SVID subject", "Declared intent", "Identity verified"]]
        for a in agents:
            agent_rows.append(
                [
                    _escape(a.get("svid_subject", "")),
                    _escape(a.get("declared_intent", "")),
                    "yes" if a.get("identity_verified") else "no",
                ]
            )
        agent_table = Table(
            agent_rows,
            colWidths=[3.4 * inch, 2.0 * inch, 1.2 * inch],
            repeatRows=1,
        )
        agent_table.setStyle(
            TableStyle(
                _header_row_style()
                + _zebra_row_style(1, len(agent_rows) - 1)
                + [
                    ("FONTSIZE", (0, 1), (-1, -1), 7.4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 3),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        out.append(agent_table)

    # ---- Active policy bundle ----
    out.append(Spacer(1, 0.08 * inch))
    out.append(Paragraph("Policy bundle (active)", styles["ReefH2"]))
    active = ai_bom.get("active_bundle")
    if active:
        bundle_rows = [
            ["Bundle ID", _escape(active.get("bundle_id", ""))],
            ["Version", _escape(active.get("version", ""))],
            ["Signer key ID", _escape(active.get("signer_key_id", ""))],
            ["Published", _format_unix(active.get("published_at_unix", 0))],
        ]
        bt = Table(bundle_rows, colWidths=[1.5 * inch, 5.3 * inch])
        bt.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.8),
                    ("TEXTCOLOR", (0, 0), (0, -1), st.COLOR_INK_MUTED),
                    ("BACKGROUND", (0, 0), (-1, -1), st.COLOR_PANEL),
                    ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ]
            )
        )
        out.append(bt)
    else:
        out.append(
            Paragraph(
                "No active policy bundle published yet (policy bus is up but "
                "the operator has not signed a bundle for this fleet).",
                styles["ReefBodyDense"],
            )
        )

    # ---- Fleet summary ----
    out.append(Spacer(1, 0.08 * inch))
    fleet_summary = ai_bom.get("fleet_node_summary", {}) or {}
    fleet_line = (
        f"Fleet nodes: {ai_bom.get('fleet_node_count', 0)} total · "
        f"{fleet_summary.get('online', 0)} online · "
        f"{fleet_summary.get('applied', 0)} applied current bundle · "
        f"{fleet_summary.get('verify_failed', 0)} verify-failed"
    )
    out.append(Paragraph(fleet_line, styles["ReefBodyMuted"]))

    out.append(PageBreak())
    return out


# ---------------------------------------------------------------------------
# Page 3 — Coverage matrix
# ---------------------------------------------------------------------------


def build_page3_coverage_matrix(
    *,
    styles,
    owasp_coverage: dict[str, dict[str, Any]],
    mitre_coverage: dict[str, dict[str, Any]],
) -> list[Flowable]:
    out: list[Flowable] = []
    out.append(Paragraph("Coverage matrix", styles["ReefH1"]))
    out.append(
        Paragraph(
            "OWASP Agentic Top 10 + MITRE ATLAS techniques mapped to the "
            "live Reef policy rules and DAST-A attack packs. Honest legend: "
            "<b>full</b> = pack-validated AND policy-rule covered; <b>partial</b> "
            "= one signal but not both; <b>none</b> = no signal yet.",
            styles["ReefBodyMuted"],
        )
    )
    out.append(Spacer(1, 0.08 * inch))

    out.append(
        Paragraph("OWASP Agentic Top 10 (ASI01..ASI10)", styles["ReefH2"])
    )
    asi_rows: list[list[Any]] = [
        ["ID", "Category", "Coverage", "Pack signal", "Policy-rule signal", "Pack IDs"]
    ]
    for asi_id in OWASP_ASI_IDS:
        cell = owasp_coverage.get(asi_id, {})
        asi_rows.append(
            [
                asi_id,
                OWASP_ASI_NAMES.get(asi_id, asi_id),
                _state_pill(cell.get("state", "none")),
                "yes" if cell.get("blocked_by_reef") else "no",
                "yes" if cell.get("policy_rule_signal") else "no",
                _escape(", ".join(cell.get("pack_ids", []))),
            ]
        )
    asi_table = Table(
        asi_rows,
        colWidths=[0.55 * inch, 1.85 * inch, 0.85 * inch, 0.85 * inch, 1.15 * inch, 1.7 * inch],
        repeatRows=1,
    )
    asi_table.setStyle(
        TableStyle(
            _header_row_style()
            + _zebra_row_style(1, len(asi_rows) - 1)
            + [
                ("FONTSIZE", (0, 1), (-1, -1), 7.4),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, st.COLOR_PANEL_EDGE),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
                ("TOPPADDING", (0, 1), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
            ]
        )
    )
    out.append(asi_table)

    out.append(Spacer(1, 0.10 * inch))
    out.append(
        Paragraph("MITRE ATLAS techniques (subset Reef maps to)", styles["ReefH2"])
    )
    mitre_rows: list[list[Any]] = [
        ["Technique", "Name", "Coverage", "Pack IDs"]
    ]
    for mid in MITRE_ATLAS_IDS:
        cell = mitre_coverage.get(mid, {})
        mitre_rows.append(
            [
                mid,
                MITRE_ATLAS_NAMES.get(mid, mid),
                _state_pill(cell.get("state", "none")),
                _escape(", ".join(cell.get("pack_ids", []))),
            ]
        )
    mitre_table = Table(
        mitre_rows,
        colWidths=[1.0 * inch, 2.3 * inch, 0.85 * inch, 2.8 * inch],
        repeatRows=1,
    )
    mitre_table.setStyle(
        TableStyle(
            _header_row_style()
            + _zebra_row_style(1, len(mitre_rows) - 1)
            + [
                ("FONTSIZE", (0, 1), (-1, -1), 7.4),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
            ]
        )
    )
    out.append(mitre_table)

    out.append(Spacer(1, 0.08 * inch))
    out.append(
        Paragraph(
            "Honest gap declaration: Reef v1 has <b>partial</b> coverage of "
            "ASI06/07 (Identity Spoofing — JWT SVID middleware is in place but "
            "full SPIFFE/SPIRE is Phase 2) and <b>partial</b> coverage of "
            "AML.T0040 (rate-limit + identity present, but not full "
            "exfiltration-cap controls). Reef does NOT claim full coverage "
            "everywhere — the matrix above is honest.",
            styles["ReefBodyDense"],
        )
    )
    out.append(PageBreak())
    return out


# ---------------------------------------------------------------------------
# Page 4 — 30-day attack heatmap
# ---------------------------------------------------------------------------


def build_page4_attack_heatmap(
    *,
    styles,
    telemetry: list[TelemetryDay],
) -> list[Flowable]:
    out: list[Flowable] = []
    out.append(Paragraph("30-day attack heatmap", styles["ReefH1"]))
    demo_days = sum(1 for d in telemetry if d.is_demo_seed)
    real_days = len(telemetry) - demo_days
    legend = (
        f"{real_days} day(s) of real audit data · {demo_days} day(s) labelled "
        f"<b>(demo seed)</b>. Cells are coloured by per-day count: white = 0, "
        f"warm = high. Buckets aggregate OWASP/MITRE tags into 6 rows for "
        f"visual scan."
    )
    out.append(Paragraph(legend, styles["ReefBodyMuted"]))
    out.append(Spacer(1, 0.05 * inch))

    # We render a transposed grid: rows = bucket, cols = day.
    # First column = bucket label, then one narrow column per day.
    col_count = len(telemetry) + 1
    day_col_width = (
        (7.4 * inch) - 1.3 * inch
    ) / max(len(telemetry), 1)
    day_col_width = max(0.12 * inch, min(0.30 * inch, day_col_width))

    header = ["Bucket"] + [d.date_iso[5:] for d in telemetry]
    rows: list[list[Any]] = [header]
    max_count = 1
    for d in telemetry:
        for c in d.by_bucket.values():
            if c > max_count:
                max_count = c
    for bucket in TELEMETRY_BUCKETS:
        row: list[Any] = [bucket]
        for d in telemetry:
            count = d.by_bucket.get(bucket, 0)
            row.append(str(count) if count else "")
        rows.append(row)
    totals_row: list[Any] = ["Total"]
    for d in telemetry:
        totals_row.append(str(d.total) if d.total else "")
    rows.append(totals_row)

    col_widths = [1.3 * inch] + [day_col_width] * len(telemetry)
    table = Table(rows, colWidths=col_widths, repeatRows=1)

    style = _header_row_style()
    style.append(("FONTSIZE", (1, 0), (-1, 0), 5.4))
    style.append(("ROTATE", (1, 0), (-1, 0), 90))  # ROTATE ignored by some viewers; tested OK in modern.
    style.append(("FONTSIZE", (0, 1), (0, -1), 7.4))
    style.append(("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"))
    style.append(("ALIGN", (1, 1), (-1, -1), "CENTER"))
    style.append(("VALIGN", (0, 1), (-1, -1), "MIDDLE"))
    style.append(("FONTSIZE", (1, 1), (-1, -1), 6))
    style.append(("LEFTPADDING", (0, 0), (-1, -1), 1))
    style.append(("RIGHTPADDING", (0, 0), (-1, -1), 1))
    style.append(("TOPPADDING", (0, 0), (-1, -1), 1.5))
    style.append(("BOTTOMPADDING", (0, 0), (-1, -1), 1.5))
    style.append(("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE))
    style.append(("INNERGRID", (0, 0), (-1, -1), 0.15, st.COLOR_PANEL_EDGE))
    # Heat colouring.
    bucket_count = len(TELEMETRY_BUCKETS)
    for r, bucket in enumerate(TELEMETRY_BUCKETS, start=1):
        for c, d in enumerate(telemetry, start=1):
            count = d.by_bucket.get(bucket, 0)
            if count <= 0:
                continue
            intensity = min(1.0, count / max(max_count, 1))
            bg = _heat_color(intensity, is_demo=d.is_demo_seed)
            style.append(("BACKGROUND", (c, r), (c, r), bg))
    # Totals row.
    style.append(("FONTNAME", (0, bucket_count + 1), (-1, bucket_count + 1), "Helvetica-Bold"))
    style.append(("BACKGROUND", (0, bucket_count + 1), (-1, bucket_count + 1), st.COLOR_PANEL))
    table.setStyle(TableStyle(style))
    out.append(table)

    out.append(Spacer(1, 0.06 * inch))
    out.append(
        Paragraph(
            "<b>(demo seed)</b> days are clearly flagged and the cell heat is "
            "rendered with a cooler hue so the auditor can distinguish real "
            "events from seeded data at a glance.",
            styles["ReefSmall"],
        )
    )
    out.append(PageBreak())
    return out


def _heat_color(intensity: float, *, is_demo: bool):
    """Return a reportlab color for a heatmap cell.

    Real events: warm reef teal ramp. Demo seed: cooler grey-cream ramp.
    """
    from reportlab.lib.colors import Color

    intensity = max(0.0, min(1.0, intensity))
    if is_demo:
        # Cool grey ramp.
        base_r, base_g, base_b = (0.78, 0.78, 0.74)
        return Color(
            base_r - 0.35 * intensity,
            base_g - 0.35 * intensity,
            base_b - 0.30 * intensity,
        )
    # Warm cream-to-burnt-orange ramp.
    if intensity < 0.5:
        # cream → amber
        t = intensity / 0.5
        return Color(
            0.96 - 0.16 * t,
            0.90 - 0.20 * t,
            0.78 - 0.40 * t,
        )
    # amber → red
    t = (intensity - 0.5) / 0.5
    return Color(
        0.80 - 0.10 * t,
        0.70 - 0.40 * t,
        0.38 - 0.20 * t,
    )


# ---------------------------------------------------------------------------
# Page 5 — DAST-A attack pack catalog
# ---------------------------------------------------------------------------


def build_page5_dast_a_packs(
    *,
    styles,
    packs: list[dict[str, Any]],
) -> list[Flowable]:
    out: list[Flowable] = []
    out.append(Paragraph("DAST-A attack pack catalog", styles["ReefH1"]))
    out.append(
        Paragraph(
            f"{len(packs)} attack pack(s) catalogued. Per-pack OWASP / MITRE "
            "mapping and current Reef block status.",
            styles["ReefBodyMuted"],
        )
    )
    out.append(Spacer(1, 0.05 * inch))

    rows: list[list[Any]] = [
        ["Pack ID", "Name", "OWASP", "MITRE", "Discovered by", "Blocked"]
    ]
    for pack in packs:
        rows.append(
            [
                _escape(pack.get("pack_id", "")),
                Paragraph(_escape(pack.get("name", "")), styles["ReefTableCell"]),
                _escape(", ".join(pack.get("owasp_asi", []) or [])),
                _escape(", ".join(pack.get("mitre_atlas", []) or [])),
                Paragraph(
                    _escape(pack.get("discovered_by", "")), styles["ReefTableCell"]
                ),
                "yes" if pack.get("blocked_by_reef") else "no",
            ]
        )
    if len(rows) == 1:
        rows.append(["—", "no packs catalogued", "—", "—", "—", "—"])

    table = Table(
        rows,
        colWidths=[
            1.05 * inch,
            1.85 * inch,
            0.75 * inch,
            1.0 * inch,
            2.0 * inch,
            0.65 * inch,
        ],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            _header_row_style()
            + _zebra_row_style(1, len(rows) - 1)
            + [
                ("FONTSIZE", (0, 1), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 1), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
            ]
        )
    )
    out.append(table)

    # OX Security citation footnote (verbatim) for the MCP-RCE pack.
    mcp_rce = next(
        (p for p in packs if p.get("pack_id") == "MCP-RCE-26.04"), None
    )
    if mcp_rce and (mcp_rce.get("ox_security_citation") or ""):
        out.append(Spacer(1, 0.10 * inch))
        out.append(
            Paragraph(
                "<b>MCP-RCE-26.04 — OX Security April 2026 citation (verbatim):</b>",
                styles["ReefSmallBold"],
            )
        )
        out.append(
            Paragraph(
                _escape(mcp_rce.get("ox_security_citation", "")),
                styles["ReefDisclaimer"],
            )
        )

    out.append(PageBreak())
    return out


# ---------------------------------------------------------------------------
# Page 6 — Audit attestation + Phase 2
# ---------------------------------------------------------------------------


PHASE_2_COMMITMENTS_VERBATIM: tuple[str, ...] = (
    "Real broker API integration (Bold Penguin / CoverGenius / Vouch dev sandboxes)",
    "Real TerraFabric SDK integration (replacing the stub)",
    "A2A delegation with monotonic scope narrowing (OAuth 2.1 + SVID-backed macaroons / biscuits)",
    "Full SPIFFE/SPIRE deployment + live Rekor anchoring",
)


def build_page6_audit_attestation(
    *,
    styles,
    merkle_root_hex: str,
    merkle_signature_b64: str,
    merkle_count: int,
    merkle_timestamp_iso: str,
    merkle_signed: bool,
    ria_signature_hex_short: str,
    ria_signature_b64_short: str,
    signer_key_id: str,
) -> list[Flowable]:
    out: list[Flowable] = []
    out.append(Paragraph("Audit attestation + Phase 2 commitments", styles["ReefH1"]))
    out.append(
        Paragraph(
            "The RIA is signed (ed25519) over the full PDF bytes. The Merkle "
            "audit root below cryptographically pins every action verdict the "
            "fleet recorded during the audit window.",
            styles["ReefBodyMuted"],
        )
    )
    out.append(Spacer(1, 0.06 * inch))

    merkle_table = Table(
        [
            ["Merkle root (hex)", _escape(merkle_root_hex or "(empty — fresh audit log)")],
            ["Signature (base64)", _escape(merkle_signature_b64 or "(unsigned — operator did not attach a signer key)")],
            ["Event count", str(merkle_count)],
            ["Generated", _escape(merkle_timestamp_iso)],
            ["Signed", "yes" if merkle_signed else "no"],
            ["Algorithm", "SHA-256 leaves; ed25519 root signature"],
        ],
        colWidths=[1.5 * inch, 5.3 * inch],
    )
    merkle_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.6),
                ("TEXTCOLOR", (0, 0), (0, -1), st.COLOR_INK_MUTED),
                ("BACKGROUND", (0, 0), (-1, -1), st.COLOR_PANEL),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("FONTNAME", (1, 0), (1, 1), "Courier"),
            ]
        )
    )
    out.append(merkle_table)

    out.append(Spacer(1, 0.06 * inch))
    out.append(Paragraph("Verifier CLI", styles["ReefH3"]))
    cli = (
        "<font face=\"Courier\">lobstertrap audit verify --event-id &lt;id&gt; "
        f"--root {(merkle_root_hex or '&lt;root&gt;')[:24]}…"
        "</font>"
    )
    out.append(Paragraph(cli, styles["ReefBodyDense"]))
    out.append(
        Paragraph(
            "Operators run the verifier against the JSONL audit log to prove a "
            "specific event was included in the signed root. Exit code 0 = "
            "proof verified; non-zero = tampered.",
            styles["ReefSmall"],
        )
    )

    # Phase 2 commitments — VERBATIM list.
    out.append(Spacer(1, 0.12 * inch))
    out.append(Paragraph("Phase 2 commitments", styles["ReefH2"]))
    for i, item in enumerate(PHASE_2_COMMITMENTS_VERBATIM, start=1):
        out.append(
            Paragraph(
                f"{i}. {_escape(item)}",
                styles["ReefBody"],
            )
        )

    # Phase 2 disclaimer — VERBATIM.
    out.append(Spacer(1, 0.06 * inch))
    out.append(
        Paragraph(
            "<b>Phase 2 disclaimer (verbatim):</b> " + _escape(PHASE_2_DISCLAIMER),
            styles["ReefDisclaimer"],
        )
    )

    # RIA signature block at the bottom — embedded for human display.
    out.append(Spacer(1, 0.12 * inch))
    out.append(Paragraph("RIA signature (Sigstore-style)", styles["ReefH3"]))
    sig_table = Table(
        [
            ["Signer key ID", _escape(signer_key_id)],
            ["Signature (hex, truncated)", _escape(ria_signature_hex_short)],
            ["Signature (base64, truncated)", _escape(ria_signature_b64_short)],
            ["Algorithm", "ed25519 over SHA-256(pdf_bytes)"],
            [
                "Anchor",
                f"Munich Re aiSure framework · Mosaic + Munich Re ${MOSAIC_MUNICH_RE_CAP_USD:,} cap "
                f"({MOSAIC_MUNICH_RE_ANNOUNCEMENT_DATE})",
            ],
        ],
        colWidths=[1.7 * inch, 5.1 * inch],
    )
    sig_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.6),
                ("TEXTCOLOR", (0, 0), (0, -1), st.COLOR_INK_MUTED),
                ("BACKGROUND", (0, 0), (-1, -1), st.COLOR_PANEL),
                ("BOX", (0, 0), (-1, -1), 0.4, st.COLOR_PANEL_EDGE),
                ("FONTNAME", (1, 1), (1, 2), "Courier"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    out.append(sig_table)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _escape(text: Any) -> str:
    """HTML-escape user-supplied text for Paragraph rendering."""
    s = "" if text is None else str(text)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _state_pill(state: str) -> Paragraph:
    """Coloured paragraph pill for ``full | partial | none``."""
    fg, bg = st.state_color(state)
    label = {"full": "FULL", "partial": "PARTIAL", "none": "NONE"}.get(
        state.lower(), state.upper()
    )
    rgb = f"#{int(fg.red*255):02X}{int(fg.green*255):02X}{int(fg.blue*255):02X}"
    bg_rgb = f"#{int(bg.red*255):02X}{int(bg.green*255):02X}{int(bg.blue*255):02X}"
    return Paragraph(
        f'<font backColor="{bg_rgb}" color="{rgb}"><b> {label} </b></font>',
        _pill_style(),
    )


def _status_pill(status: str) -> Paragraph:
    """Coloured paragraph pill for Atlas status (verified|quarantined|poisoned)."""
    lc = (status or "unknown").lower()
    if lc == "verified":
        fg, bg = st.COLOR_OK, st.COLOR_OK_BG
    elif lc == "quarantined":
        fg, bg = st.COLOR_WARN, st.COLOR_WARN_BG
    elif lc == "poisoned":
        fg, bg = st.COLOR_RISK, st.COLOR_RISK_BG
    else:
        fg, bg = st.COLOR_INK_MUTED, st.COLOR_PANEL
    rgb = f"#{int(fg.red*255):02X}{int(fg.green*255):02X}{int(fg.blue*255):02X}"
    bg_rgb = f"#{int(bg.red*255):02X}{int(bg.green*255):02X}{int(bg.blue*255):02X}"
    return Paragraph(
        f'<font backColor="{bg_rgb}" color="{rgb}"><b> {lc.upper()} </b></font>',
        _pill_style(),
    )


def _pill_style():
    from reportlab.lib.styles import ParagraphStyle

    return ParagraphStyle(
        name="_pill_style",
        fontName="Helvetica",
        fontSize=7.2,
        leading=9,
        alignment=0,
    )


def _format_unix(ts: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(float(ts), tz=dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return str(ts)


__all__ = [
    "PHASE_2_COMMITMENTS_VERBATIM",
    "build_page1_executive_summary",
    "build_page2_ai_bom",
    "build_page3_coverage_matrix",
    "build_page4_attack_heatmap",
    "build_page5_dast_a_packs",
    "build_page6_audit_attestation",
]
