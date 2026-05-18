"""Color palette, fonts, and paragraph + table styles.

Visual identity: dense, auditor-readable, NOT marketing fluff. Inspired
by the cream-surface productivity vibe family (Notion / Linear / Cal.com)
+ a Reef teal accent that maps to the policy-bus dashboard. Typography
defaults to Helvetica / Helvetica-Bold (reportlab ships them) so the PDF
renders identically without any external font dependencies.
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, StyleSheet1
from reportlab.lib.units import inch, mm


# Palette — cream surface + slate ink + signal accents.
COLOR_INK = colors.HexColor("#0F172A")
COLOR_INK_MUTED = colors.HexColor("#475569")
COLOR_INK_FADED = colors.HexColor("#94A3B8")
COLOR_BG = colors.HexColor("#FBF9F4")        # cream
COLOR_PANEL = colors.HexColor("#F2EFE8")     # darker cream
COLOR_PANEL_EDGE = colors.HexColor("#E5E0D5")
COLOR_REEF_TEAL = colors.HexColor("#0E7C7B")
COLOR_REEF_TEAL_DARK = colors.HexColor("#0B5F5F")
COLOR_OK = colors.HexColor("#1E8E5F")
COLOR_WARN = colors.HexColor("#C77800")
COLOR_RISK = colors.HexColor("#B0413E")
COLOR_RISK_BG = colors.HexColor("#F7E3E1")
COLOR_OK_BG = colors.HexColor("#E1F1E9")
COLOR_WARN_BG = colors.HexColor("#FAEFD9")
COLOR_TABLE_HEADER_BG = colors.HexColor("#1F2937")
COLOR_TABLE_HEADER_FG = colors.HexColor("#F8FAFC")
COLOR_TABLE_ALT_ROW_BG = colors.HexColor("#F4F1EA")


# Page geometry.
PAGE_MARGIN_L = 0.6 * inch
PAGE_MARGIN_R = 0.6 * inch
PAGE_MARGIN_T = 0.55 * inch
PAGE_MARGIN_B = 0.65 * inch
HEADER_BAR_HEIGHT = 0.42 * inch
FOOTER_BAR_HEIGHT = 0.35 * inch


def build_stylesheet() -> StyleSheet1:
    """Return the paragraph stylesheet the section renderers use."""
    ss = StyleSheet1()
    ss.add(
        ParagraphStyle(
            name="ReefH1",
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=COLOR_INK,
            spaceAfter=6,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefH2",
            fontName="Helvetica-Bold",
            fontSize=12.5,
            leading=15,
            textColor=COLOR_REEF_TEAL_DARK,
            spaceBefore=8,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefH3",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=12,
            textColor=COLOR_INK,
            spaceBefore=4,
            spaceAfter=2,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefBody",
            fontName="Helvetica",
            fontSize=9.2,
            leading=12.2,
            textColor=COLOR_INK,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefBodyDense",
            fontName="Helvetica",
            fontSize=8.4,
            leading=11,
            textColor=COLOR_INK,
            spaceAfter=2,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefMono",
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=COLOR_INK_MUTED,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefBodyMuted",
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=COLOR_INK_MUTED,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefSmall",
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=COLOR_INK_MUTED,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefSmallBold",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=COLOR_INK,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefDisclaimer",
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=10.5,
            textColor=COLOR_INK_MUTED,
            leftIndent=4,
            spaceBefore=4,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefTierHeadline",
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            textColor=COLOR_REEF_TEAL,
            spaceBefore=4,
            spaceAfter=4,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefTableCell",
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=COLOR_INK,
        )
    )
    ss.add(
        ParagraphStyle(
            name="ReefTableHeader",
            fontName="Helvetica-Bold",
            fontSize=7.6,
            leading=9.5,
            textColor=COLOR_TABLE_HEADER_FG,
        )
    )
    return ss


def state_color(state: str) -> tuple:
    """Return ``(fg, bg)`` for a coverage state (``full | partial | none``)."""
    s = (state or "").lower()
    if s == "full":
        return COLOR_OK, COLOR_OK_BG
    if s == "partial":
        return COLOR_WARN, COLOR_WARN_BG
    return COLOR_RISK, COLOR_RISK_BG


__all__ = [
    "COLOR_INK",
    "COLOR_INK_MUTED",
    "COLOR_INK_FADED",
    "COLOR_BG",
    "COLOR_PANEL",
    "COLOR_PANEL_EDGE",
    "COLOR_REEF_TEAL",
    "COLOR_REEF_TEAL_DARK",
    "COLOR_OK",
    "COLOR_OK_BG",
    "COLOR_WARN",
    "COLOR_WARN_BG",
    "COLOR_RISK",
    "COLOR_RISK_BG",
    "COLOR_TABLE_HEADER_BG",
    "COLOR_TABLE_HEADER_FG",
    "COLOR_TABLE_ALT_ROW_BG",
    "PAGE_MARGIN_L",
    "PAGE_MARGIN_R",
    "PAGE_MARGIN_T",
    "PAGE_MARGIN_B",
    "HEADER_BAR_HEIGHT",
    "FOOTER_BAR_HEIGHT",
    "build_stylesheet",
    "state_color",
    "mm",
    "inch",
]
