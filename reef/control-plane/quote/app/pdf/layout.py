"""Page templates, headers, footers, watermark for the RIA PDF.

A :class:`RIADocTemplate` derives from reportlab's ``BaseDocTemplate``
and registers a single ``Frame`` per page. Headers + footers + optional
SAMPLE watermark are drawn on the canvas via the ``onPage`` callback.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Optional

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate

from app.pdf import style as st


@dataclass
class RIAHeaderContext:
    """Header/footer metadata painted on every page.

    Stored on the doc template so the canvas callback can pull it without
    reaching back into the section flowables.
    """

    fleet_id: str
    ria_id: str
    generated_at: dt.datetime
    signer_key_id: str
    reef_version: str
    is_sample: bool
    sample_watermark_text: str = (
        "SAMPLE — generated without live Gemini API key. "
        "Live RIAs include real Munich Re-rubric-grounded Gemini Pro scoring."
    )


PAGE_WIDTH, PAGE_HEIGHT = LETTER


class RIADocTemplate(BaseDocTemplate):
    """The single document template for the RIA PDF."""

    def __init__(self, filename: str, header_ctx: RIAHeaderContext, **kw) -> None:
        super().__init__(
            filename,
            pagesize=LETTER,
            leftMargin=st.PAGE_MARGIN_L,
            rightMargin=st.PAGE_MARGIN_R,
            topMargin=st.PAGE_MARGIN_T + st.HEADER_BAR_HEIGHT,
            bottomMargin=st.PAGE_MARGIN_B + st.FOOTER_BAR_HEIGHT,
            title=f"Reef Insurance Artifact — {header_ctx.ria_id}",
            author="Reef",
            subject="Reef Insurance Artifact (RIA)",
            creator="Reef Quote Layer 7 RIA generator",
            **kw,
        )
        self.header_ctx = header_ctx

        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            PAGE_WIDTH - self.leftMargin - self.rightMargin,
            PAGE_HEIGHT - self.bottomMargin - self.topMargin,
            id="reef-frame",
            showBoundary=0,
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        self.addPageTemplates(
            [
                PageTemplate(
                    id="reef-page",
                    frames=[frame],
                    onPage=self._draw_page_chrome,
                )
            ]
        )

    # ------------------------------------------------------------------
    # Canvas drawing callbacks
    # ------------------------------------------------------------------

    def _draw_page_chrome(self, canv: Canvas, _doc: BaseDocTemplate) -> None:
        ctx = self.header_ctx
        # Background tint (full bleed cream) so the page reads as a unit.
        canv.saveState()
        canv.setFillColor(st.COLOR_BG)
        canv.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
        canv.restoreState()

        # Header bar.
        _draw_header(canv, ctx)
        # Footer bar.
        _draw_footer(canv, ctx, page_num=canv.getPageNumber())
        # Sample watermark (only when is_sample).
        if ctx.is_sample:
            _draw_watermark(canv, ctx.sample_watermark_text)


# ---------------------------------------------------------------------------
# Header / footer / watermark drawing helpers
# ---------------------------------------------------------------------------


def _draw_header(canv: Canvas, ctx: RIAHeaderContext) -> None:
    canv.saveState()
    # Top accent stripe.
    canv.setFillColor(st.COLOR_REEF_TEAL_DARK)
    canv.rect(
        0,
        PAGE_HEIGHT - 0.18 * inch,
        PAGE_WIDTH,
        0.18 * inch,
        stroke=0,
        fill=1,
    )
    # Header text block.
    text_y = PAGE_HEIGHT - 0.18 * inch - 0.28 * inch
    canv.setFillColor(st.COLOR_INK)
    canv.setFont("Helvetica-Bold", 11)
    canv.drawString(st.PAGE_MARGIN_L, text_y, "REEF — Reef Insurance Artifact")
    canv.setFont("Helvetica", 8.5)
    canv.setFillColor(st.COLOR_INK_MUTED)
    right_text = f"Fleet {ctx.fleet_id}  ·  RIA {ctx.ria_id}  ·  v{ctx.reef_version}"
    canv.drawRightString(PAGE_WIDTH - st.PAGE_MARGIN_R, text_y, right_text)
    canv.restoreState()


def _draw_footer(canv: Canvas, ctx: RIAHeaderContext, *, page_num: int) -> None:
    canv.saveState()
    y_line = st.PAGE_MARGIN_B + st.FOOTER_BAR_HEIGHT - 0.08 * inch
    canv.setStrokeColor(st.COLOR_PANEL_EDGE)
    canv.setLineWidth(0.4)
    canv.line(st.PAGE_MARGIN_L, y_line, PAGE_WIDTH - st.PAGE_MARGIN_R, y_line)

    text_y = st.PAGE_MARGIN_B + 0.05 * inch
    canv.setFillColor(st.COLOR_INK_MUTED)
    canv.setFont("Helvetica", 7.5)
    left = (
        f"Generated {ctx.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ·  "
        f"Signed by {ctx.signer_key_id}"
    )
    canv.drawString(st.PAGE_MARGIN_L, text_y, left)

    canv.setFont("Helvetica-Bold", 7.5)
    canv.drawRightString(
        PAGE_WIDTH - st.PAGE_MARGIN_R,
        text_y,
        f"Page {page_num} of 6",
    )

    # Honest mid-line disclaimer — always present, never marketing copy.
    canv.setFont("Helvetica-Oblique", 6.8)
    canv.drawCentredString(
        PAGE_WIDTH / 2,
        text_y - 0.13 * inch,
        "ESTIMATED RANGE, not Munich-Re-published.  Rubric-grounded score, "
        "not a Lloyd's quote.",
    )
    canv.restoreState()


def _draw_watermark(canv: Canvas, text: str) -> None:
    """Diagonal "SAMPLE" watermark drawn behind page content."""
    canv.saveState()
    canv.translate(PAGE_WIDTH / 2, PAGE_HEIGHT / 2)
    canv.rotate(35)
    canv.setFillColor(st.COLOR_REEF_TEAL)
    # Manual transparency via gray-state — reportlab's setFillAlpha is the
    # cleanest way to dim it without fighting the PDF graphics state.
    try:
        canv.setFillAlpha(0.10)
    except AttributeError:  # pragma: no cover — old reportlab
        pass
    canv.setFont("Helvetica-Bold", 78)
    canv.drawCentredString(0, 0, "SAMPLE")
    try:
        canv.setFillAlpha(0.18)
    except AttributeError:  # pragma: no cover
        pass
    canv.setFont("Helvetica-Oblique", 9)
    canv.drawCentredString(0, -65, text[:90])
    canv.restoreState()


__all__ = [
    "RIAHeaderContext",
    "RIADocTemplate",
    "PAGE_WIDTH",
    "PAGE_HEIGHT",
]
