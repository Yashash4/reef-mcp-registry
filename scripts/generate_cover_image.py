"""Generate the Reef submission cover image (1920x1080) at samples/cover-image.png.

Triple-panel composition per docs/superpowers/specs/2026-05-18-reef-design.md §11.5:

  TOP    — red "BIND DENIED - MCP-RCE-26.04" overlay on an MCP server icon
            with signature-verification-fail glyph.
  MIDDLE — 7x7 grid of 49 dots with green stadium-wave ripple animation
            captured as a single still frame (mid-ripple).
  BOTTOM — a signed RIA PDF reading: "Risk tier B+ * Suggested premium
            range $42k-$54k for $5M coverage * Grounded on Munich Re's
            public AI insurance framework"
  Tagline: "The signed supply chain MCP needs. The artifact your
            underwriter can price."

Color palette + typography match reef-overview.html verbatim:

  --bg:        #0a0a0a   (canvas)
  --surface:   #111113   (panel)
  --surface-2: #18181b   (inner panel)
  --border:    #27272a
  --emerald:   #10b981
  --cyan:      #06b6d4
  --red:       #ef4444
  --amber:     #f59e0b
  --violet:    #a78bfa
  --text:      #fafafa
  --text-2:    #a1a1aa
  --text-3:    #71717a

Run::

    python scripts/generate_cover_image.py

Output is written to ``samples/cover-image.png``. The script is fully
deterministic; re-running it overwrites the existing file.
"""

from __future__ import annotations

from pathlib import Path
import math

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "samples" / "cover-image.png"

# Canvas
W, H = 1920, 1080

# Palette
BG = (10, 10, 10)
SURFACE = (17, 17, 19)
SURFACE_2 = (24, 24, 27)
BORDER = (39, 39, 42)
BORDER_SOFT = (31, 31, 35)
TEXT = (250, 250, 250)
TEXT_2 = (161, 161, 170)
TEXT_3 = (113, 113, 122)
EMERALD = (16, 185, 129)
EMERALD_SOFT = (16, 185, 129, 30)
CYAN = (6, 182, 212)
CYAN_SOFT = (6, 182, 212, 30)
RED = (239, 68, 68)
RED_SOFT = (239, 68, 68, 36)
AMBER = (245, 158, 11)
AMBER_SOFT = (245, 158, 11, 30)
VIOLET = (167, 139, 250)

# Windows font discovery (deterministic — these ship on every Windows host;
# the script also falls back to PIL's default font if missing so other
# operators can re-run on macOS / Linux).
FONT_DIR = Path("C:/Windows/Fonts")


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = FONT_DIR / name
    if path.exists():
        return ImageFont.truetype(str(path), size=size)
    # Cross-platform fallback chain
    for fallback in ("DejaVuSans-Bold.ttf", "Arial.ttf", "arial.ttf"):
        try:
            return ImageFont.truetype(fallback, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


F_DISPLAY = _font("seguibl.ttf", 80)  # Segoe UI Black for display headlines
F_DISPLAY_FALLBACK = _font("arialbd.ttf", 80)
F_HEADLINE = _font("seguisb.ttf", 56)  # Semibold
F_BODY = _font("segoeui.ttf", 30)
F_BODY_BOLD = _font("segoeuib.ttf", 30)
F_BODY_SM = _font("segoeui.ttf", 22)
F_BODY_SM_BOLD = _font("segoeuib.ttf", 22)
F_MONO_LG = _font("consolab.ttf", 36)
F_MONO = _font("consola.ttf", 24)
F_MONO_SM = _font("consola.ttf", 18)
F_TAGLINE = _font("seguili.ttf", 38)  # Segoe Light Italic (display-ish)

# Some hosts won't have Segoe UI Black; fall back to Arial Bold for the
# main display headline. We probe at runtime.
if not (FONT_DIR / "seguibl.ttf").exists():
    F_DISPLAY = F_DISPLAY_FALLBACK


def rounded_rect(draw, xy, radius, fill=None, outline=None, width=1):
    """Pillow's rounded_rectangle wrapper that handles outline width cleanly."""
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def grid_backdrop(img: Image.Image) -> None:
    """Subtle 48px grid background, matching reef-overview.html .grid-bg."""
    draw = ImageDraw.Draw(img)
    step = 48
    for x in range(0, W, step):
        draw.line([(x, 0), (x, H)], fill=BORDER_SOFT, width=1)
    for y in range(0, H, step):
        draw.line([(0, y), (W, y)], fill=BORDER_SOFT, width=1)


def vignette(img: Image.Image) -> None:
    """Radial darken at the corners so the panels pop."""
    mask = Image.new("L", (W, H), 0)
    md = ImageDraw.Draw(mask)
    cx, cy = W // 2, H // 2
    max_r = int(math.hypot(cx, cy))
    for r in range(max_r, 0, -8):
        alpha = int(min(180, 180 * (r / max_r) ** 2))
        md.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            fill=alpha,
        )
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 255))
    img.paste(overlay, (0, 0), mask)


def chip(draw, x, y, text, color=EMERALD, font=F_BODY_SM_BOLD):
    """Pill-shaped chip matching reef-overview.html .chip."""
    pad_x, pad_y = 16, 8
    bbox = font.getbbox(text)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    w = tw + pad_x * 2 + 18
    h = th + pad_y * 2 + 6
    rounded_rect(
        draw,
        (x, y, x + w, y + h),
        radius=h // 2,
        fill=SURFACE_2,
        outline=BORDER,
        width=2,
    )
    # Dot
    cy = y + h // 2
    draw.ellipse((x + 12, cy - 5, x + 22, cy + 5), fill=color)
    draw.text((x + 32, y + pad_y - 4), text, font=font, fill=TEXT_2)
    return w, h


def draw_top_panel(img: Image.Image) -> None:
    """TOP panel — MCP supply chain block beat.

    Layout: dark surface card occupying y=80..400. Left side carries the
    huge red "BIND DENIED" headline + violation code; right side carries
    the MCP server icon with the signature-verification-fail glyph.
    """
    draw = ImageDraw.Draw(img, "RGBA")

    # Panel
    px, py, pw, ph = 80, 80, W - 160, 320
    rounded_rect(draw, (px, py, px + pw, py + ph), radius=24, fill=SURFACE, outline=BORDER, width=2)
    # Red glow ribbon along the top edge
    draw.rectangle((px, py, px + pw, py + 6), fill=RED)
    # Red soft inner halo
    halo = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.rectangle((0, 0, pw, ph), fill=RED_SOFT)
    halo = halo.filter(ImageFilter.GaussianBlur(radius=70))
    img.paste(halo, (px, py), halo)

    # Chip at top-left of the panel
    chip(draw, px + 32, py + 24, "PRIMARY HEADLINE", color=RED)
    chip(draw, px + 254, py + 24, "MCP SUPPLY CHAIN", color=CYAN)

    # Big BIND DENIED headline
    draw.text(
        (px + 32, py + 80),
        "BIND DENIED",
        font=F_DISPLAY,
        fill=RED,
    )
    # Violation code below
    draw.text(
        (px + 32, py + 180),
        "MCP-RCE-26.04",
        font=F_MONO_LG,
        fill=TEXT,
    )
    draw.text(
        (px + 32, py + 232),
        "Anthropic MCP STDIO RCE  *  7,000+ servers  *  150M+ downloads",
        font=F_BODY_SM,
        fill=TEXT_2,
    )
    draw.text(
        (px + 32, py + 264),
        "OX Security disclosure, April 2026  *  Reef blocks at handshake",
        font=F_BODY_SM,
        fill=TEXT_3,
    )

    # MCP server icon on the right side
    icon_x = px + pw - 360
    icon_y = py + 70
    icon_w = 280
    icon_h = 180
    rounded_rect(
        draw,
        (icon_x, icon_y, icon_x + icon_w, icon_y + icon_h),
        radius=18,
        fill=SURFACE_2,
        outline=BORDER,
        width=2,
    )
    # "Server" stack glyph
    for i in range(3):
        sy = icon_y + 24 + i * 36
        draw.rounded_rectangle(
            (icon_x + 32, sy, icon_x + icon_w - 32, sy + 24),
            radius=6,
            fill=(35, 35, 40),
            outline=BORDER,
            width=1,
        )
        # Status LED — bottom row red (the poisoned one), others cyan
        led_color = RED if i == 2 else CYAN
        draw.ellipse((icon_x + 48, sy + 8, icon_x + 58, sy + 18), fill=led_color)
        draw.text(
            (icon_x + 70, sy + 1),
            ["com.anthropic/server-fs    v1.2.0", "io.github.modelctxp/...    v0.6.3", "com.attacker-example/evil 0.5.0"][i],
            font=F_MONO_SM,
            fill=TEXT_2 if i < 2 else RED,
        )

    # Signature-fail X over the bottom (poisoned) row
    cx = icon_x + icon_w + 10
    cy = icon_y + icon_h - 22
    draw.ellipse((cx - 22, cy - 22, cx + 22, cy + 22), fill=RED, outline=(120, 0, 0), width=2)
    draw.line((cx - 9, cy - 9, cx + 9, cy + 9), fill=TEXT, width=4)
    draw.line((cx + 9, cy - 9, cx - 9, cy + 9), fill=TEXT, width=4)


def draw_middle_panel(img: Image.Image) -> None:
    """MIDDLE panel — 7x7 fleet grid with a stadium-wave ripple.

    Single still frame mid-ripple: green wave has propagated through the
    leftmost 3 columns; rows 4-7 still cyan/unacked. Bottom-right cell
    is amber to suggest a kept-old-active node (the honest-state nod).
    """
    draw = ImageDraw.Draw(img, "RGBA")

    px, py, pw, ph = 80, 420, W - 160, 320
    rounded_rect(draw, (px, py, px + pw, py + ph), radius=24, fill=SURFACE, outline=BORDER, width=2)
    # Cyan ribbon top edge
    draw.rectangle((px, py, px + pw, py + 6), fill=CYAN)
    halo = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.rectangle((0, 0, pw, ph), fill=EMERALD_SOFT)
    halo = halo.filter(ImageFilter.GaussianBlur(radius=80))
    img.paste(halo, (px, py), halo)

    # Chip
    chip(draw, px + 32, py + 24, "49-NODE FLEET", color=EMERALD)
    chip(draw, px + 220, py + 24, "SIGNED POLICY BUNDLE v4", color=CYAN)
    chip(draw, px + 552, py + 24, "STADIUM WAVE  *  <4s", color=AMBER)

    # 7x7 grid
    grid_size = 7
    cell = 28
    gap = 8
    total = grid_size * cell + (grid_size - 1) * gap
    gx = px + 60
    gy = py + 100
    # Center grid vertically in the remaining panel
    gy = py + (ph - total) // 2 + 20

    # Headline text on the right
    txt_x = gx + total + 80
    draw.text(
        (txt_x, py + 90),
        "49 nodes acknowledging",
        font=F_HEADLINE,
        fill=TEXT,
    )
    draw.text(
        (txt_x, py + 156),
        "a Sigstore-signed policy bundle.",
        font=F_HEADLINE,
        fill=TEXT,
    )
    draw.text(
        (txt_x, py + 228),
        "Stadium wave ripples through last_ack_unix rank in under 4 seconds.",
        font=F_BODY,
        fill=TEXT_2,
    )

    for row in range(grid_size):
        for col in range(grid_size):
            cx = gx + col * (cell + gap) + cell // 2
            cy = gy + row * (cell + gap) + cell // 2

            # Ripple state: cells get progressively more "acked" the further
            # left they are. Bottom-right one is amber (kept_old_active).
            if (row, col) == (grid_size - 1, grid_size - 1):
                color = AMBER
                glow = AMBER_SOFT
            elif col < 3:
                color = EMERALD
                glow = EMERALD_SOFT
            elif col == 3:
                # Crest of the wave — brighter, with halo
                color = (32, 220, 160)
                glow = (16, 185, 129, 90)
            else:
                color = CYAN
                glow = CYAN_SOFT

            # Glow halo
            for r in (24, 18, 12):
                hue = (*glow[:3], max(8, glow[3] - (r - 12) * 3))
                draw.ellipse(
                    (cx - r, cy - r, cx + r, cy + r),
                    fill=hue,
                )
            # Cell
            draw.ellipse((cx - 10, cy - 10, cx + 10, cy + 10), fill=color)


def draw_bottom_panel(img: Image.Image) -> None:
    """BOTTOM panel — the signed RIA PDF.

    A stylized PDF surface with the Reef Insurance Artifact summary copy
    matching the committed sample-ria.pdf headline numbers (Tier B+, $42k-
    $54k for $5M coverage, Munich Re-grounded). The verbatim ESTIMATED-
    RANGE disclaimer prints at the bottom of the page.
    """
    draw = ImageDraw.Draw(img, "RGBA")

    px, py, pw, ph = 80, 760, W - 160, 240
    rounded_rect(draw, (px, py, px + pw, py + ph), radius=24, fill=SURFACE, outline=BORDER, width=2)
    # Amber ribbon top edge
    draw.rectangle((px, py, px + pw, py + 6), fill=AMBER)

    # Amber soft inner halo
    halo = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.rectangle((0, 0, pw, ph), fill=AMBER_SOFT)
    halo = halo.filter(ImageFilter.GaussianBlur(radius=70))
    img.paste(halo, (px, py), halo)

    # PDF mock on the left
    pdf_x = px + 32
    pdf_y = py + 32
    pdf_w = 220
    pdf_h = ph - 64
    rounded_rect(
        draw,
        (pdf_x, pdf_y, pdf_x + pdf_w, pdf_y + pdf_h),
        radius=10,
        fill=(245, 245, 240),  # cream surface from RIA palette
        outline=BORDER,
        width=2,
    )
    # PDF header bar
    draw.rectangle((pdf_x, pdf_y, pdf_x + pdf_w, pdf_y + 32), fill=(13, 71, 79))  # reef-teal
    draw.text(
        (pdf_x + 12, pdf_y + 6),
        "REEF INSURANCE ARTIFACT",
        font=F_MONO_SM,
        fill=(240, 240, 230),
    )
    # PDF body — fake content lines
    for i in range(7):
        ly = pdf_y + 52 + i * 14
        line_w = pdf_w - 32 - (i % 3) * 24
        draw.rectangle((pdf_x + 16, ly, pdf_x + 16 + line_w, ly + 4), fill=(180, 175, 165))
    # Tier badge
    badge_x = pdf_x + 16
    badge_y = pdf_y + pdf_h - 56
    draw.rounded_rectangle(
        (badge_x, badge_y, badge_x + 64, badge_y + 28),
        radius=8,
        fill=(13, 71, 79),
    )
    draw.text((badge_x + 12, badge_y + 1), "B+", font=F_MONO_LG, fill=(240, 240, 230))
    # Signature lines
    sig_y = pdf_y + pdf_h - 22
    draw.rectangle((pdf_x + 96, sig_y, pdf_x + pdf_w - 16, sig_y + 4), fill=(13, 71, 79))
    draw.rectangle((pdf_x + 96, sig_y + 8, pdf_x + pdf_w - 60, sig_y + 12), fill=(150, 145, 135))

    # Headline copy on the right
    rx = px + 32 + pdf_w + 40
    chip(draw, rx, py + 24, "REEF INSURANCE ARTIFACT", color=AMBER)
    chip(draw, rx + 360, py + 24, "ED25519 SIGNED", color=EMERALD)

    draw.text(
        (rx, py + 76),
        "Risk tier B+  *  Premium $42k-$54k for $5M",
        font=F_HEADLINE,
        fill=TEXT,
    )
    draw.text(
        (rx, py + 142),
        "Grounded on Munich Re's public AI insurance framework (aiSure(TM)).",
        font=F_BODY,
        fill=TEXT_2,
    )
    draw.text(
        (rx, py + 180),
        "ESTIMATED RANGE, not Munich-Re-published. Phase 2 integrates real broker API.",
        font=F_BODY_SM,
        fill=TEXT_3,
    )


def draw_tagline(img: Image.Image) -> None:
    """Tagline at the bottom edge of the canvas."""
    draw = ImageDraw.Draw(img)
    tagline_1 = "The signed supply chain MCP needs."
    tagline_2 = "The artifact your underwriter can price."
    # We render a narrow strip below the bottom panel — but the bottom
    # panel already extends to y=1000, leaving only y=1000..1080 for
    # tagline content. Put it as a single line, centered, in tasteful
    # display italic.
    y = 1020
    full = f"{tagline_1}   {tagline_2}"
    bbox = F_TAGLINE.getbbox(full)
    tw = bbox[2] - bbox[0]
    x = (W - tw) // 2
    draw.text((x, y), full, font=F_TAGLINE, fill=TEXT_2)


def draw_reef_logo(img: Image.Image) -> None:
    """Top-left wordmark + 'TechEx 2026' badge."""
    draw = ImageDraw.Draw(img)
    # Wordmark
    draw.text((32, 18), "REEF", font=F_MONO_LG, fill=TEXT)
    # Hairline below
    draw.rectangle((32, 60, 168, 62), fill=EMERALD)
    # TechEx badge top-right
    badge_text = "TECHEX  2026"
    bbox = F_MONO_SM.getbbox(badge_text)
    bw = bbox[2] - bbox[0] + 24
    bh = 30
    bx = W - bw - 32
    by = 24
    draw.rounded_rectangle(
        (bx, by, bx + bw, by + bh),
        radius=15,
        fill=SURFACE_2,
        outline=BORDER,
        width=1,
    )
    draw.text((bx + 12, by + 5), badge_text, font=F_MONO_SM, fill=TEXT_2)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    grid_backdrop(img)
    # Vignette (apply via paste of darker overlay)
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    # Radial-ish vignette by drawing concentric ellipses with decreasing
    # alpha towards the center
    cx, cy = W // 2, H // 2
    for r in range(int(math.hypot(cx, cy)), 0, -40):
        a = int(min(80, 80 * (r / math.hypot(cx, cy)) ** 2))
        od.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(0, 0, 0, a))
    img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

    draw_reef_logo(img)
    draw_top_panel(img)
    draw_middle_panel(img)
    draw_bottom_panel(img)
    draw_tagline(img)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT, format="PNG", optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
