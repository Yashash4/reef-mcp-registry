"""Generate the Reef architecture diagram (1920x1080) at samples/architecture-diagram.png.

Horizontal 4-pillar flow + DAST-A continuous backbone underneath, matching
the §4 System Architecture section of the spec but rendered as a clean
landscape image judges can screenshot. Mirrors the reef-overview.html
visual language verbatim (zinc-950 bg, semantic 5-hue palette, Instrument
Serif italic display via Segoe Italic fallback, JetBrains Mono via
Consolas fallback).

The four pillars (left to right) and their data flow:

  Reef Atlas  --(signed AI-BOM)--> Reef Forge  --(signed bundle)-->
  Lobster Trap+Reef (Run)  --(merkle audit + AI-BOM)--> Reef Quote
  (Score) --> Reef Insurance Artifact (PDF)

  DAST-A runs CONTINUOUSLY underneath, emitting attack packs that feed
  Forge (draft policies via Gemini Flash) and Quote (heatmap data).

Run::

    python scripts/generate_architecture_diagram.py

Output is written to ``samples/architecture-diagram.png``. Deterministic;
re-running overwrites the existing file.
"""

from __future__ import annotations

from pathlib import Path
import math

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "samples" / "architecture-diagram.png"

# Canvas
W, H = 1920, 1080

# Palette — matches scripts/generate_cover_image.py + reef-overview.html
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
AMBER = (245, 158, 11)
AMBER_SOFT = (245, 158, 11, 30)
VIOLET = (167, 139, 250)
VIOLET_SOFT = (167, 139, 250, 30)

FONT_DIR = Path("C:/Windows/Fonts")


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = FONT_DIR / name
    if path.exists():
        return ImageFont.truetype(str(path), size=size)
    for fallback in ("DejaVuSans-Bold.ttf", "Arial.ttf", "arial.ttf"):
        try:
            return ImageFont.truetype(fallback, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


F_TITLE = _font("seguibl.ttf", 56)
F_DISPLAY = _font("seguibl.ttf", 42)
F_PILLAR = _font("seguisb.ttf", 32)
F_BODY = _font("segoeui.ttf", 22)
F_BODY_BOLD = _font("segoeuib.ttf", 22)
F_BODY_SM = _font("segoeui.ttf", 18)
F_MONO = _font("consola.ttf", 18)
F_MONO_SM = _font("consola.ttf", 15)
F_FLOW = _font("consolab.ttf", 16)


def rounded_rect(draw, xy, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def grid_backdrop(img: Image.Image) -> None:
    """Subtle 48px grid background, matching reef-overview.html .grid-bg."""
    draw = ImageDraw.Draw(img)
    step = 48
    for x in range(0, W, step):
        draw.line([(x, 0), (x, H)], fill=BORDER_SOFT, width=1)
    for y in range(0, H, step):
        draw.line([(0, y), (W, y)], fill=BORDER_SOFT, width=1)


def draw_header(img: Image.Image) -> None:
    """Top title bar."""
    draw = ImageDraw.Draw(img, "RGBA")
    # Wordmark left
    draw.text((48, 36), "REEF", font=_font("consolab.ttf", 32), fill=TEXT)
    draw.rectangle((48, 76, 184, 78), fill=EMERALD)
    # TechEx badge top-right
    badge_text = "REEF ARCHITECTURE  *  TECHEX 2026"
    bbox = F_MONO.getbbox(badge_text)
    bw = bbox[2] - bbox[0] + 32
    bh = 40
    bx = W - bw - 48
    by = 38
    rounded_rect(draw, (bx, by, bx + bw, by + bh), radius=20, fill=SURFACE_2, outline=BORDER, width=1)
    draw.text((bx + 16, by + 10), badge_text, font=F_MONO, fill=TEXT_2)

    # Main title centered
    title = "Discover  *  Build  *  Run  *  Score"
    bbox = F_TITLE.getbbox(title)
    tw = bbox[2] - bbox[0]
    draw.text(((W - tw) // 2, 122), title, font=F_TITLE, fill=TEXT)
    subtitle = "One product, four pillars + the continuous DAST-A adversary."
    bbox = F_BODY.getbbox(subtitle)
    tw = bbox[2] - bbox[0]
    draw.text(((W - tw) // 2, 200), subtitle, font=F_BODY, fill=TEXT_2)


def draw_pillar_card(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int,
                     accent: tuple, accent_soft: tuple, pillar: str, product: str,
                     blurb: list[str], chips: list[str], img: Image.Image) -> None:
    """Render a single pillar card with accent ribbon + headline + blurb + chips."""
    # Halo
    halo = Image.new("RGBA", (w + 80, h + 80), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.rectangle((40, 40, w + 40, h + 40), fill=accent_soft)
    halo = halo.filter(ImageFilter.GaussianBlur(radius=44))
    img.paste(halo, (x - 40, y - 40), halo)

    rounded_rect(draw, (x, y, x + w, y + h), radius=20, fill=SURFACE, outline=BORDER, width=2)
    # Accent ribbon top edge
    draw.rectangle((x, y, x + w, y + 6), fill=accent)

    # Pillar tag (Discover / Build / Run / Score)
    draw.text((x + 28, y + 28), pillar.upper(), font=F_MONO, fill=TEXT_3)

    # Product name
    draw.text((x + 28, y + 60), product, font=F_PILLAR, fill=TEXT)

    # Accent underline under product name
    bbox = F_PILLAR.getbbox(product)
    pw = bbox[2] - bbox[0]
    draw.rectangle((x + 28, y + 108, x + 28 + min(pw, w - 56), y + 110), fill=accent)

    # Blurb lines
    by = y + 132
    for line in blurb:
        draw.text((x + 28, by), line, font=F_BODY_SM, fill=TEXT_2)
        by += 26

    # Chips at the bottom of the card
    cy = y + h - 56
    cx = x + 28
    for chip_text in chips:
        bbox = F_MONO_SM.getbbox(chip_text)
        cw = bbox[2] - bbox[0] + 24
        ch = 28
        if cx + cw > x + w - 20:
            cx = x + 28
            cy += 34
        rounded_rect(draw, (cx, cy, cx + cw, cy + ch), radius=14, fill=SURFACE_2, outline=BORDER, width=1)
        draw.text((cx + 12, cy + 6), chip_text, font=F_MONO_SM, fill=TEXT_2)
        cx += cw + 8


def draw_arrow(draw: ImageDraw.ImageDraw, x1: int, y1: int, x2: int, y2: int,
               label: str, accent: tuple) -> None:
    """Draw a thick directional arrow with a label sitting above the line."""
    # Line
    draw.line((x1, y1, x2, y2), fill=accent, width=4)
    # Arrowhead (small filled triangle)
    head_size = 14
    angle = math.atan2(y2 - y1, x2 - x1)
    hx1 = x2 - head_size * math.cos(angle - math.pi / 8)
    hy1 = y2 - head_size * math.sin(angle - math.pi / 8)
    hx2 = x2 - head_size * math.cos(angle + math.pi / 8)
    hy2 = y2 - head_size * math.sin(angle + math.pi / 8)
    draw.polygon([(x2, y2), (hx1, hy1), (hx2, hy2)], fill=accent)
    # Label centered above the line
    bbox = F_FLOW.getbbox(label)
    lw = bbox[2] - bbox[0]
    lx = (x1 + x2) // 2 - lw // 2
    ly = min(y1, y2) - 28
    # Soft label backplate so it doesn't fight the grid
    rounded_rect(draw, (lx - 10, ly - 4, lx + lw + 10, ly + 22), radius=6, fill=SURFACE_2, outline=BORDER, width=1)
    draw.text((lx, ly), label, font=F_FLOW, fill=accent)


def draw_pillars(img: Image.Image) -> None:
    """Render the 4 pillar cards in a horizontal row."""
    draw = ImageDraw.Draw(img, "RGBA")

    # Layout — 4 cards across, 60px margin, 32px gap.
    margin_x = 60
    gap = 28
    card_w = (W - 2 * margin_x - 3 * gap) // 4
    card_h = 460
    y = 260

    pillars = [
        {
            "accent": CYAN,
            "soft": CYAN_SOFT,
            "tag": "Discover",
            "product": "Reef Atlas",
            "blurb": [
                "MCP signature registry +",
                "AI-BOM discovery.",
                "",
                "Cosign-keyless OIDC.",
                "Manifest pinning. STDIO",
                "entrypoint hash policy.",
            ],
            "chips": ["FastAPI", "ed25519", "Sigstore"],
        },
        {
            "accent": VIOLET,
            "soft": VIOLET_SOFT,
            "tag": "Build",
            "product": "Reef Forge",
            "blurb": [
                "Plain-English to signed",
                "YAML policy compiler.",
                "",
                "Shadow-test against",
                "a labeled benign corpus",
                "before signing bundles.",
            ],
            "chips": ["Gemini Pro/Flash", "PolicyDiff"],
        },
        {
            "accent": EMERALD,
            "soft": EMERALD_SOFT,
            "tag": "Run",
            "product": "Lobster Trap + Reef",
            "blurb": [
                "Edge DPI proxy. 4 actions:",
                "MODIFY, REDIRECT,",
                "QUARANTINE, HUMAN_REVIEW.",
                "",
                "SVID JWT. Merkle audit.",
                "MCP pre-ingress verify.",
            ],
            "chips": ["Go 1.22", "gRPC bus", "49-node fleet"],
        },
        {
            "accent": AMBER,
            "soft": AMBER_SOFT,
            "tag": "Score",
            "product": "Reef Quote",
            "blurb": [
                "Munich-Re-grounded",
                "underwriter agent. Reads",
                "AI-BOM + audit + coverage.",
                "",
                "Outputs the signed",
                "Reef Insurance Artifact.",
            ],
            "chips": ["Gemini 3 Pro", "reportlab", "RIA PDF"],
        },
    ]

    positions = []
    for i, p in enumerate(pillars):
        x = margin_x + i * (card_w + gap)
        draw_pillar_card(
            draw, x, y, card_w, card_h,
            p["accent"], p["soft"], p["tag"], p["product"],
            p["blurb"], p["chips"], img,
        )
        positions.append((x, y, card_w, card_h, p["accent"]))

    # Inter-pillar arrows placed in the gap between cards. Anchor at the
    # bottom-of-card baseline so labels never collide with body copy.
    arrow_y = y + card_h - 60
    flows = [
        ("signed AI-BOM", CYAN),
        ("signed policy bundle", VIOLET),
        ("merkle audit + AI-BOM", EMERALD),
    ]
    for i in range(3):
        x1 = positions[i][0] + positions[i][2] + 4
        x2 = positions[i + 1][0] - 4
        draw_arrow(draw, x1, arrow_y, x2, arrow_y, flows[i][0], flows[i][1])

    return positions


def draw_dast_a_backbone(img: Image.Image, pillar_positions: list) -> None:
    """DAST-A as a continuous horizontal backbone underneath the pillars,
    feeding Forge (drafts) + Quote (heatmap)."""
    draw = ImageDraw.Draw(img, "RGBA")

    # Backbone card spans Build and Run + Score (positions 1..3)
    x_left = pillar_positions[0][0]
    x_right = pillar_positions[3][0] + pillar_positions[3][2]
    y = 780
    h = 160

    # Halo
    halo = Image.new("RGBA", (x_right - x_left + 80, h + 80), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    hd.rectangle((40, 40, x_right - x_left + 40, h + 40), fill=(239, 68, 68, 26))
    halo = halo.filter(ImageFilter.GaussianBlur(radius=44))
    img.paste(halo, (x_left - 40, y - 40), halo)

    rounded_rect(draw, (x_left, y, x_right, y + h), radius=20, fill=SURFACE, outline=BORDER, width=2)
    draw.rectangle((x_left, y, x_right, y + 6), fill=RED)

    # Pillar tag
    draw.text((x_left + 28, y + 24), "CONTINUOUS  *  ADVERSARY", font=F_MONO, fill=TEXT_3)
    draw.text((x_left + 28, y + 52), "DAST-A", font=F_PILLAR, fill=TEXT)
    draw.rectangle((x_left + 28, y + 100, x_left + 140, y + 102), fill=RED)

    # Body to the right
    body_x = x_left + 240
    draw.text((body_x, y + 30), "Dynamic Agent Security Testing.", font=F_BODY_BOLD, fill=TEXT)
    draw.text((body_x, y + 60), "PPO RL adversary runs forever. Emits named/dated/CVE-mapped attack packs.", font=F_BODY_SM, fill=TEXT_2)
    draw.text((body_x, y + 86), "Feeds Forge with Gemini-Flash blue-team policy drafts; feeds Quote with the 30-day heatmap.", font=F_BODY_SM, fill=TEXT_2)
    draw.text((body_x, y + 116), "Packs: MCP-RCE-26.04  *  EchoLeak-26.05  *  MarkdownExfil-26.05  *  ToolChain-Drift-26.04", font=F_MONO_SM, fill=TEXT_3)

    # Vertical upward connectors from the DAST-A backbone to Forge & Quote bottoms
    # Forge card index 1
    f = pillar_positions[1]
    forge_x = f[0] + f[2] // 2
    forge_bottom = f[1] + f[3]
    draw_arrow(draw, forge_x, y - 4, forge_x, forge_bottom + 18, "policy drafts", VIOLET)

    # Quote card index 3
    q = pillar_positions[3]
    quote_x = q[0] + q[2] // 2
    quote_bottom = q[1] + q[3]
    draw_arrow(draw, quote_x, y - 4, quote_x, quote_bottom + 18, "30-day heatmap", AMBER)


def draw_footer(img: Image.Image) -> None:
    """Bottom strip: callout that Reef sits in the empty quadrant."""
    draw = ImageDraw.Draw(img, "RGBA")
    y = 980
    h = 64
    rounded_rect(draw, (60, y, W - 60, y + h), radius=16, fill=SURFACE_2, outline=BORDER, width=1)

    # Left chip
    chip_text = "EDGE  *  OPEN-SOURCE  *  SIGNED MCP  *  UNDERWRITER-SCORABLE"
    draw.text((84, y + 18), chip_text, font=F_MONO, fill=TEXT_2)

    # Right citation
    right_text = "Built on Veea Lobster Trap  *  MIT  *  github.com/Yashash4/reef-mcp-registry"
    bbox = F_MONO.getbbox(right_text)
    rw = bbox[2] - bbox[0]
    draw.text((W - 84 - rw, y + 18), right_text, font=F_MONO, fill=TEXT_3)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    grid_backdrop(img)

    # Vignette
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    cx, cy = W // 2, H // 2
    for r in range(int(math.hypot(cx, cy)), 0, -40):
        a = int(min(80, 80 * (r / math.hypot(cx, cy)) ** 2))
        od.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(0, 0, 0, a))
    img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

    draw_header(img)
    positions = draw_pillars(img)
    draw_dast_a_backbone(img, positions)
    draw_footer(img)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT, format="PNG", optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
