"""
Generate the branded Inno Setup wizard artwork from the EXISTING SharkNet assets.

    python make_installer_art.py

Everything here is derived, never invented:
  * the artwork composites `assets/logo.png` (the real app logo) — no new mark is drawn
  * every colour is a literal copy of a CSS custom property from
    `frontend/css/1-base.css` (the app's dark theme), listed in PALETTE below
  * the wordmark mirrors the app header: "SHARK" in --text + "NET" in --accent
  * the background reproduces the app's own body backdrop: --bg-deep with the
    radial accent wash from `body { background: radial-gradient(...) }`

Outputs 24-bit BMPs (the only format Inno Setup accepts for wizard images) at the
sizes Inno picks between for DPI scaling:

    assets/installer/wizard-<W>x<H>.bmp        -> WizardImageFile      (side panel)
    assets/installer/wizard-small-<W>x<H>.bmp  -> WizardSmallImageFile (header badge)

The version number is deliberately NOT baked into the artwork, so a release bump
never invalidates these files.

Rendered at 4x and downsampled with LANCZOS, so edges stay clean at every DPI.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
LOGO = ROOT / "assets" / "logo.png"
OUT = ROOT / "assets" / "installer"

# ---- verbatim from frontend/css/1-base.css :root (dark theme) ----
PALETTE = {
    "bg_deep":   (0x0A, 0x0A, 0x0F),   # --bg-deep
    "bg_card":   (0x12, 0x12, 0x1A),   # --bg-card
    "bg_card_2": (0x17, 0x17, 0x22),   # --bg-card-2
    "line":      (0x23, 0x23, 0x3A),   # --line
    "accent":    (0x00, 0xD4, 0xFF),   # --accent
    "text":      (0xE6, 0xE6, 0xF5),   # --text
    "dim":       (0x7A, 0x7A, 0x97),   # --dim
}

SS = 4  # supersampling factor

# Inno Setup picks the closest match for the current DPI.
WIZARD_SIZES = [(164, 314), (205, 392), (246, 470), (328, 628)]
SMALL_SIZES = [(55, 58), (83, 87), (110, 116), (165, 174)]

# A restrained node-graph motif, echoing the network nodes already in the logo.
# Normalised (x, y) in the lower part of the panel; deterministic, never random.
NODES = [(0.14, 0.74), (0.38, 0.68), (0.62, 0.78), (0.86, 0.71),
         (0.26, 0.87), (0.54, 0.92), (0.78, 0.86)]
EDGES = [(0, 1), (1, 2), (2, 3), (0, 4), (4, 5), (5, 2), (5, 6), (6, 3), (1, 4)]


def _font(size: int, bold: bool = False):
    """Segoe UI — the app's own primary UI face (`font: 14px "Segoe UI", …`).
    Falls back to Pillow's default rather than failing the build."""
    for name in (("segoeuib.ttf", "segoeui.ttf") if bold else ("segoeui.ttf",)):
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    try:
        return ImageFont.truetype("arialbd.ttf" if bold else "arial.ttf", size)
    except Exception:
        return ImageFont.load_default()


def _blend(base, over, a):
    return tuple(int(base[i] + (over[i] - base[i]) * a) for i in range(3))


def _backdrop(w: int, h: int) -> Image.Image:
    """--bg-deep with a vertical lift toward --bg-card plus the app's
    radial-gradient accent wash anchored top-right."""
    img = Image.new("RGB", (w, h), PALETTE["bg_deep"])
    px = img.load()
    cx, cy = w * 0.80, h * -0.10          # 'at 80% -10%', as in the CSS
    radius = max(w, h) * 1.15
    for y in range(h):
        vert = (y / max(1, h - 1)) ** 1.25 * 0.55      # deep -> card, eased
        row = _blend(PALETTE["bg_deep"], PALETTE["bg_card"], vert)
        for x in range(w):
            d = (((x - cx) ** 2 + (y - cy) ** 2) ** 0.5) / radius
            glow = max(0.0, 1.0 - d) ** 2 * 0.16       # matches --grad-accent
            px[x, y] = _blend(row, PALETTE["accent"], glow) if glow > 0 else row
    return img


def _draw_mesh(img: Image.Image, w: int, h: int) -> None:
    d = ImageDraw.Draw(img, "RGBA")
    pts = [(x * w, y * h) for x, y in NODES]
    for a, b in EDGES:
        d.line([pts[a], pts[b]], fill=PALETTE["accent"] + (34,), width=max(1, SS // 2))
    for x, y in pts:
        r = SS * 1.7
        d.ellipse([x - r, y - r, x + r, y + r], fill=PALETTE["accent"] + (70,))
        r2 = SS * 0.7
        d.ellipse([x - r2, y - r2, x + r2, y + r2], fill=PALETTE["accent"] + (150,))


def build_wizard(w: int, h: int) -> Image.Image:
    W, H = w * SS, h * SS
    img = _backdrop(W, H)
    _draw_mesh(img, W, H)
    d = ImageDraw.Draw(img, "RGBA")

    # --- logo (the real asset, aspect preserved) ---
    logo = Image.open(LOGO).convert("RGBA")
    target_w = int(W * 0.56)
    logo = logo.resize((target_w, int(target_w * logo.height / logo.width)), Image.LANCZOS)
    lx, ly = (W - logo.width) // 2, int(H * 0.17)
    img.paste(logo, (lx, ly), logo)

    # --- wordmark: SHARK (--text) + NET (--accent), as in the app header ---
    fs = int(W * 0.132)
    f = _font(fs, bold=True)
    track = max(1, int(fs * 0.07))          # letter-spacing
    left, right = "SHARK", "NET"

    def measure(s):
        return sum(d.textlength(c, font=f) + track for c in s) - track

    total = measure(left) + measure(right)
    x = (W - total) / 2
    y = ly + logo.height + int(H * 0.035)
    for s, col in ((left, PALETTE["text"]), (right, PALETTE["accent"])):
        for c in s:
            d.text((x, y), c, font=f, fill=col)
            x += d.textlength(c, font=f) + track

    # --- accent rule + tagline (mirrors the app's dim caption treatment) ---
    ry = y + fs * 1.55
    rw = W * 0.30
    d.line([(W - rw) / 2, ry, (W + rw) / 2, ry],
           fill=PALETTE["accent"] + (165,), width=max(1, SS // 2))

    # auto-fit the tagline so it always keeps a margin, at every DPI variant
    tag = "LAN CONTROL  ·  NETWORK SECURITY"
    max_tw = W * 0.80
    fs2 = int(W * 0.046)
    while fs2 > 4:
        f2 = _font(fs2, bold=False)
        track2 = max(1, int(fs2 * 0.11))
        tw = sum(d.textlength(c, font=f2) + track2 for c in tag) - track2
        if tw <= max_tw:
            break
        fs2 -= 1
    tx, ty = (W - tw) / 2, ry + fs2 * 0.95
    for c in tag:
        d.text((tx, ty), c, font=f2, fill=PALETTE["dim"])
        tx += d.textlength(c, font=f2) + track2

    # --- 1px accent edge on the inner side, echoing the app's --line borders ---
    d.line([(W - SS, 0), (W - SS, H)], fill=PALETTE["line"], width=SS)
    return img.resize((w, h), Image.LANCZOS)


def build_small(w: int, h: int) -> Image.Image:
    """Header badge. Background is --bg-card so it blends into the themed
    header panel set in installer.iss [Code]."""
    W, H = w * SS, h * SS
    img = Image.new("RGB", (W, H), PALETTE["bg_card"])
    logo = Image.open(LOGO).convert("RGBA")
    pad = int(min(W, H) * 0.06)
    box_w, box_h = W - pad * 2, H - pad * 2
    scale = min(box_w / logo.width, box_h / logo.height)
    logo = logo.resize((max(1, int(logo.width * scale)), max(1, int(logo.height * scale))),
                       Image.LANCZOS)
    img.paste(logo, ((W - logo.width) // 2, (H - logo.height) // 2), logo)
    return img.resize((w, h), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    made = []
    for w, h in WIZARD_SIZES:
        p = OUT / f"wizard-{w}x{h}.bmp"
        build_wizard(w, h).save(p, "BMP")
        made.append(p)
    for w, h in SMALL_SIZES:
        p = OUT / f"wizard-small-{w}x{h}.bmp"
        build_small(w, h).save(p, "BMP")
        made.append(p)
    for p in made:
        print(f"  {p.relative_to(ROOT)}  ({p.stat().st_size:,} bytes)")
    print(f"\n{len(made)} files written to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
