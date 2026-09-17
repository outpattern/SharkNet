"""
Generate assets/logo.png (clean, transparent shield) and assets/sharknet.ico
from a source banner image.

Usage:  python make_icon.py [source_image]
Default source: the SharkNet banner in Downloads.
"""
from __future__ import annotations

import sys
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ASSETS.mkdir(exist_ok=True)

DEFAULT_SRC = Path.home() / "Downloads" / "Gemini_Generated_Image_1okxsp1okxsp1okx.jpg"


def is_background(r, g, b):
    """Checkerboard = low-saturation dark gray. Keep bright/blue shield pixels."""
    mx, mn = max(r, g, b), min(r, g, b)
    sat = mx - mn
    return sat < 26 and mx < 115


def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SRC
    if not src.exists():
        print(f"source not found: {src}")
        sys.exit(1)

    img = Image.open(src).convert("RGBA")
    W, H = img.size
    px = img.load()

    # 1) find the shield bounding box in the top ~72% (exclude the text row)
    top = int(H * 0.72)
    minx, miny, maxx, maxy = W, H, 0, 0
    for y in range(0, top, 2):
        for x in range(0, W, 2):
            r, g, b, _ = px[x, y]
            if not is_background(r, g, b):
                if x < minx: minx = x
                if x > maxx: maxx = x
                if y < miny: miny = y
                if y > maxy: maxy = y
    if maxx <= minx:
        print("could not locate shield")
        sys.exit(1)
    pad = 12
    minx = max(0, minx - pad); miny = max(0, miny - pad)
    maxx = min(W, maxx + pad); maxy = min(top, maxy + pad)

    shield = img.crop((minx, miny, maxx, maxy))
    sp = shield.load()
    sw, sh = shield.size
    # 2) knock out the checkerboard background -> transparent
    for y in range(sh):
        for x in range(sw):
            r, g, b, a = sp[x, y]
            if is_background(r, g, b):
                sp[x, y] = (r, g, b, 0)

    # 3) square canvas (transparent), centered
    side = max(sw, sh)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(shield, ((side - sw) // 2, (side - sh) // 2), shield)

    logo_png = ASSETS / "logo.png"
    canvas.resize((512, 512), Image.LANCZOS).save(logo_png)
    print(f"wrote {logo_png}")

    ico = ASSETS / "sharknet.ico"
    canvas.save(ico, sizes=[(16, 16), (32, 32), (48, 48), (64, 64),
                            (128, 128), (256, 256)])
    print(f"wrote {ico}")


if __name__ == "__main__":
    main()
