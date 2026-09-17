"""
Front-end regression guards for the UI fixes made during the i18n/F3 pass.

These are source-inspection tests (no DOM) that pin the specific bugs we hit so
they can't silently come back:

  * language dropdown was painted BEHIND the control card (topbar backdrop-filter
    made a static stacking context) -> topbar must be a positioned context, and
    the layer order must stay content < topbar < modal < toasts;
  * the block-confirmation toast was buried behind the modal's blurred backdrop
    -> toasts must sit above the modal;
  * "Cut others" did nothing because `e.currentTarget` is null after the awaited
    confirm dialog -> the handler must capture the button BEFORE awaiting;
  * provider chips must render as an aligned grid, ordered by popularity
    (Netflix/YouTube/WhatsApp/Shahid/Watch iT first);
  * the YOU/GATEWAY badge must never be the element that gets clipped.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = ROOT / "frontend" / "css"
JS = ROOT / "frontend" / "js"


def _css():
    return "\n".join(p.read_text(encoding="utf-8") for p in CSS.glob("*.css"))


def _zindex(selector_body):
    m = re.search(r"z-index\s*:\s*(\d+)", selector_body)
    return int(m.group(1)) if m else None


def _rule(css, selector):
    # crude single-rule extractor: `selector{ ... }`
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    return m.group(1) if m else ""


def test_layer_order_topbar_modal_toasts():
    css = _css()
    topbar = _rule(css, ".topbar")
    toasts = _rule(css, ".toasts")
    modal = _rule(css, ".modal")
    assert "position:relative" in topbar.replace(" ", ""), "topbar must be a positioned stacking context"
    tb, md, ts = _zindex(topbar), _zindex(modal), _zindex(toasts)
    assert tb and md and ts, f"missing z-index (topbar={tb} modal={md} toasts={ts})"
    # content(0) < topbar < modal < toasts  — toast/dropdown must never hide behind content/modal
    assert 0 < tb < md < ts, f"bad layer order: topbar={tb} modal={md} toasts={ts}"


def test_cut_others_captures_button_before_await():
    src = (JS / "f-theme.js").read_text(encoding="utf-8")
    # the cutOthers handler awaits confirmDialog, so it must NOT pass e.currentTarget to guard()
    assert "guard(btn," in src, "cutOthers must guard() the pre-captured button"
    assert 'guard(e.currentTarget, () => api("/api/cut_all_except_me' not in src, \
        "cutOthers passes e.currentTarget after await -> null -> API never fires"
    # and it must capture the button before awaiting
    assert re.search(r"const btn = e\.currentTarget;\s*//.*await", src), "must capture btn before await"


def test_service_popularity_order():
    src = (JS / "a-core.js").read_text(encoding="utf-8")
    m = re.search(r"const SERVICE_ORDER\s*=\s*\[(.*?)\]", src, re.S)
    assert m, "SERVICE_ORDER missing"
    ids = re.findall(r'"([^"]+)"', m.group(1))
    assert ids[:5] == ["netflix", "youtube", "whatsapp", "shahid", "watch-it"], \
        f"popularity order must start Netflix/YouTube/WhatsApp/Shahid/Watch iT, got {ids[:5]}"
    assert "sortServicesByPopularity(r.services" in src, "loadServices must sort by popularity"


def test_service_chips_are_a_grid():
    css = _css()
    psets = _rule(css, ".psets")
    assert "display:grid" in psets.replace(" ", ""), "provider chips must be an aligned grid"


def test_badge_never_clipped():
    css = _css()
    badges = _rule(css, ".dev .badges")
    badge = _rule(css, ".badge")
    assert "flex:none" in badges.replace(" ", ""), ".dev .badges must not shrink (YOU/GATEWAY clipping)"
    assert "white-space:nowrap" in badge.replace(" ", ""), ".badge must not wrap"


def test_footer_dedication_is_localized():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert 'data-i18n="footer.dedication"' in html, "footer dedication must be localized"
