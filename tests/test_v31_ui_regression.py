"""
V3.1 Windows UI regression gate.

These pin the six real-Windows defects that a browser demo could not catch, so
they can never silently come back:

  1. the custom desktop toast must NOT become a taskbar / Alt+Tab window — the
     tool-window ex-style is applied while the window is still hidden, BEFORE the
     first show (a taskbar button created on that first show would persist);
  2. no ghost rectangle / stale shadow — the host window HIDES itself the moment
     the card stack drains, and the desktop card carries no drop-shadow;
  3. one event = one card, max 3 visible, the rest queue (no merged "N new
     devices" summary) — enforced by the renderer + router, checked here too;
  5. the Settings → Language controls are SharkNet-styled, not native buttons;
  6. the Settings close "X" is SharkNet-styled, not a native white square;
  7. language + theme quick controls are gone from the header (see test_v31_ux).

The lifecycle tests drive the real DesktopToaster with an injected fake webview,
so they need no display, no WebView2 and no Win32 window to exist.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from backend import desktop_toast as dt

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "frontend" / "css" / "3-features.css").read_text(encoding="utf-8")
HNOTIFY = (ROOT / "frontend" / "js" / "h-notify.js").read_text(encoding="utf-8")
TOAST_HTML = (ROOT / "frontend" / "toast.html").read_text(encoding="utf-8")
DT_SRC = (ROOT / "backend" / "desktop_toast.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------- fake webview
class _FakeWin:
    """Records the ordered method calls the toaster makes on its window."""
    def __init__(self, log):
        self.log = log
        self.native = None            # force the FindWindowW fallback -> hwnd 0

    def evaluate_js(self, js):
        self.log.append(("evaluate_js", js))
        if "snHeight" in js:
            return 96
        return None

    def resize(self, w, h): self.log.append(("resize", w, h))
    def move(self, x, y): self.log.append(("move", x, y))
    def show(self): self.log.append(("show",))
    def hide(self): self.log.append(("hide",))
    def destroy(self): self.log.append(("destroy",))


class _FakeWebview:
    def __init__(self):
        self.log = []
        self.created_kwargs = None
        self.window = None

    def create_window(self, title, url, **kw):
        self.log.append(("create_window", title))
        self.created_kwargs = kw
        self.window = _FakeWin(self.log)
        return self.window


class _Notice:
    def __init__(self, title="New device detected", body="Roku · 192.168.0.40",
                 category="new_device"):
        self.title, self.body, self.category = title, body, category


@pytest.fixture(autouse=True)
def _no_real_win32(monkeypatch):
    """A live SharkNet may be running; never let a test resolve/modify a real
    window. With no handle, _apply_exstyle/_harden are safe no-ops."""
    monkeypatch.setattr(dt.DesktopToaster, "_hwnd", staticmethod(lambda win: 0))


# ---------------------------------------------------------------- Issue 1
def test_toolwindow_exstyle_is_applied_before_the_first_show():
    """The real fix for 'SharkNet Notification' as a separate taskbar/Alt+Tab
    window: the ex-style must be set while the window is STILL hidden."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    order = []
    # record ex-style application against the window's own call log
    toaster._apply_exstyle = lambda win: wv.log.append(("exstyle",))
    assert toaster.show(_Notice()) is True
    seq = [c[0] for c in wv.log]
    assert "show" in seq, "the window must be shown"
    assert seq.index("exstyle") < seq.index("show"), \
        "the tool-window ex-style must be applied BEFORE the first show"
    assert seq.count("show") == 1, "shown exactly once on the first notice"


def test_window_is_created_hidden_and_frameless_no_focus():
    wv = _FakeWebview()
    dt.DesktopToaster("http://x/toast.html", webview=wv).start()
    kw = wv.created_kwargs
    assert kw["hidden"] is True, "must be created hidden (no pre-show taskbar button)"
    assert kw["frameless"] is True
    assert kw["focus"] is False, "a notification must never steal focus"


def test_exstyle_constants_hide_from_taskbar_alt_tab_and_never_activate():
    # WS_EX_TOOLWINDOW hides from taskbar AND Alt+Tab; NOACTIVATE prevents focus theft
    assert dt.WS_EX_TOOLWINDOW == 0x00000080
    assert dt.WS_EX_NOACTIVATE == 0x08000000
    assert dt.WS_EX_TOPMOST == 0x00000008
    assert dt.WS_EX_APPWINDOW == 0x00040000


def test_exstyle_transform_clears_appwindow_the_taskbar_thumbnail_cause():
    """The live packaged HWND was 0x08050088 (TOOLWINDOW *and* APPWINDOW) and still
    produced a second 'SharkNet Notification' taskbar thumbnail, because WinForms
    sets WS_EX_APPWINDOW (ShowInTaskbar) and it OVERRIDES TOOLWINDOW. The transform
    must CLEAR APPWINDOW, not merely add TOOLWINDOW."""
    LIVE = 0x08050088                      # measured on the real packaged window
    out = dt.toolwindow_exstyle(LIVE)
    assert out == 0x08010088, f"expected APPWINDOW cleared -> 0x08010088, got {out:#010x}"
    assert not (out & dt.WS_EX_APPWINDOW), "WS_EX_APPWINDOW must be cleared"
    assert out & dt.WS_EX_TOOLWINDOW, "WS_EX_TOOLWINDOW must be set"
    assert out & dt.WS_EX_NOACTIVATE, "WS_EX_NOACTIVATE must be set (no focus theft)"
    assert out & dt.WS_EX_TOPMOST, "WS_EX_TOPMOST must be set"
    # idempotent: applying it to an already-hardened style is a no-op
    assert dt.toolwindow_exstyle(out) == out


def test_exstyle_transform_sets_flags_on_a_bare_window():
    out = dt.toolwindow_exstyle(0)
    assert out == (dt.WS_EX_TOOLWINDOW | dt.WS_EX_NOACTIVATE | dt.WS_EX_TOPMOST)


def test_apply_exstyle_uses_the_appwindow_clearing_transform():
    # the hardener must go through the transform (so it clears APPWINDOW), and must
    # NOT own the toast to the main window (ownership would hide it in the tray case)
    assert "toolwindow_exstyle(ex)" in DT_SRC
    assert "GWLP_HWNDPARENT" not in DT_SRC, "must not make the toast an owned window"


# ---------------------------------------------------------------- Issue 2
def test_stack_empty_hides_the_host_window_no_ghost_rectangle():
    """When the last card leaves, the launcher hides the frameless host so no
    grey ghost rectangle / stale shadow is left on the desktop."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())               # window is now visible
    assert toaster._hidden is False
    # the JS bridge object the page calls when its stack drains
    api = wv.created_kwargs["js_api"]
    assert hasattr(api, "empty"), "toast.html needs an empty() bridge to hide the host"
    api.empty()
    assert toaster._hidden is True, "host must hide when the stack empties"
    assert ("hide",) in wv.log


def test_h_notify_fires_the_empty_hook_when_the_stack_drains():
    # the renderer must call window.snOnEmpty when nothing is visible or queued
    assert "snOnEmpty" in HNOTIFY
    assert "notifyIfEmpty" in HNOTIFY
    assert "visible <= 0 && queue.length === 0" in HNOTIFY


def test_toast_host_page_wires_empty_to_the_pywebview_bridge():
    assert "window.snOnEmpty" in TOAST_HTML
    assert "api.empty" in TOAST_HTML


def test_desktop_toast_card_has_no_drop_shadow():
    """The desktop drop-shadow read as a large grey rectangle on Windows."""
    m = re.search(r"body\.sn-desktop \.sn-toast\{([^}]*)\}", CSS)
    assert m, "desktop toast rule missing"
    assert "box-shadow" not in m.group(1), "desktop card must carry no drop-shadow"
    # and the base card also dropped the old heavy glow
    base = re.search(r"\.sn-toast\{([^}]*)\}", CSS)
    assert base and "box-shadow" not in base.group(1)


def test_stop_destroys_the_window_leaving_no_orphan():
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())
    toaster.stop()
    assert ("destroy",) in wv.log
    assert toaster._window is None
    toaster.stop()                        # idempotent


# ---------------------------------------------------------------- Issue 3
def test_renderer_caps_visible_and_bounds_the_queue():
    assert "var MAX_VISIBLE = 3" in HNOTIFY
    assert re.search(r"var MAX_QUEUE = \d+", HNOTIFY)
    # promotion: a dismissed card pulls the next queued one
    assert "queue.shift()" in HNOTIFY


def test_router_never_merges_into_a_summary_card():
    src = (ROOT / "backend" / "notify_router.py").read_text(encoding="utf-8")
    for gone in ("_buffer", "_group", "flush", "_pending", "_timer"):
        assert gone not in src, f"grouping artefact {gone!r} must be gone"
    assert "_render(Notice(" in src, "every event must render individually"


# ---------------------------------------------------------------- Issue 5
def test_language_controls_are_sharknet_styled_not_native():
    """paneLanguage renders .lang-list/.lang-row/.lr-check — all must be themed
    (backgrounds/borders/tokens), never left as native white buttons."""
    for sel in (r"\.lang-list\{", r"\.lang-row\{", r"\.lang-row\.on\{",
                r"\.lang-row:hover\{", r"\.lang-row:focus-visible\{"):
        assert re.search(sel, CSS), f"missing language rule {sel}"
    row = re.search(r"\.lang-row\{([^}]*)\}", CSS).group(1)
    assert "var(--bg-card-2)" in row and "var(--line)" in row, "must use SharkNet tokens"
    assert "font-family:inherit" in row, "must not use the native button font"
    on = re.search(r"\.lang-row\.on\{([^}]*)\}", CSS).group(1)
    assert "--accent" in on, "the selected language must carry the accent"


# ---------------------------------------------------------------- Issue 6
def test_settings_close_button_is_sharknet_styled():
    """#sxX (class a-x) lives in .sx-head; it must be themed like the modal close,
    not a native white square."""
    m = re.search(r"#modalX,\.modal-head \.a-x,\.sx-head \.a-x\{([^}]*)\}", CSS)
    assert m, ".sx-head .a-x must share the themed close-button rule"
    body = m.group(1)
    assert "var(--bg-card-2)" in body and "var(--line)" in body
    assert "place-items:center" in body, "the X must be centred"
    assert re.search(r"\.sx-head \.a-x:hover\{", CSS), "needs a subtle hover"
    assert re.search(r"\.sx-head \.a-x:focus-visible\{", CSS), "needs a focus ring"


# ------------------------------------------- desktop toast host sizing/anchoring
def test_host_is_opaque_ground_not_transparent():
    """transparent=True exposed the WinForms white BackColor on this WebView2
    stack (the white-rectangle defect). The host must be an OPAQUE SharkNet
    ground instead."""
    wv = _FakeWebview()
    dt.DesktopToaster("http://x/toast.html", webview=wv).start()
    kw = wv.created_kwargs
    assert kw["transparent"] is False, "host must not use flaky WebView2 transparency"
    assert kw["background_color"] == dt.GROUND == "#0a0a0f"
    # and the page paints the theme-aware ground, not a transparent page
    body = re.search(r"body\.sn-desktop\{([^}]*)\}", CSS).group(1)
    assert "background:var(--bg-deep)" in body, "desktop body must paint the ground"
    assert "background:transparent" not in body


def test_min_size_allows_a_single_card_height():
    """pywebview's default min_size (200,100) clamped a ~88px one-card host while
    the move used the un-clamped height, jumping the bottom edge. min_size must
    allow a one-card host."""
    wv = _FakeWebview()
    dt.DesktopToaster("http://x/toast.html", webview=wv).start()
    mw, mh = wv.created_kwargs["min_size"]
    assert mh <= 100 and mh == dt.MIN_HEIGHT


def test_host_height_hugs_the_measured_stack():
    """The window is resized to the exact measured stack height (no fixed tall
    window). The fake reports 96 for snHeight()."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())
    resizes = [c for c in wv.log if c[0] == "resize"]
    assert resizes, "the host must be resized to the content"
    assert resizes[-1][2] == 96, "resized to the measured stack height, not a guess"


def test_bottom_edge_is_fixed_for_every_card_count():
    """Anchor stability: y = workBottom - height - MARGIN, so the BOTTOM edge is
    constant regardless of how many cards are visible (the bottom card never
    jumps between 1/2/3)."""
    w = dt.DEFAULT_WIDTH
    edges = {h: dt.bottom_right(w, h)[1] + h for h in (88, 172, 256)}
    assert len(set(edges.values())) == 1, f"bottom edge drifts by count: {edges}"


def test_stack_grows_upward_as_it_gets_taller():
    """A taller stack starts higher up (smaller top-y) while the bottom stays put."""
    w = dt.DEFAULT_WIDTH
    y1 = dt.bottom_right(w, 88)[1]
    y3 = dt.bottom_right(w, 256)[1]
    assert y3 < y1, "adding cards must extend the stack upward, not downward"


def test_reflow_resizes_and_re_anchors_the_visible_host():
    """The page's JS bridge (card expired / promoted) re-fits the live host."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())           # host now visible
    api = wv.created_kwargs["js_api"]
    assert hasattr(api, "reflow"), "toast.html needs a reflow() bridge"
    wv.log.clear()
    api.reflow(172)                   # e.g. shrank from 3 to 2 cards
    resizes = [c for c in wv.log if c[0] == "resize"]
    moves = [c for c in wv.log if c[0] == "move"]
    assert resizes and resizes[-1][2] == 172, "reflow must resize to the new height"
    assert moves, "reflow must re-anchor bottom-right"
    exp_x, exp_y = dt.bottom_right(dt.DEFAULT_WIDTH, 172)
    assert moves[-1][1:] == (exp_x, exp_y), "reflow must keep the bottom-right anchor"


def test_reflow_is_a_noop_while_hidden():
    """A stray reflow after the host hid must not re-show anything."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())
    toaster.hide()
    wv.log.clear()
    wv.created_kwargs["js_api"].reflow(200)
    assert not wv.log, "reflow must do nothing while the host is hidden"


def test_page_and_js_drive_the_reflow():
    assert "window.snReflow" in TOAST_HTML and "api.reflow" in TOAST_HTML
    assert "reflowHost" in HNOTIFY
    # grows on add, shrinks on removal
    assert "reflowHost();" in HNOTIFY


def test_no_scroll_css_on_the_desktop_host():
    # html/body never scroll, and the desktop body hides overflow
    assert "html,body{margin:0;padding:0;overflow:hidden}" in TOAST_HTML
    body = re.search(r"body\.sn-desktop\{([^}]*)\}", CSS).group(1)
    assert "overflow:hidden" in body


def test_rounded_corners_helper_present():
    assert dt.DWMWA_WINDOW_CORNER_PREFERENCE == 33 and dt.DWMWCP_ROUND == 2
    assert "_round_corners" in DT_SRC and "DwmSetWindowAttribute" in DT_SRC


# ------------------------------------------- desktop toast follows the app theme
def test_ground_follows_theme():
    assert dt.ground_for("dark") == dt.GROUND == "#0a0a0f"
    assert dt.ground_for("light") == dt.GROUND_LIGHT == "#eef0f5"
    assert dt.ground_for("anything-else") == dt.GROUND, "unknown -> safe dark default"


def test_host_ground_is_created_for_the_current_theme():
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.set_theme("light", "en")      # before the window exists
    toaster.start()
    assert wv.created_kwargs["background_color"] == dt.GROUND_LIGHT
    wv2 = _FakeWebview()
    t2 = dt.DesktopToaster("http://x/toast.html", webview=wv2)  # default theme
    t2.start()
    assert wv2.created_kwargs["background_color"] == dt.GROUND    # dark default


def test_set_theme_stores_even_without_a_window_and_normalizes():
    toaster = dt.DesktopToaster("http://x/toast.html", webview=_FakeWebview())
    toaster.set_theme("light", "ar")
    assert toaster._theme == "light" and toaster._lang == "ar"
    toaster.set_theme("dark")
    assert toaster._theme == "dark"
    toaster.set_theme("nonsense")
    assert toaster._theme == "dark", "unknown theme falls back to dark"


def test_show_applies_the_current_theme_before_rendering_the_card():
    """A light-theme app must produce a LIGHT toast even on the first (default-dark)
    window: snTheme(light) must run before snPush."""
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.set_theme("light", "en")
    toaster.show(_Notice())
    ev = [c[1] for c in wv.log if c[0] == "evaluate_js"]
    theme_i = next((i for i, j in enumerate(ev) if "snTheme" in j and "light" in j), -1)
    push_i = next((i for i, j in enumerate(ev) if "snPush" in j), -1)
    assert theme_i >= 0 and push_i >= 0, "both snTheme and snPush must run"
    assert theme_i < push_i, "the theme must be applied BEFORE the card is pushed"


def test_theme_change_propagates_live_to_a_visible_host_without_touching_the_queue():
    wv = _FakeWebview()
    toaster = dt.DesktopToaster("http://x/toast.html", webview=wv)
    toaster.show(_Notice())               # host visible with a card
    wv.log.clear()
    toaster.set_theme("light", "en")      # live switch
    js = [c[1] for c in wv.log if c[0] == "evaluate_js"]
    assert any("snTheme" in j and "light" in j for j in js), "must push the new theme live"
    # a theme switch must NOT re-push cards or resize/re-anchor the stack
    assert not any("snPush" in j for j in js), "theme change must not touch the queue"
    assert not any(c[0] in ("resize", "move") for c in wv.log), "theme change must not re-anchor"


def test_launcher_propagates_the_authoritative_theme_to_the_toaster():
    run_src = (ROOT / "run.py").read_text(encoding="utf-8")
    assert "self._toaster.set_theme" in run_src, "TitleBarApi must feed the toaster"
    assert 'get_lang=lambda: app_settings.load().get("locale"' in run_src, \
        "toast language must reuse the persisted locale (one source of truth)"
    # the toast page + CSS drive theme purely by tokens (no separate notif theme)
    assert "snTheme" in TOAST_HTML
    body = re.search(r"body\.sn-desktop\{([^}]*)\}", CSS).group(1)
    assert "background:var(--bg-deep)" in body, "host ground is a theme token, not a fixed colour"


# ---------------------------------------------------------------- dark/light + RTL
def test_new_controls_are_theme_and_rtl_safe():
    # tokens (not hard-coded colours) => both themes; logical props already covered
    row = re.search(r"\.lang-row\{([^}]*)\}", CSS).group(1)
    assert "#fff" not in row and "white" not in row, "no hard-coded light colour"
    # the settings popup RTL rules still force IP/MAC/value runs back to LTR
    assert 'html[dir="rtl"]' in CSS and "direction:ltr" in CSS
