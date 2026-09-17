"""
V3.1 notification routing — ONE event, ONE user-facing notification.

Pins the rules that removed the duplicate (in-app toast AND a Windows balloon for
the same event):

  window visible  -> in-app only
  window hidden   -> custom desktop toast only
  desktop renderer broken -> exactly one native balloon, as a LAST resort

plus burst grouping, storm protection, shutdown, and the guarantee that a
notification failure can never disturb enforcement.
"""
from __future__ import annotations

import threading

import pytest

from backend.notify_router import NotificationRouter, Notice, GROUPED_CATEGORY


class Sink:
    """Records what a renderer was asked to draw."""

    def __init__(self, boom=False):
        self.calls = []
        self.boom = boom

    def __call__(self, *a):
        self.calls.append(a)
        if self.boom:
            raise RuntimeError("renderer exploded")

    @property
    def n(self):
        return len(self.calls)


def router(**kw):
    # grouping (and its timer) was removed — the router now renders every notice
    # individually, so no timer_factory/group_window is needed.
    return NotificationRouter(**kw)


# ------------------------------------------------------------ routing
def test_visible_window_gets_the_in_app_toast_only():
    inapp, desktop, fallback = Sink(), Sink(), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop, fallback_sink=fallback)
    r.set_window_visible(True)
    r.dispatch("Device blocked", "Ahmed iPhone\n192.168.0.5", "cut")
    assert inapp.n == 1
    assert desktop.n == 0, "no desktop toast while the window is on screen"
    assert fallback.n == 0, "no native Windows notification, ever, in normal operation"


def test_hidden_window_gets_the_custom_desktop_toast_only():
    inapp, desktop, fallback = Sink(), Sink(), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop, fallback_sink=fallback)
    r.set_window_visible(False)
    r.dispatch("Device blocked", "Ahmed iPhone", "cut")
    assert desktop.n == 1
    assert inapp.n == 0
    assert fallback.n == 0, "custom toast rendered -> never also a native balloon"


def test_minimised_is_treated_as_hidden():
    inapp, desktop = Sink(), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop)
    r.set_window_visible(False)            # what on_minimized() does
    r.dispatch("Security alert", "x", "security")
    assert (desktop.n, inapp.n) == (1, 0)


def test_exactly_one_sink_per_event_across_visibility_changes():
    inapp, desktop, fallback = Sink(), Sink(), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop, fallback_sink=fallback)
    for visible in (True, False, True, False, False, True):
        r.set_window_visible(visible)
        r.dispatch("t", "b", "cut")
    assert inapp.n + desktop.n == 6, "one renderer per event"
    assert inapp.n == 3 and desktop.n == 3
    assert fallback.n == 0


def test_hide_restore_hide_changes_routing():
    inapp, desktop = Sink(), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop)
    r.set_window_visible(False)
    r.dispatch("a", "b", "cut")
    r.set_window_visible(True)
    r.dispatch("a", "b", "cut")
    r.set_window_visible(False)
    r.dispatch("a", "b", "cut")
    assert desktop.n == 2 and inapp.n == 1


# ------------------------------------------------------------ fallback
def test_native_balloon_only_when_the_custom_renderer_fails():
    inapp, desktop, fallback = Sink(), Sink(boom=True), Sink()
    r = router(inapp_sink=inapp, desktop_sink=desktop, fallback_sink=fallback)
    r.set_window_visible(False)
    r.dispatch("Device offline", "TV", "device_offline")
    assert desktop.n == 1, "it must try the custom renderer first"
    assert fallback.n == 1, "exactly one fallback notification"
    assert inapp.n == 0


def test_fallback_used_when_no_desktop_renderer_exists():
    fallback = Sink()
    r = router(inapp_sink=Sink(), desktop_sink=None, fallback_sink=fallback)
    r.set_window_visible(False)
    r.dispatch("t", "b", "cut")
    assert fallback.n == 1


def test_a_failing_sink_never_raises_into_the_engine():
    r = router(inapp_sink=Sink(boom=True), desktop_sink=Sink(boom=True),
               fallback_sink=Sink(boom=True))
    r.set_window_visible(True)
    r.dispatch("t", "b", "cut")          # must not raise
    r.set_window_visible(False)
    r.dispatch("t", "b", "cut")          # must not raise


def test_no_sinks_at_all_is_safe():
    r = router()
    r.dispatch("t", "b", "cut")


# ------------------------------------------------------------ NO merging
def test_single_new_device_is_one_individual_card():
    inapp = Sink()
    r = router(inapp_sink=inapp)
    r.set_window_visible(True)
    r.dispatch("New device detected", "Apple\n192.168.0.9", GROUPED_CATEGORY)
    assert inapp.n == 1
    assert inapp.calls[0][0].title == "New device detected"


def test_burst_of_new_devices_stays_as_separate_cards_not_merged():
    """The visual merge was removed: each new_device event renders on its own,
    immediately — never a 'N new devices detected' summary."""
    inapp = Sink()
    r = router(inapp_sink=inapp)
    r.set_window_visible(True)
    for i, vendor in enumerate(["Private", "Private", "Unknown", "Unknown", "Router"]):
        r.dispatch("New device detected", f"{vendor}\n192.168.0.{i}", GROUPED_CATEGORY)
    assert inapp.n == 5, "five events -> five individual cards"
    titles = {c[0].title for c in inapp.calls}
    assert titles == {"New device detected"}
    # no aggregated summary title anywhere
    assert not any("devices detected" in c[0].title and c[0].title[0].isdigit()
                   for c in inapp.calls)


def test_router_never_produces_a_grouped_summary_card():
    """Structural: the router no longer has any merge/group/buffer machinery."""
    r = router(inapp_sink=Sink())
    for attr in ("_group", "_buffer", "flush", "_pending", "_timer"):
        assert not hasattr(r, attr), f"grouping machinery {attr!r} must be gone"


def test_router_is_presentation_only_and_never_touches_events():
    """The router only receives already-rendered text. It must not IMPORT any
    state/enforcement module, so it structurally cannot merge, drop or alter the
    underlying device events."""
    import ast
    import inspect
    from backend import notify_router
    tree = ast.parse(inspect.getsource(notify_router))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(a.name for a in node.names)
    banned = {"state", "STATE", "policy", "forwarder", "spoofer", "SPOOFER",
              "backend.state", "backend.engine.policy", "backend.engine.forwarder"}
    assert not (imported & banned), f"router imports enforcement modules: {imported & banned}"
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "devices" not in names and "snapshot" not in names


def test_every_category_renders_immediately():
    inapp = Sink()
    r = router(inapp_sink=inapp)
    r.set_window_visible(True)
    r.dispatch("Device blocked", "x", "cut")
    r.dispatch("New device detected", "y\n1", "new_device")
    assert inapp.n == 2, "each event -> exactly one render, no buffering for any category"


# ------------------------------------------------------------ storm protection
def test_repeated_ticks_do_not_storm(monkeypatch, tmp_path):
    """Storm protection lives in the MANAGER's transition diff (no second engine
    here): an unchanged device across many ticks emits nothing to the router."""
    from backend.engine.notifications import NotificationManager, DEFAULT_POLICY
    seen = []
    m = NotificationManager(dispatch=lambda *a: seen.append(a),
                            policy=dict(DEFAULT_POLICY))
    dev = {"ip": "10.0.0.5", "mac": "aa", "mode": "cut", "online": True, "label": "TV"}
    first = m.feed([dev], [])
    extra = sum(len(m.feed([dev], [])) for _ in range(30))
    assert len(first) == 1 and extra == 0


# ------------------------------------------------------------ lifecycle
def test_stop_is_idempotent():
    inapp = Sink()
    r = router(inapp_sink=inapp)
    r.set_window_visible(True)
    r.dispatch("New device detected", "a\n1", GROUPED_CATEGORY)
    assert inapp.n == 1                # rendered immediately (no buffering)
    r.stop()
    r.stop()
    r.stop()                           # idempotent, no raise


def test_window_visibility_defaults_to_visible():
    assert router().is_window_visible() is True


# --------------------------------------- manager -> router integration
def test_manager_passes_the_category_to_a_three_arg_sink():
    from backend.engine.notifications import NotificationManager, DEFAULT_POLICY
    got = []
    m = NotificationManager(policy=dict(DEFAULT_POLICY))
    m.set_dispatch(lambda title, body, category: got.append((title, body, category)))
    m._q.put_nowait(("cut", "T", "B"))
    m.start()
    for _ in range(200):
        if got:
            break
        import time
        time.sleep(0.01)
    m.stop()
    assert got and got[0][2] == "cut"


def test_manager_still_supports_a_two_arg_sink():
    """A legacy two-argument sink (e.g. the tray balloon) keeps working."""
    from backend.engine.notifications import NotificationManager, DEFAULT_POLICY
    got = []
    m = NotificationManager(policy=dict(DEFAULT_POLICY))
    m.set_dispatch(lambda title, body: got.append((title, body)))
    m._q.put_nowait(("cut", "T", "B"))
    m.start()
    for _ in range(200):
        if got:
            break
        import time
        time.sleep(0.01)
    m.stop()
    assert got == [("T", "B")]


def test_server_wires_exactly_one_inapp_sink_and_drains_once(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    server._INAPP_TOASTS.clear()
    server._queue_inapp(Notice("cut", "T", "B"))
    first = server.drain_inapp_toasts()
    second = server.drain_inapp_toasts()
    assert len(first) == 1 and first[0]["title"] == "T"
    assert second == [], "a notice must be delivered exactly once"


def test_state_msg_carries_toasts(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    server._INAPP_TOASTS.clear()
    server._queue_inapp(Notice("new_device", "New device detected", "Apple\n10.0.0.2"))
    msg = server.HUB.state_msg()
    assert [x["title"] for x in msg["toasts"]] == ["New device detected"]
    assert server.HUB.state_msg()["toasts"] == []


# --------------------------------------- desktop toast window
def test_desktop_toaster_is_optional_and_fails_safe(monkeypatch):
    from backend import desktop_toast
    t = desktop_toast.DesktopToaster("http://x/toast.html")
    monkeypatch.setattr(desktop_toast, "log", desktop_toast.log)

    class NoWebview:
        def create_window(self, *a, **k):
            raise RuntimeError("no display")

    t._webview = NoWebview()
    assert t.start() is False
    assert t.show(Notice("cut", "t", "b")) is False    # caller then falls back
    t.stop()
    t.stop()


def test_desktop_toaster_positions_inside_the_work_area(monkeypatch):
    from backend import desktop_toast
    monkeypatch.setattr(desktop_toast, "work_area", lambda: (0, 0, 1920, 1040))
    x, y = desktop_toast.bottom_right(372, 120)
    assert x == 1920 - 372 - desktop_toast.MARGIN
    assert y == 1040 - 120 - desktop_toast.MARGIN


def test_desktop_toaster_never_goes_off_screen(monkeypatch):
    from backend import desktop_toast
    monkeypatch.setattr(desktop_toast, "work_area", lambda: (0, 0, 200, 100))
    x, y = desktop_toast.bottom_right(372, 400)
    assert x >= 0 and y >= 0


def test_desktop_window_declares_the_no_focus_styles():
    """The toast must not steal focus, and must stay out of the taskbar/Alt+Tab."""
    import inspect
    from backend import desktop_toast
    src = inspect.getsource(desktop_toast)
    assert "WS_EX_NOACTIVATE" in src
    assert "WS_EX_TOOLWINDOW" in src
    assert "focus=False" in src
    assert "SWP_NOACTIVATE" in src


def test_shutdown_destroys_the_notification_window():
    from backend import desktop_toast

    class FakeWin:
        def __init__(self):
            self.destroyed = False

        def destroy(self):
            self.destroyed = True

    t = desktop_toast.DesktopToaster("http://x")
    win = FakeWin()
    t._window = win
    t.stop()
    assert win.destroyed is True
    t.stop()            # idempotent


def test_max_three_visible_notifications_is_enforced_in_the_component():
    """The renderer caps the visible stack and queues the rest."""
    import re as _re
    from pathlib import Path as _P
    js = (_P(__file__).resolve().parents[1] / "frontend" / "js" / "h-notify.js").read_text(encoding="utf-8")
    m = _re.search(r"MAX_VISIBLE\s*=\s*(\d+)", js)
    assert m and int(m.group(1)) == 3
    assert "queue.push" in js and "queue.shift()" in js


def test_in_app_duplicate_toast_was_removed():
    """handleEvent must no longer toast new_device — the router owns it now."""
    from pathlib import Path as _P
    js = (_P(__file__).resolve().parents[1] / "frontend" / "js" / "d-devices-map.js").read_text(encoding="utf-8")
    fn = js[js.index("function handleEvent"):js.index("function toast(")]
    assert "toast.new_device" not in fn, "duplicate in-app new-device toast is back"
    assert "renderServerToasts" in js, "router-selected toasts are not rendered"


def test_notification_card_uses_an_accent_line_not_a_full_border():
    from pathlib import Path as _P
    css = (_P(__file__).resolve().parents[1] / "frontend" / "css" / "3-features.css").read_text(encoding="utf-8")
    import re as _re
    card = _re.search(r"\.sn-toast\{([^}]*)\}", css)
    assert card, ".sn-toast not styled"
    assert "border:1px solid var(--line)" in card.group(1), "should use a neutral hairline"
    assert "var(--accent)" not in card.group(1), "no full cyan ring on the card"
    assert ".sn-toast::before" in css, "missing the narrow accent line"


def test_hover_pauses_auto_dismiss():
    from pathlib import Path as _P
    js = (_P(__file__).resolve().parents[1] / "frontend" / "js" / "h-notify.js").read_text(encoding="utf-8")
    assert "mouseenter" in js and "mouseleave" in js
    assert "remaining" in js, "must resume the REMAINING time, not restart it"
