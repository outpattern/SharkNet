"""
V3.1 tray + launcher-runtime tests.

These cover the parts of the background runtime that CAN be verified without a
Windows desktop: the tray controller's logic (menu wiring, settings-backed toggle,
idempotent stop, graceful absence of pystray), the coordinated shutdown ordering in
run.py's AppRuntime, and the /api/runtime contract.

They deliberately do NOT assert anything about a real tray icon, a real balloon or
a real window — pystray is replaced by a fake. Actual Windows tray/GUI behavior
still has to be validated by hand on Windows.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import localization                      # noqa: E402
from backend.tray import TrayController               # noqa: E402


# --------------------------------------------------------------- fake pystray
class FakeMenuItem:
    def __init__(self, text, action, checked=None, default=False, visible=None):
        self.text = text
        self.action = action
        self.checked = checked
        self.default = default
        self.visible = visible          # callable(item)->bool, or None (always shown)

    def shown(self):
        """Resolve the dynamic `visible` predicate the way pystray would."""
        if self.visible is None:
            return True
        try:
            return bool(self.visible(self))
        except Exception:
            return False


class FakeMenu:
    SEPARATOR = object()

    def __init__(self, *items):
        self.items = list(items)


class FakeIcon:
    def __init__(self, name, image, title, menu):
        self.name = name
        self.image = image
        self.title = title
        self.menu = menu
        self.visible = True
        self.ran = False
        self.stopped = False
        self.updates = 0
        self.notifications = []

    def run(self):
        self.ran = True

    def stop(self):
        self.stopped = True

    def update_menu(self):
        self.updates += 1

    def notify(self, body, title=None):
        self.notifications.append((title, body))


def fake_pystray():
    m = types.SimpleNamespace()
    m.Icon = FakeIcon
    m.Menu = FakeMenu
    m.MenuItem = FakeMenuItem
    return m


class Store:
    """Stand-in for the settings store + the server's apply_settings_patch()."""

    def __init__(self, initial=None):
        self.data = initial or {"notifications": {"enabled": True}, "tray": {}}
        self.saves = []

    def load(self):
        return json.loads(json.dumps(self.data))

    def save(self, patch):
        self.saves.append(patch)
        for section, vals in patch.items():
            if isinstance(vals, dict):
                self.data.setdefault(section, {}).update(vals)
            else:
                self.data[section] = vals
        return self.load()


def make_tray(store=None, **kw):
    store = store or Store()
    tray = TrayController(get_settings=store.load, save_settings=store.save,
                          backend=fake_pystray(), image=object(), **kw)
    return tray, store


def _shown_texts(tray):
    """Menu item texts pystray would actually display (dynamic `visible` applied)."""
    return [i.text for i in tray._icon.menu.items
            if isinstance(i, FakeMenuItem) and i.shown()]


# ------------------------------------------------------------------ lifecycle
def test_tray_starts_and_builds_open_notifications_exit_menu():
    # no Cut/Uncut wiring -> the dynamic pair is never shown; base menu only
    tray, _ = make_tray()
    assert tray.start() is True
    assert tray.is_live() is True
    items = [i for i in tray._icon.menu.items if isinstance(i, FakeMenuItem)]
    assert _shown_texts(tray) == ["Open SharkNet", "Notifications", "Exit"]
    assert items[0].default is True
    assert items[1].checked(items[1]) is True


def test_tray_shows_cut_uncut_only_when_network_is_ready():
    calls = {"cut": 0, "uncut": 0}
    ready = {"on": True}
    tray, _ = make_tray(
        on_cut_others=lambda: calls.__setitem__("cut", calls["cut"] + 1),
        on_uncut_others=lambda: calls.__setitem__("uncut", calls["uncut"] + 1),
        network_ready=lambda: ready["on"],
    )
    tray.start()
    # connected: both items visible, in the right place
    assert _shown_texts(tray) == ["Open SharkNet", "Notifications",
                                   "Cut Others", "Uncut Others", "Exit"]
    # disconnected: both hidden completely (not greyed)
    ready["on"] = False
    assert _shown_texts(tray) == ["Open SharkNet", "Notifications", "Exit"]
    # reconnect: they come back (menu is re-evaluated on open)
    ready["on"] = True
    assert "Cut Others" in _shown_texts(tray)
    # the items invoke the injected callbacks (the existing main-UI bulk path)
    items = {i.text: i for i in tray._icon.menu.items if isinstance(i, FakeMenuItem)}
    items["Cut Others"].action()
    items["Uncut Others"].action()
    assert calls == {"cut": 1, "uncut": 1}


def test_tray_hides_cut_uncut_when_no_callbacks_wired():
    tray, _ = make_tray(network_ready=lambda: True)   # ready True but no callbacks
    tray.start()
    assert _shown_texts(tray) == ["Open SharkNet", "Notifications", "Exit"]


def test_tray_unavailable_without_pystray_is_not_an_error(monkeypatch):
    """No pystray -> start() returns False and the app runs windowed (V3.0)."""
    import backend.tray as tray_mod
    monkeypatch.setattr(tray_mod, "_load_pystray", lambda: None)
    tray = TrayController()
    assert tray.start() is False
    assert tray.is_live() is False
    tray.notify("t", "b")      # must not raise
    tray.stop()                # must not raise


def test_tray_stop_is_idempotent():
    tray, _ = make_tray()
    tray.start()
    icon = tray._icon
    tray.stop()
    tray.stop()
    tray.stop()
    assert icon.stopped is True
    assert tray.is_live() is False


def test_notify_goes_to_the_icon_and_survives_failure():
    tray, _ = make_tray()
    tray.start()
    tray.notify("Device blocked", "Ahmed iPhone")
    assert tray._icon.notifications == [("Device blocked", "Ahmed iPhone")]

    def boom(*a, **k):
        raise RuntimeError("tray gone")

    tray._icon.notify = boom
    tray.notify("x", "y")      # swallowed: a failed toast never crashes SharkNet


def test_notify_before_start_is_a_silent_drop():
    tray, _ = make_tray()
    tray.notify("x", "y")      # no icon yet -> no-op, no raise


# --------------------------------------------------------- settings-backed toggle
def test_toggle_notifications_persists_through_the_shared_write_path():
    tray, store = make_tray()
    tray.start()
    assert tray.notifications_enabled() is True
    assert tray.toggle_notifications() is False
    assert store.saves == [{"notifications": {"enabled": False}}]
    assert tray.notifications_enabled() is False
    # and the menu was asked to re-draw its checkmark
    assert tray._icon.updates >= 1
    assert tray.toggle_notifications() is True
    assert store.data["notifications"]["enabled"] is True


def test_toggle_survives_a_failing_store():
    store = Store()

    def boom(_patch):
        raise OSError("disk full")

    tray = TrayController(get_settings=store.load, save_settings=boom,
                          backend=fake_pystray(), image=object())
    tray.start()
    tray.toggle_notifications()        # must not raise


def test_notifications_enabled_defaults_true_when_settings_unreadable():
    def boom():
        raise OSError("nope")

    tray = TrayController(get_settings=boom, backend=fake_pystray(), image=object())
    assert tray.notifications_enabled() is True


# ------------------------------------------------------------------- tray i18n
@pytest.mark.parametrize("locale,expected", [
    ("ar", "خروج"),
    ("fr", "Quitter"),
    ("es", "Salir"),
    ("zh-CN", "退出"),
])
def test_tray_menu_is_localized_from_the_bundled_locale_files(locale, expected):
    tray, _ = make_tray(locale=locale)
    tray.start()
    items = [i for i in tray._icon.menu.items if isinstance(i, FakeMenuItem)]
    assert items[-1].text == expected


def test_tray_falls_back_to_english_for_an_unknown_locale():
    tray, _ = make_tray(locale="xx-YY")
    tray.start()
    assert _shown_texts(tray) == ["Open SharkNet", "Notifications", "Exit"]


def test_every_locale_supplies_the_tray_menu_strings():
    for loc in ("en", "ar", "es", "fr", "zh-CN"):
        table = localization.load_table(loc, "tray.")
        assert set(table) == {"tray.open", "tray.notifications", "tray.exit",
                              "tray.cut_others", "tray.uncut_others"}, loc


# ------------------------------------------------ localization loader contract
def test_translator_returns_none_for_missing_keys():
    tr = localization.translator("en", "notif.")
    assert tr("notif.nope") is None
    assert tr("notif.hardcut.title") == "Hard Cut"


def test_translator_interpolates_and_survives_a_bad_format():
    tr = localization.translator("en", "notif.")
    assert "Dad PC" in tr("notif.cut.body", name="Dad PC")


def test_missing_locale_file_yields_an_empty_table():
    assert localization.load_table("nope-XX", "tray.") == {}
    assert localization.locale_path("nope-XX") is None


# ------------------------------------------------- notification dispatch wiring
def test_manager_set_dispatch_routes_to_the_tray():
    from backend.engine.notifications import NotificationManager
    tray, _ = make_tray()
    tray.start()
    m = NotificationManager()
    m.set_dispatch(tray.notify)
    m._q.put_nowait(("T", "B"))
    m.start()
    for _ in range(200):
        if tray._icon.notifications:
            break
        import time
        time.sleep(0.01)
    m.stop()
    assert tray._icon.notifications == [("T", "B")]


def test_manager_set_dispatch_none_drops_silently():
    from backend.engine.notifications import NotificationManager
    m = NotificationManager()
    m.set_dispatch(None)
    m.start()
    m._q.put_nowait(("T", "B"))
    m.stop()          # no dispatcher -> nothing happens, no raise


# ----------------------------------------------------- run.py AppRuntime (launcher)
@pytest.fixture()
def runtime_mod():
    import run
    return run


class FakeWindow:
    def __init__(self):
        self.hidden = False
        self.shown = 0
        self.destroyed = False

    def hide(self):
        self.hidden = True

    def show(self):
        self.hidden = False
        self.shown += 1

    def restore(self):
        self.shown += 1

    def destroy(self):
        self.destroyed = True


class FakeGuard:
    def __init__(self):
        self.released = 0

    def release(self):
        self.released += 1


def test_close_hides_to_tray_when_enabled(runtime_mod):
    tray, _ = make_tray()
    tray.start()
    win, guard = FakeWindow(), FakeGuard()
    rt = runtime_mod.AppRuntime(guard=guard,
                                get_settings=lambda: {"tray": {"keep_running_on_close": True}})
    rt.attach(win)
    rt.attach_tray(tray)
    assert rt.on_closing() is False          # close vetoed
    assert win.hidden is True
    assert rt.is_done() is False             # nothing was torn down


def test_close_quits_when_background_is_disabled(runtime_mod):
    tray, _ = make_tray()
    tray.start()
    rt = runtime_mod.AppRuntime(guard=FakeGuard(),
                                get_settings=lambda: {"tray": {"keep_running_on_close": False}})
    rt.attach(FakeWindow())
    rt.attach_tray(tray)
    assert rt.on_closing() is True


def test_close_quits_when_there_is_no_tray_to_restore_from(runtime_mod):
    """Honesty rule: without a live tray, hiding would strand the user, so the
    setting is ignored and the window really closes."""
    rt = runtime_mod.AppRuntime(guard=FakeGuard(),
                                get_settings=lambda: {"tray": {"keep_running_on_close": True}})
    rt.attach(FakeWindow())
    rt.attach_tray(None)
    assert rt.on_closing() is True


def test_tray_exit_destroys_the_window_and_stops_close_to_tray(runtime_mod):
    tray, _ = make_tray()
    tray.start()
    win = FakeWindow()
    rt = runtime_mod.AppRuntime(guard=FakeGuard(),
                                get_settings=lambda: {"tray": {"keep_running_on_close": True}})
    rt.attach(win)
    rt.attach_tray(tray)
    rt.request_exit()
    assert win.destroyed is True
    # a real quit is in progress: the next close must NOT be vetoed
    assert rt.on_closing() is True


def test_shutdown_is_idempotent_and_releases_the_guard(runtime_mod, monkeypatch):
    calls = []
    import backend.server as bserver
    monkeypatch.setattr(bserver, "cleanup", lambda: calls.append("cleanup"))
    tray, _ = make_tray()
    tray.start()
    icon = tray._icon
    guard = FakeGuard()
    rt = runtime_mod.AppRuntime(guard=guard, get_settings=dict)
    rt.attach_tray(tray)
    rt.shutdown()
    rt.shutdown()
    rt.shutdown()
    assert calls == ["cleanup"]          # engine teardown ran exactly once
    assert guard.released == 1           # guard released exactly once
    assert icon.stopped is True          # tray stopped
    assert rt.is_done() is True


def test_shutdown_without_a_window_or_tray_is_safe(runtime_mod, monkeypatch):
    import backend.server as bserver
    monkeypatch.setattr(bserver, "cleanup", lambda: None)
    rt = runtime_mod.AppRuntime()
    rt.shutdown()                        # partial init -> must not raise
    assert rt.is_done() is True


def test_request_exit_without_a_window_shuts_down_directly(runtime_mod, monkeypatch):
    import backend.server as bserver
    monkeypatch.setattr(bserver, "cleanup", lambda: None)
    rt = runtime_mod.AppRuntime(guard=FakeGuard(), get_settings=dict)
    rt.request_exit()
    assert rt.is_done() is True


def test_show_window_restores_and_never_raises(runtime_mod):
    win = FakeWindow()
    win.hidden = True
    rt = runtime_mod.AppRuntime()
    rt.attach(win)
    rt.show_window()
    assert win.hidden is False
    assert win.shown >= 1
    runtime_mod.AppRuntime().show_window()      # no window attached -> no raise


# --------------------------------------------------------------- /api/runtime
# The endpoint functions are called directly (as the other V3.1 server tests do),
# so no HTTP test client / extra dependency is needed.
def _post_settings(server, patch):
    import asyncio

    class Req:
        async def json(self):
            return patch

    return asyncio.run(server.api_set_settings(Req()))


def test_api_runtime_reports_no_background_without_a_tray(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    monkeypatch.setitem(server.RUNTIME, "tray", False)
    _post_settings(server, {"tray": {"keep_running_on_close": True}})
    r = server.api_runtime()
    assert r["ok"] is True
    assert r["tray"] is False
    # setting says "keep running", but with no tray closing really quits — the UI
    # must be told the truth, not the preference
    assert r["background"] is False


def test_api_runtime_reports_background_when_tray_and_setting_agree(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    monkeypatch.setitem(server.RUNTIME, "tray", True)
    _post_settings(server, {"tray": {"keep_running_on_close": True}})
    r = server.api_runtime()
    assert r["tray"] is True and r["background"] is True
    _post_settings(server, {"tray": {"keep_running_on_close": False}})
    assert server.api_runtime()["background"] is False


def test_settings_listeners_fire_so_the_tray_checkbox_resyncs(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    saved = server.NOTIFY.get_policy()
    seen = []
    server.SETTINGS_LISTENERS.append(seen.append)
    try:
        _post_settings(server, {"notifications": {"enabled": False}})
        assert seen and seen[-1]["notifications"]["enabled"] is False
    finally:
        server.SETTINGS_LISTENERS.remove(seen.append)
        server.NOTIFY.set_policy(saved)          # don't leak into other tests


def test_a_failing_settings_listener_cannot_break_the_api(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    saved = server.NOTIFY.get_policy()

    def boom(_s):
        raise RuntimeError("tray died")

    server.SETTINGS_LISTENERS.append(boom)
    try:
        r = _post_settings(server, {"notifications": {"sound": False}})
        assert r["ok"] is True                   # a dead tray never breaks settings
    finally:
        server.SETTINGS_LISTENERS.remove(boom)
        server.NOTIFY.set_policy(saved)
