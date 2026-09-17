"""
V3.1 runtime backbone tests — settings persistence + single-instance guard.
No GUI, no registry side effects (winreg is faked), no real ports leaked.
"""
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def tmp_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # settings caches nothing; each call reads the env -> tmp dir
    import importlib
    from backend import settings as S
    importlib.reload(S)
    return S


# ---------------- settings ----------------
def test_settings_defaults_when_missing(tmp_appdata):
    s = tmp_appdata.load()
    assert s["locale"] == "en"
    assert s["tray"]["keep_running_on_close"] is True
    assert s["notifications"]["cut"] is True
    assert s["notifications"]["limit"] is False


def test_settings_save_reload_roundtrip(tmp_appdata):
    tmp_appdata.save({"locale": "ar", "notifications": {"limit": True}})
    s = tmp_appdata.load()
    assert s["locale"] == "ar"
    assert s["notifications"]["limit"] is True
    # untouched keys preserved
    assert s["notifications"]["cut"] is True
    assert s["tray"]["minimize_to_tray"] is True


def test_settings_bool_coercion_and_unknown_keys_ignored(tmp_appdata):
    s = tmp_appdata.save({"notifications": {"cut": 0, "hardcut": 1, "junk": True},
                          "bogus_section": {"x": 1}})
    assert s["notifications"]["cut"] is False
    assert s["notifications"]["hardcut"] is True
    assert "junk" not in s["notifications"]
    assert "bogus_section" not in s


def test_settings_corrupt_file_falls_back(tmp_appdata):
    (tmp_path := tmp_appdata._path()).write_text("{ not json", encoding="utf-8")
    s = tmp_appdata.load()          # must not raise
    assert s["locale"] == "en"


def test_autostart_no_target_in_dev_returns_false(tmp_appdata):
    # dev (not frozen) + no exe_path -> nothing sensible to register -> False, no write
    assert tmp_appdata.apply_autostart(True) is False


def test_autostart_writes_and_removes_via_fake_registry(tmp_appdata, monkeypatch):
    # fake winreg so we assert the logic WITHOUT touching the real registry
    store = {}

    class FakeKey:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake = type("winreg", (), {})()
    fake.HKEY_CURRENT_USER = 1
    fake.KEY_SET_VALUE = 2
    fake.REG_SZ = 1
    fake.OpenKey = staticmethod(lambda *a, **k: FakeKey())
    fake.SetValueEx = staticmethod(lambda key, name, r, typ, val: store.__setitem__(name, val))
    fake.DeleteValue = staticmethod(lambda key, name: store.pop(name))
    monkeypatch.setitem(sys.modules, "winreg", fake)

    assert tmp_appdata.apply_autostart(True, exe_path=r"C:\X\SharkNet.exe") is True
    assert store["SharkNet"] == '"C:\\X\\SharkNet.exe"'
    assert tmp_appdata.apply_autostart(False) is True
    assert "SharkNet" not in store


# ---------------- single instance ----------------
def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def test_single_instance_second_acquire_fails():
    from backend.single_instance import SingleInstance
    port = _free_port()
    a = SingleInstance(port)
    b = SingleInstance(port)
    try:
        assert a.acquire() is True
        assert b.acquire() is False, "a second engine must NOT be allowed to start"
    finally:
        a.release(); b.release()


def test_single_instance_signal_restores_existing():
    from backend.single_instance import SingleInstance
    port = _free_port()
    first = SingleInstance(port)
    assert first.acquire() is True
    activated = threading.Event()
    first.start_listener(lambda: activated.set())
    try:
        second = SingleInstance(port)
        assert second.acquire() is False          # first owns it
        assert second.signal_existing() is True   # ping the first to restore UI
        assert activated.wait(2.0), "existing instance must be told to restore"
    finally:
        first.release()


def test_single_instance_release_is_idempotent():
    from backend.single_instance import SingleInstance
    port = _free_port()
    a = SingleInstance(port)
    a.acquire()
    a.release()
    a.release()      # safe twice
    # port is free again after release
    b = SingleInstance(port)
    assert b.acquire() is True
    b.release()


# ---------------- server integration (settings API + translator + event tap) ----------------
def test_backend_translator_localizes_notifications():
    from backend import server
    tr_ar = server._notif_translator("ar")
    assert tr_ar("notif.cut.title") == "تم حظر الجهاز"          # bundled Arabic notif string
    assert "جهاز" in (tr_ar("notif.hardcut.body", name="جهاز") or "")
    assert server._notif_translator("en")("notif.hardcut.title") == "Hard Cut"


def test_settings_api_roundtrip_and_applies_to_manager(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    saved = server.NOTIFY.get_policy()
    try:
        g = server.api_get_settings()
        assert g["ok"] and g["settings"]["notifications"]["cut"] is True

        class Req:
            async def json(self):
                return {"notifications": {"limit": True}, "locale": "fr"}
        import asyncio
        r = asyncio.run(server.api_set_settings(Req()))
        assert r["ok"] and r["settings"]["notifications"]["limit"] is True
        assert r["settings"]["locale"] == "fr"
        assert server.NOTIFY.should_notify("limit") is True     # applied to the live manager
    finally:
        server.NOTIFY.set_policy(saved)                         # don't leak into other tests


def test_broadcast_feeds_manager_even_with_no_ui_clients(monkeypatch):
    """The background-mode tap: broadcast() must feed the NotificationManager
    every tick even when no WebSocket client is connected (UI closed)."""
    from backend import server
    from backend.state import STATE, Device
    calls = []
    monkeypatch.setattr(server.NOTIFY, "feed", lambda devs, evs: (calls.append((devs, evs)) or []))
    STATE.devices.clear()
    STATE.devices["10.9.9.9"] = Device(ip="10.9.9.9", mac="aa")
    try:
        import asyncio
        assert not server.HUB.clients            # no UI connected
        asyncio.run(server.HUB.broadcast())
        assert calls, "broadcast must feed notifications even with no UI clients"
        assert any(d.get("ip") == "10.9.9.9" for d in calls[0][0])
    finally:
        STATE.devices.clear()
