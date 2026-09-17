"""
V3.1 optional rule persistence ("Restore saved rules on startup").

Default OFF preserves the deliberate fresh-session safe posture. ON reapplies the
user's saved rules (mode + kbps + ad-hoc domains) from the EXISTING persisted
model, once per control session, never to self/gateway, failing safe on junk.
Services are not part of the persisted model, so they are never restored.
"""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture()
def isolated(monkeypatch):
    """Fresh %LOCALAPPDATA% so settings + sqlite are per-test and empty."""
    monkeypatch.setenv("LOCALAPPDATA", tempfile.mkdtemp(prefix="sn_persist_"))
    # rebind db to the fresh path
    import importlib
    from backend import db as _db
    importlib.reload(_db)
    from backend import settings as _s
    importlib.reload(_s)
    from backend.engine import scanner as _sc
    importlib.reload(_sc)
    from backend.state import STATE
    STATE.devices.clear()
    STATE.rules_restored = False
    yield _sc, _db, _s, STATE
    STATE.devices.clear()
    STATE.rules_restored = False


def _dev(STATE, ip, mac, **kw):
    from backend.state import Device
    d = Device(ip=ip, mac=mac, **kw)
    STATE.devices[ip] = d
    return d


def test_default_setting_is_off(isolated):
    _sc, _db, _s, STATE = isolated
    assert _s.load().get("restore_rules") is False


def test_off_preserves_fresh_session_neutral(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m1", "cut", 0, 0)
    _s.save({"restore_rules": False})
    _dev(STATE, "10.0.0.1", "m1")
    _sc._maybe_restore_saved_rules()
    assert STATE.devices["10.0.0.1"].mode == "allow"


def test_on_restores_limit(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m2", "limit", 500, 300)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.2", "m2")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "limit" and d.down_kbps == 500 and d.up_kbps == 300


def test_on_restores_cut(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m3", "cut", 0, 0)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.3", "m3")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "cut"


def test_on_restores_hardcut(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m4", "hardcut", 0, 0)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.4", "m4")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "hardcut"


def test_on_restores_domain_blocks(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m5", "allow", 0, 0)
    _db.save_blocked("m5", ["ads.example", "track.example"])
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.5", "m5")
    _sc._maybe_restore_saved_rules()
    assert d.blocked == ["ads.example", "track.example"]
    assert "ads.example" in d.eff_blocked


def test_off_never_restores_a_destructive_rule(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m6", "hardcut", 0, 0)
    _s.save({"restore_rules": False})
    d = _dev(STATE, "10.0.0.6", "m6")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "allow", "OFF must never silently apply a saved CUT/HARD CUT"


def test_malformed_persisted_mode_fails_safe(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m7", "banana", 0, 0)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.7", "m7")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "allow", "an unknown saved mode must not be applied"


def test_gateway_and_self_are_never_restored(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("gw", "cut", 0, 0)
    _db.save_rule("me", "cut", 0, 0)
    _s.save({"restore_rules": True})
    gw = _dev(STATE, "10.0.0.254", "gw", is_gateway=True)
    me = _dev(STATE, "10.0.0.7", "me", is_self=True)
    _sc._maybe_restore_saved_rules()
    assert gw.mode == "allow" and me.mode == "allow"


def test_setting_persists(isolated):
    _sc, _db, _s, STATE = isolated
    _s.save({"restore_rules": True})
    assert _s.load().get("restore_rules") is True
    _s.save({"restore_rules": False})
    assert _s.load().get("restore_rules") is False


def test_restore_runs_once_per_session_and_never_reclobbers(isolated):
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m8", "cut", 0, 0)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.8", "m8")
    _sc._maybe_restore_saved_rules()
    assert d.mode == "cut" and STATE.rules_restored is True
    # user uncuts this session; a later scan must NOT re-apply the saved cut
    d.mode = "allow"
    _sc._maybe_restore_saved_rules()
    assert d.mode == "allow"


def test_in_session_changed_device_is_not_seeded(isolated):
    """A device the user already set this session is skipped even on the first
    restore pass (only still-neutral devices are seeded)."""
    _sc, _db, _s, STATE = isolated
    _db.save_rule("m9", "cut", 0, 0)
    _s.save({"restore_rules": True})
    d = _dev(STATE, "10.0.0.9", "m9", mode="limit", down_kbps=100)
    _sc._maybe_restore_saved_rules()
    assert d.mode == "limit", "a device with a live in-session rule is never overwritten"


def test_settings_bool_coercion_for_restore_rules(isolated):
    _sc, _db, _s, STATE = isolated
    s = _s.save({"restore_rules": 1})       # truthy non-bool from a sloppy client
    assert s["restore_rules"] is True
