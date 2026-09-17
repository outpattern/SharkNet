"""
SHARKmac unit tests — MAC generation + validation (pure logic, no OS/network).
Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine import sharkmac as sm            # noqa: E402


# ---------------- parsing / normalization ----------------
def test_normalize_accepts_common_forms():
    assert sm.normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert sm.normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert sm.normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert sm.normalize_mac("  02:00:00:00:00:01 ") == "02:00:00:00:00:01"


def test_normalize_rejects_junk():
    for bad in ["", "xyz", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff", "12345"]:
        assert sm.normalize_mac(bad) is None


# ---------------- predicates ----------------
def test_bit_predicates():
    assert sm.is_multicast("01:00:5e:00:00:01")       # I/G set
    assert not sm.is_multicast("02:00:00:00:00:01")
    assert sm.is_locally_administered("02:00:00:00:00:01")   # U/L set
    assert not sm.is_locally_administered("f0:db:f8:11:22:33")  # real Apple OUI
    assert sm.is_broadcast("ff:ff:ff:ff:ff:ff")
    assert sm.is_all_zero("00:00:00:00:00:00")
    assert sm.is_unicast("02:00:00:00:00:01")


# ---------------- validate_for_apply ----------------
def test_validate_rejects_dangerous_and_dupes():
    assert sm.validate_for_apply("ff:ff:ff:ff:ff:ff")[0] is False   # broadcast
    assert sm.validate_for_apply("00:00:00:00:00:00")[0] is False   # all-zero
    assert sm.validate_for_apply("01:00:5e:00:00:01")[0] is False   # multicast
    assert sm.validate_for_apply("nope")[0] is False                # invalid
    ok, why = sm.validate_for_apply("02:aa:bb:cc:dd:ee",
                                    current="02:aa:bb:cc:dd:ee")
    assert ok is False and "current" in why.lower()
    assert sm.validate_for_apply("02:11:22:33:44:55",
                                 avoid={"02:11:22:33:44:55"})[0] is False
    assert sm.validate_for_apply("02:11:22:33:44:56")[0] is True


# ---------------- random ----------------
def test_random_mac_is_valid_local_unicast():
    for _ in range(200):
        m = sm.random_mac()
        assert sm.is_valid(m)
        assert sm.is_unicast(m) and sm.is_locally_administered(m)
        assert not sm.is_broadcast(m) and not sm.is_all_zero(m)


def test_random_mac_varies_and_avoids():
    cur = sm.random_mac()
    saved = {sm.random_mac() for _ in range(5)}
    got = {sm.random_mac(avoid={cur} | saved) for _ in range(50)}
    assert len(got) > 40                     # high entropy, effectively unique
    assert cur not in got and not (got & saved)


# ---------------- stable ----------------
def test_stable_mac_is_deterministic():
    a = sm.stable_mac("seed-123", "Home Test")
    b = sm.stable_mac("seed-123", "Home Test")
    c = sm.stable_mac("seed-123", "Office")
    assert a == b                            # reproducible
    assert a != c                            # different profile -> different MAC
    assert sm.is_unicast(a) and sm.is_locally_administered(a)


# ---------------- vendor ----------------
def test_vendor_mac_keeps_oui_and_is_global_unicast():
    oui = "f0:db:f8"                         # a real Apple OUI
    m = sm.vendor_mac(oui)
    assert m.startswith(oui)
    assert sm.is_unicast(m)
    assert not sm.is_locally_administered(m)  # looks like a real vendor NIC
    # tail varies
    tails = {sm.vendor_mac(oui)[9:] for _ in range(30)}
    assert len(tails) > 20


def test_vendor_mac_rejects_bad_oui():
    assert sm.vendor_mac("zz:zz:zz") is None
    assert sm.vendor_mac("f0:db") is None


# ---------------- vendor OUI database ----------------
def test_vendor_db_loads_and_is_sane():
    db = sm.VENDORS
    vendors = db.vendors()
    assert len(vendors) >= 10                       # curated list is populated
    for v in ("Apple", "Samsung", "Intel", "TP-Link", "Cisco"):
        assert v in vendors
    # EVERY stored OUI must be a valid unicast/global prefix (no invented junk)
    for v in vendors:
        for oui in db.ouis_for(v):
            assert sm.normalize_mac(oui + ":00:00:00") is not None
            full = oui + ":11:22:33"
            assert sm.is_unicast(full)
            assert not sm.is_multicast(full)


def test_vendor_db_generate_and_search():
    db = sm.VENDORS
    m = db.generate("Apple")
    assert m and any(m.startswith(o) for o in db.ouis_for("Apple"))
    assert sm.is_unicast(m)
    assert "TP-Link" in db.search("tp")
    assert db.search("") == db.vendors()
    assert db.random_oui("NoSuchVendor") is None
    assert db.generate("NoSuchVendor") is None


# ---------------- coordinator isolation (the wrong-adapter bug fix) ----------
def _fake_change_env(monkeypatch, active_guid, changed_guid):
    from backend import server
    from backend.engine import macadapter
    ad = {"name": "TestNIC", "guid": changed_guid, "permanent": "aa:bb:cc:dd:ee:ff",
          "current": "aa:bb:cc:dd:ee:ff", "capability": "supported", "reason": ""}
    monkeypatch.setattr(macadapter, "find_adapter", lambda g, force=False: ad)
    monkeypatch.setattr(macadapter, "set_mac", lambda g, m: (True, ""))
    monkeypatch.setattr(macadapter, "clear_mac", lambda g: (True, ""))
    monkeypatch.setattr(macadapter, "cycle_adapter", lambda n: (True, ""))
    monkeypatch.setattr(macadapter, "verify_effective", lambda g, m: True)
    monkeypatch.setattr(macadapter, "effective_mac", lambda g: "02:11:22:33:44:55")
    monkeypatch.setattr(server, "_selected_guid", lambda: active_guid)
    calls = []
    monkeypatch.setattr(server, "stop_control", lambda: calls.append("stop_control"))
    monkeypatch.setattr(server, "_fresh_scan", lambda: calls.append("fresh_scan"))
    monkeypatch.setattr(server, "_reselect_interface", lambda n: calls.append("reselect"))
    monkeypatch.setattr(server, "_snapshot_rules", lambda: {})
    events = []
    monkeypatch.setattr(server.STATE, "push_event", lambda kind, **k: events.append((kind, k)))
    return server, calls, events


def test_change_on_non_active_adapter_leaves_session_untouched(monkeypatch):
    """THE fix: changing an adapter SharkNet is NOT controlling must never stop
    enforcement, re-select the interface, or start a fresh scan."""
    server, calls, events = _fake_change_env(monkeypatch, active_guid="{ETH}", changed_guid="{WIFI}")
    server._run_mac_change("{WIFI}", "02:11:22:33:44:55", False)
    assert calls == []                                   # zero session side effects
    assert events[0][0] == "mac_changed"
    assert events[0][1].get("session_reset") is False


def test_change_on_active_adapter_resets_session(monkeypatch):
    """Changing the controlling adapter DOES reset the session (fresh scan)."""
    server, calls, events = _fake_change_env(monkeypatch, active_guid="{ETH}", changed_guid="{ETH}")
    server._run_mac_change("{ETH}", "02:11:22:33:44:55", False)
    assert "stop_control" in calls and "fresh_scan" in calls and "reselect" in calls
    assert events[0][0] == "mac_changed"
    assert events[0][1].get("session_reset") is True


def test_generate_endpoint_avoids_current_without_adapter_lookup():
    from backend import server
    r = server.api_mac_generate(server.MacGenReq(preset="random", current="02:aa:bb:cc:dd:ee"))
    assert r["ok"] and r["mac"] != "02:aa:bb:cc:dd:ee"
