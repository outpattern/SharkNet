"""
Regression tests for the release-hardening phase. Pure logic — no network,
no admin, no sockets. Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.state import AppState, Device, is_managed          # noqa: E402
from backend.engine import policy                                # noqa: E402


IP = "10.0.0.5"          # a device on the LAN
NET = "93.184.216.34"    # "example.com" out on the internet


def _lookup(*devs):
    m = {d.ip: d for d in devs}
    return m.get


# ---------------------------------------------------------------------------
# P0: rule/blocked semantics via the SHARED policy (both engines use this)
#   A allow · B cut · C limit · D block-only · E block+limit · F block+cut
# ---------------------------------------------------------------------------
def test_A_allow_is_never_managed():
    d = Device(ip=IP, mac="aa", mode="allow")
    assert not is_managed(d)
    # not managed -> policy never even targets it (traffic untouched)
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.PASS
    assert policy.decide(IP, NET, "example.com", _lookup(d))[0] == policy.PASS


def test_B_cut_drops_everything():
    d = Device(ip=IP, mac="aa", mode="cut")
    assert is_managed(d)
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.DROP
    assert policy.decide(IP, NET, "anything.com", _lookup(d))[0] == policy.DROP
    # download direction too (dst is the device)
    assert policy.decide(NET, IP, None, _lookup(d))[0] == policy.DROP


def test_C_limit_rate_limits():
    d = Device(ip=IP, mac="aa", mode="limit", down_kbps=1500, up_kbps=512)
    assert is_managed(d)
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.LIMIT
    assert policy.decide(NET, IP, None, _lookup(d))[0] == policy.LIMIT


def test_D_block_only_blocks_domain_but_forwards_the_rest():
    """THE critical regression: domain-block-only must NEVER be a blackout."""
    d = Device(ip=IP, mac="aa", mode="allow", blocked=["example.com"])
    assert is_managed(d)                       # so it IS MITM'd (spoofed)
    # request to the blocked domain -> DROP
    assert policy.decide(IP, NET, "example.com", _lookup(d))[0] == policy.DROP
    assert policy.decide(IP, NET, "m.example.com", _lookup(d))[0] == policy.DROP
    # request to any OTHER domain -> FORWARD (not dropped)
    assert policy.decide(IP, NET, "google.com", _lookup(d))[0] == policy.FORWARD
    # a normal non-request packet (no domain parsed) -> FORWARD, never DROP
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.FORWARD
    # inbound/download packets -> FORWARD
    assert policy.decide(NET, IP, None, _lookup(d))[0] == policy.FORWARD


def test_D_block_only_is_not_equivalent_to_cut():
    """Explicit: a whole stream of ordinary packets is forwarded, not cut."""
    blocked = Device(ip=IP, mac="aa", mode="allow", blocked=["example.com"])
    cut = Device(ip=IP, mac="aa", mode="cut")
    lk_b, lk_c = _lookup(blocked), _lookup(cut)
    forwarded = sum(policy.decide(IP, NET, None, lk_b)[0] == policy.FORWARD for _ in range(50))
    dropped = sum(policy.decide(IP, NET, None, lk_c)[0] == policy.DROP for _ in range(50))
    assert forwarded == 50      # block-only forwards everything non-blocked
    assert dropped == 50        # cut drops everything
    assert forwarded != 0       # <-- the bug would have made this 0 (blackout)


def test_E_block_plus_limit():
    d = Device(ip=IP, mac="aa", mode="limit", down_kbps=1000, blocked=["example.com"])
    assert policy.decide(IP, NET, "example.com", _lookup(d))[0] == policy.DROP   # block wins
    assert policy.decide(IP, NET, "other.com", _lookup(d))[0] == policy.LIMIT    # else limited
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.LIMIT


def test_F_block_plus_cut():
    d = Device(ip=IP, mac="aa", mode="cut", blocked=["example.com"])
    assert policy.decide(IP, NET, "example.com", _lookup(d))[0] == policy.DROP
    assert policy.decide(IP, NET, "other.com", _lookup(d))[0] == policy.DROP     # cut drops all
    assert policy.decide(IP, NET, None, _lookup(d))[0] == policy.DROP


def test_I_rapid_state_transitions_leave_no_stale_decision():
    """The classifier is stateless: each transition is judged only by the
    device's CURRENT rule/blocks — no memory of a previous mode leaks through."""
    d = Device(ip=IP, mac="aa", mode="allow")
    lk = _lookup(d)
    seq = [
        ("allow", [], policy.PASS,   None),
        ("cut", [], policy.DROP,     None),
        ("limit", [], policy.LIMIT,  None),
        ("allow", ["example.com"], policy.FORWARD, "google.com"),   # block-only, other domain
        ("allow", ["example.com"], policy.DROP,    "example.com"),  # block-only, blocked
        ("allow", [], policy.PASS,   None),                         # fully released
    ]
    for mode, blocked, expect, dom in seq:
        d.mode, d.blocked = mode, blocked
        assert policy.decide(IP, NET, dom, lk)[0] == expect, (mode, blocked, dom)


def test_J_device_removed_from_managed_set():
    """Returning to allow+no-blocks removes the device from managed()."""
    st = AppState()
    d = Device(ip=IP, mac="aa", mode="cut")
    st.devices[IP] = d
    assert d.ip in {x.ip for x in st.managed()}      # managed while cut
    d.mode, d.blocked = "allow", []
    assert d.ip not in {x.ip for x in st.managed()}  # gone once allowed
    assert policy.decide(IP, NET, None, st.get)[0] == policy.PASS


def test_P0_domains_mutation_does_not_crash_snapshot():
    """Forwarder thread mutates Device.domains while the broadcaster calls
    to_dict()/snapshot() ~1 Hz. Regression: to_dict used dataclasses.asdict,
    which iterated domains and raised 'dict changed size during iteration',
    killing the live-update pump. to_dict must never iterate domains."""
    import threading, time as _t
    st = AppState()
    d = Device(ip="10.0.0.9", mac="zz", mode="limit")
    st.devices["10.0.0.9"] = d
    stop = threading.Event(); errors = []

    def mutate():
        i = 0
        while not stop.is_set():
            dm = d.domains
            if len(dm) > 400:
                dm.clear()
            dm["host%d.com" % i] = _t.time(); i += 1

    def snap():
        try:
            while not stop.is_set():
                st.snapshot()      # to_dict on every device
                d.to_dict()
        except Exception as e:     # a RuntimeError here = the P0 bug
            errors.append(repr(e))

    tm = threading.Thread(target=mutate); ts = threading.Thread(target=snap)
    tm.start(); ts.start(); _t.sleep(1.2); stop.set(); tm.join(); ts.join()
    assert not errors, "snapshot raced with domains mutation: %s" % errors
    dd = d.to_dict()
    assert "domains" not in dd and dd["domain_count"] >= 0


def test_P1_refresh_preserves_session_rules(monkeypatch):
    """A mid-session re-scan ('Refresh devices') must NOT drop the active
    CUT/LIMIT/BLOCK the user set this session (regression: scan cleared the
    device table and re-added everything as `allow`)."""
    from backend.engine import scanner, netinfo
    from backend.state import STATE as G
    G.interface = netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")
    G.devices.clear(); G.scanning = False
    # user CUT one device and domain-blocked another, this session
    G.devices["192.168.9.50"] = Device(ip="192.168.9.50", mac="de:ad:be:ef:00:01", mode="cut")
    G.devices["192.168.9.51"] = Device(ip="192.168.9.51", mac="de:ad:be:ef:00:02",
                                       mode="allow", blocked=["youtube.com"])
    # re-scan finds the same two devices (one at a NEW ip) + a brand-new device
    monkeypatch.setattr(scanner, "_scan_once", lambda iface, timeout=3.0: [
        ("192.168.9.77", "de:ad:be:ef:00:01"),   # the CUT device, new IP
        ("192.168.9.51", "de:ad:be:ef:00:02"),   # the blocked device
        ("192.168.9.60", "de:ad:be:ef:00:99"),   # a new device
    ])
    monkeypatch.setattr(scanner.db, "load_devices", lambda: {})
    monkeypatch.setattr(scanner, "_enrich", lambda devs, cb: None)   # no bg network
    try:
        scanner.scan(on_update=None)
        cut = next((d for d in G.devices.values() if d.mac == "de:ad:be:ef:00:01"), None)
        blk = G.get("192.168.9.51")
        new = G.get("192.168.9.60")
        assert cut is not None and cut.mode == "cut", "active CUT was dropped by refresh"
        assert blk is not None and blk.blocked == ["youtube.com"], "domain block was dropped"
        assert new is not None and new.mode == "allow" and not new.blocked, "new device must start allow"
    finally:
        G.devices.clear(); G.interface = None; G.scanning = False


def test_P1b_refresh_preserves_services_and_monitor(monkeypatch):
    """V3.0 audit regression: a mid-session refresh must ALSO carry device-scope
    SERVICE blocks and the observation MONITOR flag — not just mode/domain-block.
    Previously the snapshot tuple was only (mode, down, up, blocked), so a service
    block silently vanished and Monitor turned off on every 'Refresh devices'."""
    from backend.engine import scanner, netinfo
    from backend.state import STATE as G, is_managed, is_intercepted
    G.interface = netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")
    G.devices.clear(); G.scanning = False; G.net_services = []; G.net_domains = []
    # A: ALLOW + service block (managed via services). B: ALLOW + MONITOR (observe only).
    a = Device(ip="192.168.9.50", mac="de:ad:be:ef:00:01", mode="allow", services=["youtube"])
    G.recompute_effective(a); G.devices["192.168.9.50"] = a
    b = Device(ip="192.168.9.51", mac="de:ad:be:ef:00:02", mode="allow", monitor=True)
    G.devices["192.168.9.51"] = b
    monkeypatch.setattr(scanner, "_scan_once", lambda iface, timeout=3.0: [
        ("192.168.9.50", "de:ad:be:ef:00:01"),
        ("192.168.9.51", "de:ad:be:ef:00:02"),
    ])
    monkeypatch.setattr(scanner.db, "load_devices", lambda: {})
    monkeypatch.setattr(scanner, "_enrich", lambda devs, cb: None)
    try:
        scanner.scan(on_update=None)
        svc = G.get("192.168.9.50"); mon = G.get("192.168.9.51")
        assert svc is not None and svc.services == ["youtube"], "SERVICE block dropped by refresh"
        assert is_managed(svc), "service-blocked device lost managed status after refresh"
        assert len(svc.eff_blocked) > 0, "eff_blocked not rebuilt from services after refresh"
        assert mon is not None and mon.monitor is True, "MONITOR flag dropped by refresh"
        assert mon.mode == "allow" and not is_managed(mon), "monitor must not become an enforcement rule"
        assert is_intercepted(mon), "monitored device must stay intercepted after refresh"
    finally:
        G.devices.clear(); G.interface = None; G.scanning = False; G.net_services = []; G.net_domains = []


def test_no_windivert_module_remains():
    """WinDivert is fully removed — importing it must fail, and nothing in the
    server references a WINDIVERT engine."""
    import importlib
    try:
        importlib.import_module("backend.engine.windivert_forwarder")
        assert False, "windivert_forwarder should not exist"
    except ModuleNotFoundError:
        pass
    from backend import server
    assert not hasattr(server, "WINDIVERT")


def test_managed_predicate_matches_state():
    """STATE.managed() and policy.select_target must agree on the same set."""
    st = AppState()
    allow = Device(ip="10.0.0.1", mac="a", mode="allow")
    blocked = Device(ip="10.0.0.2", mac="b", mode="allow", blocked=["x.com"])
    cut = Device(ip="10.0.0.3", mac="c", mode="cut")
    limit = Device(ip="10.0.0.4", mac="d", mode="limit")
    for d in (allow, blocked, cut, limit):
        st.devices[d.ip] = d
    managed_ips = {d.ip for d in st.managed()}
    assert managed_ips == {"10.0.0.2", "10.0.0.3", "10.0.0.4"}   # allow excluded
    assert "10.0.0.1" not in managed_ips


# ---------------------------------------------------------------------------
# Scan concurrency (TOCTOU): begin_scan() is an atomic claim
# ---------------------------------------------------------------------------
def test_begin_scan_is_atomic_claim():
    st = AppState()
    assert st.begin_scan() is True       # first claim wins
    assert st.begin_scan() is False      # second is refused while scanning
    st.scanning = False
    assert st.begin_scan() is True       # released -> can claim again


# ---------------------------------------------------------------------------
# Defender ack must never raise when the interface/gateway is unavailable
# ---------------------------------------------------------------------------
def test_defender_ack_safe_without_interface():
    from backend.engine.defender import Defender
    d = Defender()
    d.iface = None
    d.alert = {"type": "gateway_spoof", "message": "x"}
    d.acknowledge()                      # must not raise
    assert d.alert is None

    class _If:                           # gateway missing
        gateway = ""
        name = "x"
        mac = "aa"
    d.iface = _If()
    d.alert = {"type": "x"}
    d.acknowledge()                      # must not raise
    assert d.alert is None


# ---------------------------------------------------------------------------
# Local API security helpers (Origin / Host validation)
# ---------------------------------------------------------------------------
def test_origin_and_host_validation():
    from backend import server
    assert server._host_is_local("127.0.0.1:8734")
    assert server._host_is_local("localhost:9000")
    assert server._host_is_local("[::1]:8734")
    assert not server._host_is_local("evil.com")
    assert not server._host_is_local("evil.com:80")

    assert server._origin_ok(None)                       # non-browser/local GET
    assert server._origin_ok("http://127.0.0.1:8734")    # our own WebView
    assert server._origin_ok("http://localhost:8734")
    assert not server._origin_ok("https://evil.com")     # cross-origin page
    assert not server._origin_ok("http://attacker.example:1234")


def test_api_token_exists_and_cleanup_idempotent():
    from backend import server
    assert isinstance(server.API_TOKEN, str) and len(server.API_TOKEN) >= 16
    # cleanup must be safe to call repeatedly with nothing started
    server.cleanup()
    server.cleanup()
