"""
P0 (observation/enforcement separation) + P1 (per-device Monitor).

Proves the core invariants:
    ALLOW + MONITOR  ≠  CUT  ≠  LIMIT
    OBSERVATION      ≠  ENFORCEMENT

i.e. Monitor makes a device INTERCEPTED + observed, but never managed, never
dropped/limited/blocked; enforcement state never implicitly turns observation on.
"""
import pytest

from backend.state import STATE, Device, is_managed, is_intercepted
from backend.engine import policy


@pytest.fixture(autouse=True)
def _clean():
    # no NETWORK-scope rule interfering with the per-device predicates
    STATE.net_services = []
    STATE.net_domains = []
    yield
    STATE.net_services = []
    STATE.net_domains = []


def dev(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02", **kw):
    return Device(ip=ip, mac=mac, **kw)


# ---------------- P0: separation ----------------
def test_allow_off_is_not_intercepted():
    d = dev()                                  # enforcement ALLOW, observation OFF
    assert not is_managed(d)
    assert not is_intercepted(d)               # never MITM'd


def test_limit_is_managed_and_intercepted():
    d = dev(mode="limit")
    assert is_managed(d) and is_intercepted(d)
    assert policy.action_for(d, "up", None) == policy.LIMIT


def test_cut_is_managed_and_drops():
    d = dev(mode="cut")
    assert is_managed(d) and is_intercepted(d)
    assert policy.action_for(d, "up", None) == policy.DROP


def test_block_is_managed():
    d = dev(blocked=["tiktok.com"])
    assert is_managed(d) and is_intercepted(d)


def test_select_target_ignores_allow_off():
    d = dev()
    lookup = lambda ip: d if ip == d.ip else None
    target, _ = policy.select_target(d.ip, "1.2.3.4", lookup)
    assert target is None                      # not selected -> not observed, not enforced


# ---------------- P1: Monitor = observe-only ----------------
def test_monitor_intercepts_without_managing():
    d = dev(monitor=True)                       # ALLOW + MONITOR
    assert is_intercepted(d)                    # observed (MITM'd)
    assert not is_managed(d)                     # but NOT an enforcement rule
    assert d.mode == "allow"                     # enforcement untouched
    # selected by the forwarder, and FORWARDED (never dropped/limited)
    lookup = lambda ip: d if ip == d.ip else None
    target, direction = policy.select_target(d.ip, "1.2.3.4", lookup)
    assert target is d and direction == "up"
    assert policy.action_for(d, "up", None) == policy.FORWARD


def test_monitor_never_drops_or_limits():
    d = dev(monitor=True)
    assert policy.action_for(d, "up", None) != policy.DROP
    assert policy.action_for(d, "up", None) != policy.LIMIT
    assert policy.action_for(d, "down", None) == policy.FORWARD


def test_the_invariant_allow_monitor_ne_cut_ne_limit():
    allow_mon = dev(monitor=True)
    cut = dev(mode="cut")
    lim = dev(mode="limit")
    a = policy.action_for(allow_mon, "up", None)
    c = policy.action_for(cut, "up", None)
    l = policy.action_for(lim, "up", None)
    assert a == policy.FORWARD and c == policy.DROP and l == policy.LIMIT
    assert a != c and c != l and a != l         # ALLOW+MONITOR ≠ CUT ≠ LIMIT
    # OBSERVATION ≠ ENFORCEMENT: monitored is intercepted but not managed
    assert is_intercepted(allow_mon) and not is_managed(allow_mon)


def test_case4_limit_plus_monitor_keeps_limit():
    d = dev(mode="limit", monitor=True)
    assert is_managed(d) and is_intercepted(d)
    assert policy.action_for(d, "up", None) == policy.LIMIT   # monitor never weakens enforcement


def test_two_devices_do_not_interfere():
    a = dev(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:05", monitor=True)  # ALLOW+MONITOR
    b = dev(ip="10.0.0.6", mac="aa:bb:cc:dd:ee:06")                # ALLOW+OFF
    lookup = {a.ip: a, b.ip: b}.get
    ta, _ = policy.select_target(a.ip, "1.2.3.4", lookup)
    tb, _ = policy.select_target(b.ip, "1.2.3.4", lookup)
    assert ta is a                              # A observed
    assert tb is None                           # B untouched


def test_intercepted_set_vs_managed_set():
    STATE.devices.clear()
    a = STATE.upsert_device("10.0.0.7", "aa:bb:cc:dd:ee:07"); a.monitor = True
    b = STATE.upsert_device("10.0.0.8", "aa:bb:cc:dd:ee:08"); b.mode = "limit"
    c = STATE.upsert_device("10.0.0.9", "aa:bb:cc:dd:ee:09")            # allow off
    inter = {d.ip for d in STATE.intercepted()}
    man = {d.ip for d in STATE.managed()}
    assert a.ip in inter and b.ip in inter and c.ip not in inter        # monitor ∪ enforce
    assert a.ip not in man and b.ip in man and c.ip not in man          # monitor-only NOT managed
    STATE.devices.clear()


def test_self_and_gateway_never_intercepted_even_if_monitor_flag():
    s = dev(is_self=True, monitor=True)
    g = dev(is_gateway=True, monitor=True)
    assert not is_intercepted(s) and not is_intercepted(g)


# ---------------- P1: API endpoint (observation only) ----------------
def test_api_monitor_is_observation_only(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")    # reconcile is a no-op; no network
    from backend.server import api_monitor, MonitorReq
    STATE.devices.clear()
    d = STATE.upsert_device("10.0.0.20", "aa:bb:cc:dd:ee:20")
    r = api_monitor(MonitorReq(ip="10.0.0.20", on=True))
    assert r["ok"] is True
    assert d.monitor is True
    assert d.mode == "allow"                    # ENFORCEMENT untouched
    assert not is_managed(d)                     # monitor is NOT an enforcement rule
    assert is_intercepted(d)                      # but it IS intercepted
    assert d.to_dict()["monitor"] is True         # exposed to the UI
    # turning it off leaves an ALLOW device with no interception
    r2 = api_monitor(MonitorReq(ip="10.0.0.20", on=False))
    assert r2["ok"] is True
    assert d.monitor is False and not is_intercepted(d)
    STATE.devices.clear()


def test_api_monitor_rejects_self_gateway(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    from backend.server import api_monitor, MonitorReq
    STATE.devices.clear()
    g = STATE.upsert_device("10.0.0.1", "aa:bb:cc:dd:ee:01", is_gateway=True)
    r = api_monitor(MonitorReq(ip="10.0.0.1", on=True))
    assert getattr(r, "status_code", 200) == 400
    assert g.monitor is False
    STATE.devices.clear()
