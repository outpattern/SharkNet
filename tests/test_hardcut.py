"""
V3.1 HARD CUT regression tests.

HARD CUT is an ADDITIONAL enforcement mode — maximum isolation via a blackhole
drop in the forwarder BEFORE any observation. These tests prove:

  * ALLOW / LIMIT / CUT behave EXACTLY as before (not weakened by the addition),
  * HARD CUT has its own distinct behavior (drop + NO observation),
  * HARD CUT never enters the forward/inject path,
  * HARD CUT rides the same is_managed/is_intercepted machinery (so ARP spoof +
    cleanup + recovery apply unchanged),
  * every switch between modes (hardcut<->allow/limit/cut) is correct,
  * self/gateway can never be hard-cut.

Real frames go through the REAL Forwarder._handle with a fake injector, so these
are behavioral proofs, not mocks of the decision.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.state import STATE, Device, is_managed, is_intercepted   # noqa: E402
from backend.engine import policy                                     # noqa: E402
from backend.engine import npcap                                      # noqa: E402
from backend.engine.forwarder import Forwarder                        # noqa: E402
from backend.engine.spoofer import SPOOFER                            # noqa: E402
from backend.engine import netinfo                                    # noqa: E402
from backend import server                                            # noqa: E402

OUR_MAC = "02:00:00:00:00:aa"
DEV_MAC = "de:ad:be:ef:00:11"
DEV_IP = "192.168.9.50"
NET = "142.250.1.10"          # an "internet" destination


@pytest.fixture(autouse=True)
def _reset():
    def clean():
        STATE.devices.clear()
        STATE.net_services = []
        STATE.net_domains = []
        STATE.enforcing = False
        STATE.controlling = False
        STATE.interface = None
    clean()
    yield
    clean()


def _iface():
    return netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac=OUR_MAC, netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")


class _FakeInj:
    def __init__(self): self.sent = []
    def send(self, b): self.sent.append(b)
    def close(self): pass


def _fwd():
    STATE.interface = _iface()
    f = Forwarder()
    f._inj = _FakeInj()
    f._my_mac_b = f._mac_to_bytes(OUR_MAC)
    SPOOFER._gateway_mac = "aa:bb:cc:dd:ee:ff"      # give the forward path a next hop
    return f


def _mk(ip=DEV_IP, mac=DEV_MAC, **kw):
    d = Device(ip=ip, mac=mac, **kw)
    STATE.devices[ip] = d
    STATE.recompute_effective(d)
    return d


def _up(dev_ip=DEV_IP, dev_mac=DEV_MAC, dst=NET, dport=443, payload=b"hello"):
    """A device -> internet frame addressed to us at L2 (the 'up' direction)."""
    from scapy.all import Ether, IP, TCP, Raw
    p = (Ether(src=dev_mac, dst=OUR_MAC) / IP(src=dev_ip, dst=dst) /
         TCP(sport=44100, dport=dport, flags="PA") / Raw(load=payload))
    return npcap._Frame(bytes(p))


def _sni(host=b"example.com", dev_ip=DEV_IP, dev_mac=DEV_MAC):
    from scapy.all import Ether, IP, TCP, Raw
    ext = b"\x00\x00" + (len(host) + 5).to_bytes(2, "big") + (len(host) + 3).to_bytes(2, "big") + \
          b"\x00" + len(host).to_bytes(2, "big") + host
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x00" + b"\x01\x00" + \
           len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    tls = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    p = (Ether(src=dev_mac, dst=OUR_MAC) / IP(src=dev_ip, dst=NET) /
         TCP(sport=44200, dport=443, flags="PA") / Raw(load=tls))
    return npcap._Frame(bytes(p))


# ============================================================ predicates / policy
def test_hardcut_is_managed_and_intercepted():
    d = _mk(mode="hardcut")
    assert is_managed(d) is True          # enforcement rule present
    assert is_intercepted(d) is True      # -> MITM'd, poisoned, restored by same path


def test_hardcut_action_for_is_drop():
    d = _mk(mode="hardcut")
    assert policy.action_for(d, "up", None) == policy.DROP
    assert policy.action_for(d, "down", None) == policy.DROP


def test_self_and_gateway_never_hardcut():
    me = _mk(ip="192.168.9.2", mac="aa", mode="hardcut", is_self=True)
    gw = _mk(ip="192.168.9.1", mac="bb", mode="hardcut", is_gateway=True)
    assert is_managed(me) is False and is_intercepted(me) is False
    assert is_managed(gw) is False and is_intercepted(gw) is False


# ============================================================ ALLOW/LIMIT/CUT unchanged
def test_allow_still_forwards():
    f = _fwd(); _mk(mode="allow")          # allow + no blocks = not intercepted
    # an ALLOW device with no rule is not intercepted -> select_target returns None ->
    # the packet is not ours to forward. Prove instead a MONITORED allow forwards:
    d = STATE.get(DEV_IP); d.monitor = True
    before = len(f._inj.sent)
    f._handle(_up())
    assert len(f._inj.sent) == before + 1, "ALLOW (observed) traffic must still forward"


def test_limit_still_throttles_and_forwards_within_budget():
    f = _fwd(); _mk(mode="limit", down_kbps=1024, up_kbps=1024)
    before = len(f._inj.sent)
    f._handle(_up(payload=b"x" * 40))       # small, within the fresh burst
    assert len(f._inj.sent) == before + 1, "LIMIT within budget must still forward"
    # its bytes ARE counted (LIMIT is observed)
    assert f.counters.get(DEV_IP, {}).get("up", 0) > 0


def test_cut_still_drops_but_is_counted():
    f = _fwd(); _mk(mode="cut")
    before = len(f._inj.sent)
    f._handle(_up())
    assert len(f._inj.sent) == before, "CUT must drop (no forward) — unchanged"
    assert f.counters.get(DEV_IP, {}).get("up", 0) > 0, \
        "CUT is still OBSERVED (byte-counted) — unchanged from V3.0"


# ============================================================ HARD CUT distinct behavior
def test_hardcut_drops_and_does_not_forward():
    f = _fwd(); _mk(mode="hardcut")
    before = len(f._inj.sent)
    for _ in range(5):
        f._handle(_up())
    assert len(f._inj.sent) == before, "HARD CUT must never enter the forward/inject path"


def test_hardcut_does_not_observe_traffic():
    """The core distinction from CUT: HARD CUT records NO byte counters (no traffic
    inspection) because it returns before _count()."""
    f = _fwd(); _mk(mode="hardcut")
    f._handle(_up())
    assert DEV_IP not in f.counters or f.counters[DEV_IP].get("up", 0) == 0, \
        "HARD CUT must NOT count/observe the device's traffic"


def test_hardcut_does_not_parse_or_record_domains():
    f = _fwd(); d = _mk(mode="hardcut")
    f._handle(_sni(b"example.com"))
    assert not d.domains, "HARD CUT must not parse/observe visited domains"


def test_cut_vs_hardcut_same_network_effect_different_observation():
    """Both fully block; only observation differs — proving hard cut is 'cut + no
    inspection', never a change to what cut does."""
    f = _fwd()
    _mk(ip="192.168.9.60", mac="c1", mode="cut")
    _mk(ip="192.168.9.61", mac="c2", mode="hardcut")
    f._handle(_up(dev_ip="192.168.9.60", dev_mac="c1"))
    f._handle(_up(dev_ip="192.168.9.61", dev_mac="c2"))
    assert f._inj.sent == [], "both drop — identical network effect (zero access)"
    assert f.counters.get("192.168.9.60", {}).get("up", 0) > 0    # cut observed
    assert "192.168.9.61" not in f.counters                       # hard cut not observed


# ============================================================ switching between modes
def test_switch_hardcut_to_allow_unmanages():
    d = _mk(mode="hardcut")
    assert is_managed(d) and is_intercepted(d)
    d.mode = "allow"; STATE.recompute_effective(d)
    assert is_managed(d) is False and is_intercepted(d) is False   # leaves the MITM set


def test_switch_hardcut_to_limit():
    d = _mk(mode="hardcut")
    d.mode = "limit"; d.down_kbps = 512; STATE.recompute_effective(d)
    assert is_managed(d) and policy.action_for(d, "down", None) == policy.LIMIT


def test_switch_hardcut_to_cut_restores_observation():
    f = _fwd(); d = _mk(mode="hardcut")
    f._handle(_up()); assert DEV_IP not in f.counters          # hard cut: not observed
    d.mode = "cut"; STATE.recompute_effective(d)
    f._handle(_up())
    assert f.counters.get(DEV_IP, {}).get("up", 0) > 0         # cut: observed again
    assert f._inj.sent == []                                   # still fully blocked


def test_switch_cut_to_hardcut_stops_observation():
    f = _fwd(); d = _mk(mode="cut")
    f._handle(_up()); assert f.counters.get(DEV_IP, {}).get("up", 0) > 0
    base = dict(f.counters[DEV_IP])
    d.mode = "hardcut"; STATE.recompute_effective(d)
    f._handle(_up())
    assert f.counters[DEV_IP] == base, "after CUT->HARD CUT, no further bytes counted"
    assert f._inj.sent == []


# ============================================================ API + stats
def test_api_rule_accepts_hardcut(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")      # reconcile no-ops (no NIC)
    _mk(mode="allow")
    r = server.api_rule(server.RuleReq(ip=DEV_IP, mode="hardcut"))
    assert r["ok"] is True and r["device"]["mode"] == "hardcut"
    assert is_managed(STATE.get(DEV_IP)) is True


def test_bulk_rule_accepts_hardcut(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    _mk(ip="192.168.9.70", mac="d1", mode="allow")
    _mk(ip="192.168.9.71", mac="d2", mode="allow")
    r = server.api_bulk_rule(server.BulkRuleReq(ips=["192.168.9.70", "192.168.9.71"],
                                                mode="hardcut"))
    assert r["ok"] is True
    assert all(d.mode == "hardcut" for d in STATE.devices.values())


def test_policy_summary_counts_hardcut_under_cut():
    _mk(ip="192.168.9.80", mac="e1", mode="cut")
    _mk(ip="192.168.9.81", mac="e2", mode="hardcut")
    s = server._policy_summary()
    assert s["hardcut"] == 1
    assert s["cut"] == 2, "the Cut stat counts cut + hard cut (both = zero access)"


def test_invalid_mode_falls_back_to_allow():
    _mk(mode="allow")
    server._apply_device_rule(STATE.get(DEV_IP), "banana", 0, 0)
    assert STATE.get(DEV_IP).mode == "allow"      # unknown mode is never applied
