"""
Phase 7 tests — service model, network scope + precedence, bulk actions, scoped
QUIC/DNS-pin enforcement, policy-aware health, catalog. Pure logic + in-process
endpoint calls; no admin, no real network (reconcile is neutralised with
SHARKNET_DEMO where it would otherwise touch the NIC).

Covers the approved matrix: B service identification · C service blocking ·
D existing presets · E expanded presets · F network rules · G device rules ·
H network-vs-device precedence · I/J/K/L multi-select + bulk allow/limit/cut ·
M partial bulk failure · N recovery predicate · O/P/Q policy-aware health ·
S CUT-ALL regression · U native backend · plus scoped QUIC (DNS/TLS/Host/UDP443).
(A domain-blocking regression lives in test_hardening/test_core; R/T/UI are
browser-verified; V scapy-absent is test_gate64.)
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.state import STATE, Device, is_managed          # noqa: E402
from backend.engine import policy                             # noqa: E402
from backend.engine.services import CATALOG, block_signals    # noqa: E402
from backend.engine import npcap                              # noqa: E402
from backend.engine.forwarder import Forwarder                # noqa: E402
from backend.engine.spoofer import SPOOFER                    # noqa: E402
from backend.engine import netinfo                            # noqa: E402
from backend import server                                    # noqa: E402

IP = "10.0.0.5"
NET = "142.250.1.10"


def _lk(*devs):
    m = {d.ip: d for d in devs}
    return m.get


@pytest.fixture(autouse=True)
def _reset_state():
    """Global STATE is a singleton and is_managed() reads its network scope, so
    every test starts and ends with a clean slate (no leak to other modules)."""
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


def _mk(ip, mac="aa", **kw):
    d = Device(ip=ip, mac=mac, **kw)
    STATE.devices[ip] = d
    STATE.recompute_effective(d)
    return d


# ===================================================================== B
def test_B_service_identification():
    assert CATALOG.identify("rr3---sn-abc.googlevideo.com") == "youtube"
    assert CATALOG.identify("a.nflxvideo.net") == "netflix"
    assert CATALOG.identify("example.org") is None
    assert CATALOG.exists("disney-plus") and not CATALOG.exists("nope")


# ===================================================================== C
def test_C_service_blocking_is_not_a_cut():
    d = _mk(IP, mode="allow", services=["youtube"])
    assert is_managed(d)
    assert "googlevideo.com" in d.eff_blocked
    assert policy.decide(IP, NET, "x.googlevideo.com", _lk(d))[0] == policy.DROP
    assert policy.decide(IP, NET, "example.com", _lk(d))[0] == policy.FORWARD   # other -> forward
    assert policy.decide(IP, NET, None, _lk(d))[0] == policy.FORWARD            # non-request -> forward


# ===================================================================== D + E
def test_D_existing_16_presets_present_in_catalog():
    names = {s.name for s in CATALOG.all()}
    for n in ["YouTube", "TikTok", "Instagram", "Facebook", "Snapchat", "WhatsApp",
              "Netflix", "Twitter/X", "Shahid", "TOD", "OSN+", "Disney+"]:
        assert n in names, n


def test_E_expanded_catalog_covers_regions():
    regions = {}
    for s in CATALOG.all():
        for r in s.regions:
            regions.setdefault(r, 0)
            regions[r] += 1
    assert regions.get("mena", 0) >= 8
    assert regions.get("us", 0) >= 5
    assert regions.get("eu", 0) >= 8
    names = {s.name for s in CATALOG.all()}
    for n in ["STARZPLAY", "Amazon Prime Video", "Viu", "Crunchyroll", "MUBI",
              "WATCH IT", "Yango Play", "Hulu", "Max (HBO Max)", "BBC iPlayer"]:
        assert n in names, n


def test_E_shared_cdn_over_block_avoided():
    # our vetting: generic shared clouds must NOT be blocking keywords
    banned = {"akamaized.net", "cloudfront.net", "fastly.net", "amazonaws.com",
              "googleapis.com", "amazon.com", "yango.com", "mbc.net", "z5.com"}
    for s in CATALOG.all():
        for dom in s.domains:
            assert dom not in banned, f"{s.id} uses over-broad domain {dom}"
    # Yango Play is scoped to play.yango.com, never bare yango.com
    assert "play.yango.com" in CATALOG.domains_for(["yango-play"])
    assert "yango.com" not in CATALOG.domains_for(["yango-play"])


# ===================================================================== F + G + H
def test_H_network_block_overrides_device_allow():
    """Precedence: NETWORK ∪ DEVICE, most-restrictive wins. A device with mode
    allow and NO block is forced managed by a network rule and its YouTube is
    dropped — the device 'allow' cannot override the network block."""
    d = _mk(IP, mode="allow")                       # device: no rules at all
    assert not is_managed(d)                         # not managed on its own
    STATE.net_services = ["youtube"]
    STATE.recompute_all_effective()
    assert is_managed(d)                             # network rule forces MITM
    assert policy.decide(IP, NET, "a.googlevideo.com", _lk(d))[0] == policy.DROP
    assert policy.decide(IP, NET, "example.com", _lk(d))[0] == policy.FORWARD   # not a cut
    assert policy.decide(IP, NET, None, _lk(d))[0] == policy.FORWARD


def test_H_union_device_and_network():
    d = _mk(IP, mode="allow", services=["netflix"])
    STATE.net_services = ["youtube"]
    STATE.net_domains = ["ads.example"]
    STATE.recompute_all_effective()
    assert policy.decide(IP, NET, "x.nflxvideo.net", _lk(d))[0] == policy.DROP   # device service
    assert policy.decide(IP, NET, "x.googlevideo.com", _lk(d))[0] == policy.DROP # network service
    assert policy.decide(IP, NET, "ads.example", _lk(d))[0] == policy.DROP       # network domain
    assert policy.decide(IP, NET, "ok.com", _lk(d))[0] == policy.FORWARD


def test_F_clearing_network_unmanages_allow_devices():
    d = _mk(IP, mode="allow")
    STATE.net_services = ["youtube"]
    STATE.recompute_all_effective()
    assert is_managed(d)
    STATE.net_services = []
    STATE.recompute_all_effective()
    assert not is_managed(d)                         # back to unmanaged (ARP restored by spoofer)
    assert policy.decide(IP, NET, None, _lk(d))[0] == policy.PASS


def test_H_network_block_plus_device_cut_still_cuts():
    d = _mk(IP, mode="cut")
    STATE.net_services = ["youtube"]
    STATE.recompute_all_effective()
    assert policy.decide(IP, NET, "example.com", _lk(d))[0] == policy.DROP   # cut drops all
    assert policy.decide(IP, NET, None, _lk(d))[0] == policy.DROP


# ===================================================================== I–M (bulk)
def _iface():
    return netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")


def test_JKL_bulk_apply_all_succeed(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")         # reconcile no-ops (no NIC)
    _mk("192.168.9.10", "de:ad:00:00:00:01", is_gateway=False)
    _mk("192.168.9.11", "de:ad:00:00:00:02")
    for mode in ("cut", "limit", "allow"):
        r = server.api_bulk_rule(server.BulkRuleReq(
            ips=["192.168.9.10", "192.168.9.11"], mode=mode, down_kbps=1024, up_kbps=512))
        assert r["ok"] is True and r["applied"] == 2 and r["failed"] == 0
        assert STATE.get("192.168.9.10").mode == mode
        assert STATE.get("192.168.9.11").mode == mode


def test_M_bulk_partial_failure_is_reported(monkeypatch):
    """Never report success when some devices failed. Mixes a real device, a
    self device, a gateway, and a vanished IP."""
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    _mk("192.168.9.10", "de:ad:00:00:00:01")
    _mk("192.168.9.99", "de:ad:00:00:00:aa", is_self=True)
    _mk("192.168.9.1", "de:ad:00:00:00:bb", is_gateway=True)
    r = server.api_bulk_rule(server.BulkRuleReq(
        ips=["192.168.9.10", "192.168.9.99", "192.168.9.1", "192.168.9.250"], mode="cut"))
    assert r["ok"] is False                           # not all succeeded
    assert r["applied"] == 1 and r["failed"] == 3
    by_ip = {x["ip"]: x for x in r["results"]}
    assert by_ip["192.168.9.10"]["ok"] is True
    assert by_ip["192.168.9.99"]["ok"] is False       # self
    assert by_ip["192.168.9.1"]["ok"] is False        # gateway
    assert by_ip["192.168.9.250"]["ok"] is False      # vanished
    assert STATE.get("192.168.9.10").mode == "cut"
    assert STATE.get("192.168.9.99").mode == "allow"  # self untouched


def test_S_cut_all_except_me_still_works(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    _mk("192.168.9.10", "de:ad:00:00:00:01")
    _mk("192.168.9.11", "de:ad:00:00:00:02")
    _mk("192.168.9.99", "de:ad:00:00:00:aa", is_self=True)
    _mk("192.168.9.1", "de:ad:00:00:00:bb", is_gateway=True)
    server.api_cut_all_except_me()
    assert STATE.get("192.168.9.10").mode == "cut"
    assert STATE.get("192.168.9.11").mode == "cut"
    assert STATE.get("192.168.9.99").mode == "allow"  # self not cut
    assert STATE.get("192.168.9.1").mode == "allow"   # gateway not cut


# ===================================================================== network API
def test_network_block_endpoint_sets_and_clears(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    d = _mk(IP, mode="allow")
    r = server.api_network_block(server.NetworkRuleReq(services=["youtube", "bogus"], domains=["ads.x"]))
    assert r["ok"] is True
    assert STATE.net_services == ["youtube"]          # bogus id filtered out
    assert STATE.net_domains == ["ads.x"]
    assert is_managed(d) and "googlevideo.com" in d.eff_blocked
    # clear
    server.api_network_block(server.NetworkRuleReq(services=[], domains=[]))
    assert STATE.net_services == [] and STATE.net_domains == []
    assert not is_managed(d)


def test_services_block_endpoint(monkeypatch):
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    d = _mk(IP, mode="allow")
    r = server.api_services_block(server.ServiceBlockReq(ip=IP, services=["netflix", "nope"]))
    assert r["ok"] is True and r["services"] == ["netflix"]
    assert "nflxvideo.net" in d.eff_blocked
    assert r["signals"]["netflix"]["identified"] is True


# ===================================================================== O/P/Q health
def test_OPQ_policy_summary(monkeypatch):
    assert server._policy_summary()["enforcing"] is False
    _mk("192.168.9.10", "a", mode="limit", down_kbps=1000)
    _mk("192.168.9.11", "b", mode="cut")
    _mk("192.168.9.12", "c", mode="allow")
    STATE.enforcing = True
    s = server._policy_summary()
    assert s["limited"] == 1 and s["cut"] == 1 and s["managed"] == 2
    assert s["enforcing"] is True and s["network"] is False
    STATE.net_services = ["youtube"]
    assert server._policy_summary()["network"] is True


# ===================================================================== scoped QUIC / signals
def test_block_signals_never_overclaims():
    yt = block_signals("youtube")     # QUIC-heavy
    assert yt["dns"] and yt["tls"] and yt["http"] and yt["quic"] == "best_effort"
    nf = block_signals("netflix")     # not QUIC
    assert nf["quic"] == "not_applicable"
    assert block_signals("does-not-exist")["identified"] is False


class _FakeInj:
    def __init__(self):
        self.sent = []

    def send(self, b):
        self.sent.append(b)

    def close(self):
        pass


def _fwd():
    STATE.interface = _iface()
    f = Forwarder()
    f._inj = _FakeInj()
    f._my_mac_b = f._mac_to_bytes(STATE.interface.mac)
    SPOOFER._gateway_mac = "aa:bb:cc:dd:ee:ff"        # so forward path has a next hop
    return f


def _dns_response(dev_ip, name, ip):
    from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
    p = (Ether(src="aa:bb:cc:dd:ee:ff", dst="02:00:00:00:00:aa") /
         IP(src="8.8.8.8", dst=dev_ip) / UDP(sport=53, dport=40000) /
         DNS(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=ip)))
    return npcap._Frame(bytes(p))


def _udp443(dev_ip, dev_mac, dst_ip):
    from scapy.all import Ether, IP, UDP, Raw
    p = (Ether(src=dev_mac, dst="02:00:00:00:00:aa") /
         IP(src=dev_ip, dst=dst_ip) / UDP(sport=50000, dport=443) / Raw(load=b"\x00" * 40))
    return npcap._Frame(bytes(p))


def test_quic_scoped_drop_via_dns_pin():
    """DNS answer for a blocked service pins its IP; QUIC (UDP/443) to THAT ip is
    dropped, but QUIC to an unrelated ip is forwarded (no broad IP blocking)."""
    f = _fwd()
    dev = _mk("192.168.9.50", "de:ad:be:ef:00:01", mode="allow", services=["youtube"])
    # 1) feed a DNS A answer youtube.com -> 3.3.3.3  => it gets pinned
    f._handle(_dns_response("192.168.9.50", "youtube.com", "3.3.3.3"))
    assert "3.3.3.3" in dev.blocked_ips
    # 2) QUIC to the pinned IP -> dropped (injector not called for it)
    before = len(f._inj.sent)
    f._handle(_udp443("192.168.9.50", "de:ad:be:ef:00:01", "3.3.3.3"))
    assert len(f._inj.sent) == before, "QUIC to a pinned blocked IP must be dropped"
    # 3) QUIC to an UNRELATED IP -> forwarded (scoped, not broad IP blocking)
    f._handle(_udp443("192.168.9.50", "de:ad:be:ef:00:01", "9.9.9.9"))
    assert len(f._inj.sent) == before + 1, "QUIC to an unrelated IP must NOT be blocked"


def test_forwarder_blocks_service_by_sni_and_dns_query():
    """Deterministic signals: a TLS ClientHello (SNI) and a DNS query for a
    blocked service are dropped inline through the real forwarder path."""
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw
    f = _fwd()
    _mk("192.168.9.50", "de:ad:be:ef:00:01", mode="allow", services=["youtube"])

    # minimal TLS ClientHello with SNI = rr1.googlevideo.com
    host = b"rr1.googlevideo.com"
    ext = b"\x00\x00" + (len(host) + 5).to_bytes(2, "big") + (len(host) + 3).to_bytes(2, "big") + \
          b"\x00" + len(host).to_bytes(2, "big") + host
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x00" + b"\x01\x00" + \
           len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    tls = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    sni_pkt = (Ether(src="de:ad:be:ef:00:01", dst="02:00:00:00:00:aa") /
               IP(src="192.168.9.50", dst=NET) / TCP(sport=44000, dport=443, flags="PA") / Raw(load=tls))
    before = len(f._inj.sent)
    f._handle(npcap._Frame(bytes(sni_pkt)))
    assert len(f._inj.sent) == before, "SNI to a blocked service must be dropped"

    # DNS query for youtube.com -> dropped
    q = (Ether(src="de:ad:be:ef:00:01", dst="02:00:00:00:00:aa") /
         IP(src="192.168.9.50", dst="8.8.8.8") / UDP(sport=5353, dport=53) /
         DNS(rd=1, qd=DNSQR(qname="youtube.com")))
    before = len(f._inj.sent)
    f._handle(npcap._Frame(bytes(q)))
    assert len(f._inj.sent) == before, "DNS query for a blocked service must be dropped"

    # a NON-blocked SNI is forwarded (not a cut)
    host2 = b"example.com"
    ext2 = b"\x00\x00" + (len(host2) + 5).to_bytes(2, "big") + (len(host2) + 3).to_bytes(2, "big") + \
           b"\x00" + len(host2).to_bytes(2, "big") + host2
    body2 = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x00" + b"\x01\x00" + \
            len(ext2).to_bytes(2, "big") + ext2
    hs2 = b"\x01" + len(body2).to_bytes(3, "big") + body2
    tls2 = b"\x16\x03\x01" + len(hs2).to_bytes(2, "big") + hs2
    ok_pkt = (Ether(src="de:ad:be:ef:00:01", dst="02:00:00:00:00:aa") /
              IP(src="192.168.9.50", dst=NET) / TCP(sport=44002, dport=443, flags="PA") / Raw(load=tls2))
    before = len(f._inj.sent)
    f._handle(npcap._Frame(bytes(ok_pkt)))
    assert len(f._inj.sent) == before + 1, "non-blocked TLS must be forwarded"


# ===================================================================== U native
def test_U_native_backend_only():
    from backend.engine import iobackend
    assert iobackend.active_backend() == "native"


# ============================================================ F1 async reconcile
# api_rule / api_monitor / api_bulk_rule mutate + persist the rule, then hand the
# (up to ~6 s, blocking gateway-ARP) engine start to _reconcile_async so it runs
# OFF the request thread. These lock in: (a) the caller returns without waiting on
# the engine, (b) an engine failure surfaces as an `enforce_error` event (never a
# fake success / 500), and (c) demo/test mode stays synchronous for determinism.

def _wait_event(kind, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if any(e["kind"] == kind for e in STATE.events):
            return True
        time.sleep(0.01)
    return False


def test_F1_reconcile_async_runs_off_request_thread(monkeypatch):
    monkeypatch.delenv("SHARKNET_DEMO", raising=False)   # exercise the real (threaded) path
    STATE.events.clear()
    started, release, done = threading.Event(), threading.Event(), threading.Event()

    def slow_reconcile():
        started.set()
        release.wait(2.0)            # simulate the blocking gateway-ARP resolve
        done.set()
        return None
    monkeypatch.setattr(server, "reconcile", slow_reconcile)

    t0 = time.time()
    server._reconcile_async()
    assert time.time() - t0 < 0.5, "caller must not block on the (slow) engine start"
    assert started.wait(1.0), "reconcile must actually run on a background thread"
    release.set()
    assert done.wait(1.0)           # let the worker finish before teardown reverts the patch


def test_F1_engine_failure_becomes_event_not_fake_success(monkeypatch):
    monkeypatch.delenv("SHARKNET_DEMO", raising=False)
    STATE.events.clear()
    monkeypatch.setattr(server, "reconcile", lambda: "no Npcap")
    server._reconcile_async()
    assert _wait_event("enforce_error"), "engine start failure must surface as an event"
    msg = next(e.get("message") for e in STATE.events if e["kind"] == "enforce_error")
    assert "Npcap" in msg


def test_F1_api_rule_persists_then_reconciles_off_thread(monkeypatch):
    # A cut is applied + persisted and the response is honest ("rule stored") even
    # when the engine cannot start; the failure is an event, not a 500 / fake ok.
    monkeypatch.delenv("SHARKNET_DEMO", raising=False)
    STATE.events.clear()
    saved = {}
    monkeypatch.setattr(server.db, "save_rule",
                        lambda mac, mode, d, u: saved.update(mac=mac, mode=mode))
    monkeypatch.setattr(server, "reconcile", lambda: "engine down")
    _mk(IP, mac="bb:bb")

    r = server.api_rule(server.RuleReq(ip=IP, mode="cut"))
    assert r["ok"] is True and r["device"]["mode"] == "cut"   # honest: rule stored
    assert saved.get("mode") == "cut"                          # persisted
    assert STATE.get(IP).mode == "cut"                         # applied to STATE
    assert _wait_event("enforce_error")                        # engine failure surfaced


def test_F1_demo_mode_reconcile_is_synchronous(monkeypatch):
    # tests/demo: _reconcile_async stays inline (no thread) so tests are deterministic.
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    calls = []
    monkeypatch.setattr(server, "reconcile", lambda: calls.append(1))
    server._reconcile_async()
    assert calls == [1], "demo/test mode must run reconcile synchronously (no thread)"


def test_F1_reconcile_serialized_no_double_start(monkeypatch):
    # Two overlapping reconciles (the F1 daemon-thread path) must start the engine
    # ONCE: _reconcile_lock serializes the decision+transition, so the second caller
    # observes enforcing=True (set at the end of the first SPOOFER.start) and skips.
    # Without the lock both pass the non-atomic `not enforcing` guard and double-start.
    monkeypatch.delenv("SHARKNET_DEMO", raising=False)
    STATE.enforcing = False
    _mk(IP, mac="cc:cc", mode="cut")                 # one managed (=intercepted) device
    starts = []

    def fake_start():
        starts.append(1)
        time.sleep(0.15)          # widen the window a lock must close
        STATE.enforcing = True    # real SPOOFER.start sets this only after the resolve
    monkeypatch.setattr(server.SPOOFER, "start", fake_start)
    monkeypatch.setattr(server.SPOOFER, "stop", lambda: None)
    monkeypatch.setattr(server.FORWARDER, "start", lambda: None)
    monkeypatch.setattr(server.FORWARDER, "stop", lambda: None)
    monkeypatch.setattr(server, "get_monitor",
                        lambda: type("M", (), {"start": staticmethod(lambda: None)})())

    threads = [threading.Thread(target=server.reconcile) for _ in range(2)]
    for t in threads: t.start()
    for t in threads: t.join(2.0)

    assert starts == [1], f"engine must start exactly once, got {len(starts)}"
    assert STATE.enforcing is True
    STATE.enforcing = False
