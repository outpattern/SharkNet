"""
F3 immediate enforcement + global-rule lifecycle + health semantics + duplicate-
handler + online-update hardening + stress/soak (Phase 7 hardening pass).

Pure logic + the real Forwarder path with crafted frames; no admin/NIC/sockets.
"""
import logging
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.state import STATE, Device, is_managed                    # noqa: E402
from backend.engine import policy, netinfo, npcap                      # noqa: E402
from backend.engine.forwarder import Forwarder                         # noqa: E402
from backend.engine.spoofer import SPOOFER                             # noqa: E402
from backend.engine import services_update as su                       # noqa: E402
from backend.engine.health import Health                               # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    def clean():
        STATE.devices.clear(); STATE.net_services = []; STATE.net_domains = []
        STATE.enforcing = False; STATE.controlling = False; STATE.interface = None
    clean(); yield; clean()


# ---------------- helpers: real Forwarder path with crafted frames ----------------
class _FakeInj:
    def __init__(self): self.sent = []
    def send(self, b): self.sent.append(b)
    def close(self): pass


def _iface():
    return netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")


def _fwd():
    STATE.interface = _iface()
    f = Forwarder()
    f._inj = _FakeInj()
    f._my_mac_b = f._mac_to_bytes(STATE.interface.mac)
    SPOOFER._gateway_mac = "aa:bb:cc:dd:ee:ff"
    return f


def _mk(ip="192.168.9.50", mac="de:ad:be:ef:00:01", **kw):
    d = Device(ip=ip, mac=mac, **kw)
    STATE.devices[ip] = d
    STATE.recompute_effective(d)
    return d


def _dns_ans(dev_ip, name, ips):
    from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
    ans = [DNSRR(rrname=name, type="A", rdata=ipx) for ipx in ips]   # list form (modern scapy)
    p = (Ether(src="aa:bb:cc:dd:ee:ff", dst="02:00:00:00:00:aa") /
         IP(src="8.8.8.8", dst=dev_ip) / UDP(sport=53, dport=40000) /
         DNS(qr=1, qd=DNSQR(qname=name), ancount=len(ans), an=ans))
    return npcap._Frame(bytes(p))


def _tcp_to(dev_ip, dev_mac, dst_ip, dport=443):
    from scapy.all import Ether, IP, TCP, Raw
    p = (Ether(src=dev_mac, dst="02:00:00:00:00:aa") /
         IP(src=dev_ip, dst=dst_ip) / TCP(sport=51000, dport=dport, flags="A") / Raw(load=b"x" * 20))
    return npcap._Frame(bytes(p))


def _udp443(dev_ip, dev_mac, dst_ip):
    from scapy.all import Ether, IP, UDP, Raw
    p = (Ether(src=dev_mac, dst="02:00:00:00:00:aa") /
         IP(src=dev_ip, dst=dst_ip) / UDP(sport=50000, dport=443) / Raw(load=b"\x00" * 40))
    return npcap._Frame(bytes(p))


# ===================================================================== F3
def test_f3_retroactive_pin_enforces_existing_connections():
    """A device that resolved a domain WHILE managed (limit), then the domain is
    blocked -> its already-resolved IPs are pinned immediately (retroactive) and an
    EXISTING TCP connection to that IP is dropped at once (not only future DNS)."""
    f = _fwd()
    dev = _mk(mode="limit", down_kbps=1000)                 # managed, not blocked yet
    # device resolves youtube.com -> 3.3.3.3 while only limited (recorded, not pinned)
    f._handle(_dns_ans("192.168.9.50", "youtube.com", ["3.3.3.3"]))
    assert "youtube.com" in dev.recent_dns and "3.3.3.3" not in dev.blocked_ips
    # now block youtube (service) + retroactive pin (what the API does)
    dev.services = ["youtube"]; STATE.recompute_effective(dev)
    assert f.pin_recent(dev) >= 1
    assert "3.3.3.3" in dev.blocked_ips
    # an EXISTING TCP connection to the pinned IP is now dropped
    before = len(f._inj.sent)
    f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "3.3.3.3"))
    assert len(f._inj.sent) == before, "existing connection to a blocked IP must drop"
    # traffic to an UNRELATED ip still forwards (scoped, no broad blocking)
    f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "9.9.9.9"))
    assert len(f._inj.sent) == before + 1


def test_f3_proactive_new_dns_and_quic():
    f = _fwd()
    dev = _mk(mode="allow", services=["netflix"])           # blocked
    f._handle(_dns_ans("192.168.9.50", "nflxvideo.net", ["5.5.5.5", "6.6.6.6"]))
    assert "5.5.5.5" in dev.blocked_ips and "6.6.6.6" in dev.blocked_ips   # multiple IPs
    before = len(f._inj.sent)
    f._handle(_udp443("192.168.9.50", "de:ad:be:ef:00:01", "5.5.5.5"))     # QUIC -> pinned
    assert len(f._inj.sent) == before                                       # dropped
    f._handle(_udp443("192.168.9.50", "de:ad:be:ef:00:01", "7.7.7.7"))     # QUIC -> unpinned
    assert len(f._inj.sent) == before + 1                                   # forwarded


def test_f3_unblock_removes_pins():
    f = _fwd()
    dev = _mk(mode="allow", services=["youtube"])
    f._handle(_dns_ans("192.168.9.50", "googlevideo.com", ["3.3.3.3"]))
    assert "3.3.3.3" in dev.blocked_ips
    dev.services = []; STATE.recompute_effective(dev)       # UNBLOCK
    f.pin_recent(dev)
    assert "3.3.3.3" not in dev.blocked_ips, "unblock must remove the stale pin (item 7)"


def test_f3_dns_freshness_expiry():
    f = _fwd()
    dev = _mk(mode="allow", services=["youtube"])
    dev.recent_dns["googlevideo.com"] = [{"3.3.3.3"}, time.time() - 1]      # already expired
    assert f.pin_recent(dev) == 0 and "3.3.3.3" not in dev.blocked_ips


def test_f3_pin_cap_bounded():
    f = _fwd()
    dev = _mk(mode="allow", services=["youtube"])
    now = time.time()
    for i in range(400):
        dev.blocked_ips["10.0.%d.%d" % (i // 256, i % 256)] = now + 600
    f._bound_pins(dev)
    assert len(dev.blocked_ips) <= f._PIN_CAP


# ===================================================================== global rules
def test_network_rule_applies_to_NEW_device_via_upsert():
    """A device discovered AFTER a network rule (e.g. by the passive Defender
    sniffer, via upsert_device) inherits the effective network policy — is_managed
    and eff_blocked are correct without any manual per-device block (item 2)."""
    STATE.net_services = ["youtube"]
    dev = STATE.upsert_device("192.168.9.77", "de:ad:be:ef:00:07")   # brand-new device
    assert is_managed(dev), "new device must inherit the network rule"
    assert "googlevideo.com" in dev.eff_blocked, "new device eff_blocked must include network service"
    lk = STATE.devices.get
    assert policy.decide("192.168.9.77", "1.2.3.4", "a.googlevideo.com", lk)[0] == policy.DROP


def test_network_rule_survives_reconnect_and_ip_change():
    STATE.net_domains = ["ads.example"]
    d1 = STATE.upsert_device("192.168.9.80", "de:ad:be:ef:00:08")
    assert is_managed(d1)
    del STATE.devices["192.168.9.80"]                                # disappears
    d2 = STATE.upsert_device("192.168.9.90", "de:ad:be:ef:00:08")    # reconnects at a NEW ip
    assert is_managed(d2) and "ads.example" in d2.eff_blocked


def test_network_precedence_device_allow_cannot_override():
    STATE.net_services = ["youtube"]
    d = STATE.upsert_device("192.168.9.50", "aa", mode="allow")      # device is ALLOW
    STATE.recompute_effective(d)
    lk = STATE.devices.get
    assert policy.decide("192.168.9.50", "1.2.3.4", "x.googlevideo.com", lk)[0] == policy.DROP
    assert policy.decide("192.168.9.50", "1.2.3.4", "ok.com", lk)[0] == policy.FORWARD  # not a cut


# ===================================================================== health
def test_health_policy_influenced_not_poor():
    h = Health()
    h.data.update({"internet_online": True, "gateway_online": True, "dns_online": True,
                   "latency_ms": 300, "packet_loss": 12})            # would be "poor"
    STATE.enforcing = True
    assert h._grade() == "good" and h.data["policy_influenced"] is True


def test_health_genuine_degradation_still_poor():
    h = Health()
    h.data.update({"internet_online": True, "gateway_online": True, "dns_online": True,
                   "latency_ms": 300, "packet_loss": 12})
    STATE.enforcing = False                                          # not our policy
    assert h._grade() == "poor" and h.data["policy_influenced"] is False


def test_health_offline_never_masked():
    h = Health()
    h.data.update({"internet_online": False, "latency_ms": None})
    STATE.enforcing = True
    assert h._grade() == "offline"


# ===================================================================== duplicate handler (item 19)
def test_no_duplicate_log_handlers(monkeypatch):
    monkeypatch.setenv("SHARKNET_BLOCK_DEBUG", "1")
    log = logging.getLogger("sharknet.engine")
    before = list(log.handlers)
    f1 = Forwarder(); f1.refresh_debug()
    f2 = Forwarder(); f2.refresh_debug()                             # a 2nd instance must NOT add a 2nd handler
    from backend.engine.forwarder import _log_file_path
    path = os.path.abspath(_log_file_path())
    fhs = [h for h in log.handlers if isinstance(h, logging.FileHandler)
           and os.path.abspath(getattr(h, "baseFilename", "")) == path]
    assert len(fhs) <= 1, "duplicate FileHandler -> duplicate BLOCK-DEBUG lines"
    for h in log.handlers:
        if h not in before:
            log.removeHandler(h)


# ===================================================================== online-update hardening (item 21)
def test_apply_update_rejects_unsigned_and_old(tmp_path):
    cache = str(tmp_path / "services_cache.json")
    feed = {"schema_version": 1, "version": 5,
            "services": [{"id": "x", "name": "X", "domains": ["x-service.com"]}]}
    # signature required + no pinned key -> refused
    r = su.apply_update(feed, cache_path=cache, local_version=0, require_signature=True)
    assert r["applied"] is False and "signature" in r["reason"]
    # version gate
    r = su.apply_update(feed, cache_path=cache, local_version=9, require_signature=False)
    assert r["applied"] is False and r["reason"] == "not newer"


def test_apply_update_atomic_with_backup(tmp_path):
    import json
    cache = str(tmp_path / "services_cache.json")
    with open(cache, "w") as fh:
        json.dump({"schema_version": 1, "version": 1, "services": []}, fh)
    feed = {"schema_version": 1, "version": 2, "services": [
        {"id": "good", "name": "Good", "domains": ["good-svc.com", "cloudfront.net"]}]}
    r = su.apply_update(feed, cache_path=cache, local_version=1, require_signature=False)
    assert r["applied"] is True and r["version"] == 2
    assert os.path.exists(cache + ".bak")                           # rollback backup
    saved = json.load(open(cache))
    assert saved["services"][0]["domains"] == ["good-svc.com"]      # unsafe cloudfront stripped


def test_malformed_feed_never_crashes():
    for bad in [None, {}, {"services": "nope"}, {"schema_version": 99, "services": []},
                {"version": 1, "services": [{"id": "!!", "name": ""}]}]:
        r = su.apply_update(bad if isinstance(bad, dict) else {}, cache_path="/nonexistent/x.json",
                            local_version=0, require_signature=False)
        assert r["applied"] is False   # never raises, never applies


# ===================================================================== stress / soak (item 18)
def test_stress_block_unblock_no_state_growth():
    f = _fwd()
    dev = _mk(mode="allow")
    # seed a bounded recent_dns
    f._handle(_dns_ans("192.168.9.50", "googlevideo.com", ["3.3.3.3", "4.4.4.4"]))
    for i in range(500):
        dev.services = ["youtube"] if i % 2 == 0 else []
        STATE.recompute_effective(dev)
        f.pin_recent(dev)
    # after the final UNBLOCK, no pins survive; caches bounded
    assert dev.services == [] and dev.blocked_ips == {}
    assert len(dev.recent_dns) <= f._DNS_CAP


def test_stress_device_churn_no_leak():
    STATE.net_services = ["youtube"]
    for i in range(500):
        ip = "192.168.9.%d" % (10 + (i % 50))
        d = STATE.upsert_device(ip, "de:ad:00:00:%02x:%02x" % (i % 256, (i // 256) % 256))
        assert is_managed(d)
        if i % 3 == 0:
            STATE.devices.pop(ip, None)                             # churn
    assert len(STATE.devices) <= 50                                 # bounded by the ip space used


def test_stress_forwarder_flood_stable():
    f = _fwd()
    _mk(mode="allow", services=["youtube"])
    sent = 0
    for i in range(2000):
        f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "9.9.9.9", dport=80))
        sent += 1
    # every non-blocked packet forwarded; no exception, counters coherent
    assert f.counters["192.168.9.50"]["up"] > 0


# ===================================================================== P0/P1: Monitor
from backend.state import is_intercepted    # noqa: E402


def test_monitor_allow_device_is_forwarded_at_packet_level():
    """P1: an ALLOW+MONITOR device is intercepted and its packet FORWARDED
    (re-injected), never dropped — enforcement decision is FORWARD."""
    f = _fwd(); STATE.enforcing = True
    d = _mk(monitor=True)                                   # ALLOW + MONITOR
    assert is_intercepted(d) and not is_managed(d)
    before = len(f._inj.sent)
    f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "3.3.3.3", dport=443))
    assert len(f._inj.sent) == before + 1                  # forwarded, not dropped
    assert f.counters["192.168.9.50"]["up"] > 0            # observed/accounted


def test_allow_off_device_is_not_intercepted_at_packet_level():
    """P0: an ALLOW device with observation OFF is not selected, so even a frame
    that reaches us is left untouched (not forwarded/dropped by us)."""
    f = _fwd(); STATE.enforcing = True
    _mk()                                                   # allow, monitor off
    before = len(f._inj.sent)
    f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "3.3.3.3", dport=443))
    assert len(f._inj.sent) == before                      # never touched


def test_cut_still_drops_even_with_monitor():
    """CASE 5: CUT keeps dropping; Monitor never resurrects a cut device's traffic
    (and the forwarder still early-returns -> nothing observed)."""
    f = _fwd(); STATE.enforcing = True
    _mk(mode="cut", monitor=True)
    before = len(f._inj.sent)
    f._handle(_tcp_to("192.168.9.50", "de:ad:be:ef:00:01", "3.3.3.3", dport=443))
    assert len(f._inj.sent) == before                      # dropped (no forward)
