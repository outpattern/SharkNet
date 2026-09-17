"""
SharkNet core unit tests — pure-logic coverage (no network / no admin needed).
Run:  python -m pytest tests/ -q
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine import domains, vendors, host_resolver          # noqa: E402
from backend.engine.forwarder import _Bucket                        # noqa: E402


# ---------- domain blocking ----------
def test_is_blocked_exact_and_subdomain():
    assert domains.is_blocked("youtube.com", ["youtube.com"])
    assert domains.is_blocked("m.youtube.com", ["youtube.com"])
    assert domains.is_blocked("r1---sn.googlevideo.com", ["googlevideo.com"])
    assert not domains.is_blocked("notyoutube.com", ["youtube.com"])
    assert not domains.is_blocked("youtube.com.evil.com", ["youtube.com"])
    assert not domains.is_blocked("example.com", [])


def test_norm():
    assert domains._norm("WWW.Example.COM.") == "example.com"
    assert domains._norm("YouTube.com") == "youtube.com"
    assert domains._norm("nodot") is None
    assert domains._norm("") is None


def test_presets_are_sane():
    assert "YouTube" in domains.PRESETS
    assert "Shahid" in domains.PRESETS
    for name, doms in domains.PRESETS.items():
        assert doms and all("." in d for d in doms)


# ---------- domain parsing ----------
def test_parse_dns_query():
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR
    pkt = IP() / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname="tiktok.com"))
    res = domains.parse_domain(pkt)
    assert res == ("tiktok.com", "dns")


def test_parse_http_host():
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    pkt = IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
    res = domains.parse_domain(pkt)
    assert res and res[0] == "example.org" and res[1] == "http"


def test_parse_none_for_plain():
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    pkt = IP() / TCP(dport=12345) / Raw(load=b"random bytes")
    assert domains.parse_domain(pkt) is None


# ---------- token bucket (rate limiter) ----------
def test_bucket_unlimited():
    b = _Bucket(0)
    assert all(b.allow(1500) for _ in range(1000))


def test_bucket_limits_rate():
    rate = 100_000  # 100 KB/s
    b = _Bucket(rate)
    b.tokens = 0            # start empty (ignore burst)
    b.ts = time.time()
    allowed = 0
    t0 = time.time()
    while time.time() - t0 < 1.0:
        if b.allow(1000):
            allowed += 1000
        time.sleep(0.0005)
    # ~1 second at 100 KB/s -> should allow roughly the rate, never far above
    assert allowed <= rate * 1.5
    assert allowed > 0


# ---------- randomized MAC detection ----------
def test_is_randomized():
    assert vendors.is_randomized("02:11:22:33:44:55")   # locally administered
    assert vendors.is_randomized("a2:87:d9:e0:90:b7")
    assert vendors.is_randomized("6e:aa:bb:cc:dd:ee")
    assert not vendors.is_randomized("f0:db:f8:11:22:33")  # real OUI
    assert not vendors.is_randomized("04:d9:f5:08:0c:32")


# ---------- friendly name ----------
def test_friendly_name():
    assert host_resolver.friendly_name("Apple Inc.", "Ahmeds-iPhone", "phone") == "Ahmeds-iPhone"
    assert host_resolver.friendly_name("Samsung Electronics", "", "phone") == "Samsung Phone"
    assert host_resolver.friendly_name("", "", "unknown") == ""
