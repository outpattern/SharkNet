"""
SharkNet v2.9 unit tests — name intelligence, history ring, domain observation.
Pure logic: no network, no admin, no sockets.  Run:  python -m pytest tests/ -q
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================
# F1 — Device Name Intelligence (priority/confidence resolver)
# ============================================================
from backend.engine.nameresolver import NameResolver, PRIORITY   # noqa: E402


def test_priority_higher_source_wins_regardless_of_order():
    r = NameResolver()
    # weak source first, then strong -> strong wins
    r.submit("aa:bb", "rdns", "router-assigned-1234")
    assert r.best("aa:bb") == "router-assigned-1234"
    r.submit("aa:bb", "dhcp", "Johns-Laptop")
    assert r.best("aa:bb") == "Johns-Laptop"
    assert r.source_of("aa:bb") == "dhcp"


def test_lower_source_never_downgrades_a_stronger_name():
    r = NameResolver()
    r.submit("aa:bb", "dhcp", "Johns-Laptop")
    # a later, weaker rDNS/NetBIOS must NOT overwrite the DHCP name (no flapping)
    assert r.submit("aa:bb", "rdns", "generic-ptr") is False
    assert r.submit("aa:bb", "netbios", "WORKGROUP-PC") is False
    assert r.best("aa:bb") == "Johns-Laptop"


def test_mdns_beats_netbios_and_rdns_but_loses_to_dhcp():
    r = NameResolver()
    r.submit("mac", "rdns", "ptr-name")
    r.submit("mac", "netbios", "NBNAME")
    r.submit("mac", "mdns", "Living-Room-TV")
    assert r.best("mac") == "Living-Room-TV"
    r.submit("mac", "dhcp", "AndroidPhone")
    assert r.best("mac") == "AndroidPhone"


def test_saved_survives_weak_rdns_but_yields_to_fresh_dhcp():
    r = NameResolver()
    r.submit("m", "saved", "My-Old-Name")
    assert r.submit("m", "rdns", "weak") is False          # saved outranks rdns
    assert r.best("m") == "My-Old-Name"
    assert r.submit("m", "dhcp", "Fresh-DHCP") is True      # dhcp outranks saved
    assert r.best("m") == "Fresh-DHCP"


def test_same_source_updates_in_place():
    r = NameResolver()
    r.submit("m", "dhcp", "name-one")
    r.submit("m", "dhcp", "name-two")     # device changed its DHCP hostname
    assert r.best("m") == "name-two"
    assert r.source_of("m") == "dhcp"


def test_cleaning_strips_local_suffix_and_rejects_junk():
    r = NameResolver()
    r.submit("m", "mdns", "Ahmeds-iPhone.local")
    assert r.best("m") == "Ahmeds-iPhone"
    assert r.submit("m2", "dhcp", "") is False     # empty rejected
    assert r.submit("m2", "dhcp", "x") is False    # too short rejected
    assert r.best("m2") == ""


def test_mac_keying_is_case_insensitive_and_independent():
    r = NameResolver()
    r.submit("AA:BB:CC", "dhcp", "Device-A")
    r.submit("11:22:33", "dhcp", "Device-B")
    assert r.best("aa:bb:cc") == "Device-A"
    assert r.best("11:22:33") == "Device-B"


def test_confidence_and_none_mac_are_safe():
    r = NameResolver()
    assert r.best(None) == "" and r.source_of(None) == ""
    assert r.submit(None, "dhcp", "x") is False
    assert r.submit("m", "bogus-source", "x") is False   # unknown source rejected
    r.submit("m", "dhcp", "Name")
    assert 0.0 < r.confidence("m") <= 1.0


def test_priority_order_is_the_documented_one():
    assert PRIORITY["user"] < PRIORITY["dhcp"] < PRIORITY["mdns"] < PRIORITY["saved"]
    assert PRIORITY["saved"] < PRIORITY["netbios"] < PRIORITY["rdns"]


def test_device_carries_name_source_field():
    from backend.state import Device
    d = Device(ip="1.2.3.4", mac="aa", hostname="Foo", name_source="dhcp")
    dd = d.to_dict()
    assert dd["name_source"] == "dhcp"
    assert dd["label"] == "Foo"          # falls back to hostname when no user name


# ============================================================
# F2 — Traffic history ring buffer
# ============================================================
from backend.engine.history import TrafficHistory, WINDOW_SECONDS   # noqa: E402


def test_ring_add_and_get_returns_samples():
    h = TrafficHistory()
    now = time.time()
    for i in range(5):
        h.add("aa:bb", 1000 + i, 500 + i, ts=now - (4 - i))
    got = h.get("aa:bb", 600)
    assert len(got) == 5
    assert got[0]["down"] == 1000 and got[-1]["down"] == 1004
    assert all(set(s) == {"ts", "down", "up"} for s in got)


def test_ring_window_excludes_old_samples():
    h = TrafficHistory()
    now = time.time()
    h.add("m", 1, 1, ts=now - 5000)      # way outside the 10-min window
    h.add("m", 2, 2, ts=now - 10)        # inside
    got = h.get("m", 600)
    assert len(got) == 1 and got[0]["down"] == 2


def test_ring_empty_for_unknown_or_none():
    h = TrafficHistory()
    assert h.get("nope", 600) == []
    assert h.get(None, 600) == []
    h.add(None, 1, 1)                    # must not raise / must not store
    assert h.get(None) == []


def test_ring_is_bounded_per_device():
    h = TrafficHistory()
    now = time.time()
    for i in range(WINDOW_SECONDS + 500):
        h.add("m", i, i, ts=now - 0.001 * i + 0.0)   # all "recent"
    # deque(maxlen) keeps it bounded regardless of how many were pushed
    stored = h._rings["m"]
    assert len(stored) <= WINDOW_SECONDS + 20


def test_ring_get_clamps_seconds_to_window():
    h = TrafficHistory()
    now = time.time()
    h.add("m", 9, 9, ts=now - 100)
    # asking for more than the window must not raise and still returns recent data
    assert h.get("m", 999999)[0]["down"] == 9


def test_ring_forget_and_clear():
    h = TrafficHistory()
    h.add("m", 1, 1); h.add("n", 2, 2)
    h.forget("m")
    assert h.get("m") == [] and len(h.get("n")) == 1
    h.clear()
    assert h.get("n") == []


def test_api_history_endpoint_reads_ring():
    """The /api/history endpoint must serve the in-memory ring (not SQLite)."""
    from backend import server
    from backend.state import STATE, Device
    from backend.engine.history import HISTORY
    try:
        STATE.devices.clear()
        STATE.devices["10.9.9.9"] = Device(ip="10.9.9.9", mac="ab:cd", mode="limit")
        HISTORY.forget("ab:cd")
        HISTORY.add("ab:cd", 111, 222)
        res = server.api_history("10.9.9.9", 600)
        assert res["ok"] is True
        assert len(res["history"]) == 1 and res["history"][0]["down"] == 111
    finally:
        STATE.devices.clear()
        HISTORY.forget("ab:cd")


# ============================================================
# F3 — Async domain observation + LRU visited store
# ============================================================
from backend.engine import domains                         # noqa: E402
from backend.engine.domain_observer import DomainObserver, _MAX_QUEUE   # noqa: E402
from backend.state import Device                            # noqa: E402


def test_record_visit_dedups_and_timestamps():
    d = Device(ip="1.1.1.1", mac="aa")
    domains.record_visit(d, "youtube.com")
    domains.record_visit(d, "google.com")
    domains.record_visit(d, "youtube.com")     # seen again -> dedup, moves to end
    assert set(d.domains) == {"youtube.com", "google.com"}
    assert list(d.domains)[-1] == "youtube.com"   # most-recently-seen is last
    assert all(isinstance(t, float) for t in d.domains.values())


def test_record_visit_lru_evicts_oldest_only():
    d = Device(ip="1.1.1.1", mac="aa")
    for i in range(5):
        domains.record_visit(d, f"host{i}.com", cap=3)
    # LRU keeps the cap; only the single oldest is dropped each time (NOT clear-all)
    assert len(d.domains) == 3
    assert "host0.com" not in d.domains and "host1.com" not in d.domains
    assert set(d.domains) == {"host2.com", "host3.com", "host4.com"}


def test_record_visit_ignores_empty():
    d = Device(ip="1.1.1.1", mac="aa")
    domains.record_visit(d, "")
    assert d.domains == {}


def test_observer_queue_is_bounded_and_never_blocks():
    """observe() must never block; overflow increments a drop counter (we lose
    observations, never forwarding)."""
    obs = DomainObserver()             # not started -> queue fills up
    for _ in range(_MAX_QUEUE + 50):
        obs.observe(object(), object())    # must never raise/block
    assert obs.dropped >= 50


def test_observer_worker_parses_and_records():
    """End-to-end: enqueue a real HTTP-Host packet, worker records the domain."""
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    pkt = IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
    dev = Device(ip="2.2.2.2", mac="bb")
    obs = DomainObserver()
    obs.start()
    try:
        obs.observe(dev, pkt)
        deadline = time.time() + 3
        while "example.org" not in dev.domains and time.time() < deadline:
            time.sleep(0.02)
        assert "example.org" in dev.domains
    finally:
        obs.stop()


def test_observer_stop_is_safe_when_not_started():
    obs = DomainObserver()
    obs.stop()          # must not raise
    obs.start(); obs.start()   # idempotent
    obs.stop()


# ============================================================
# F4 — raw ARP build + manual IP parse (GOLDEN: byte-for-byte vs scapy)
# ============================================================
from backend.engine import rawpkt                          # noqa: E402


def test_build_arp_matches_scapy_byte_for_byte():
    from scapy.layers.l2 import Ether, ARP
    cases = [
        # (eth_dst, eth_src, op, sender_mac, sender_ip, target_mac, target_ip)
        ("f0:db:f8:11:22:33", "04:d9:f5:08:0c:32", 2,
         "04:d9:f5:08:0c:32", "192.168.1.1", "f0:db:f8:11:22:33", "192.168.1.50"),
        ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1,
         "11:22:33:44:55:66", "10.0.0.2", "aa:bb:cc:dd:ee:ff", "10.0.0.254"),
        ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:01", 2,
         "00:00:00:00:00:01", "172.16.5.5", "ff:ff:ff:ff:ff:ff", "172.16.5.1"),
    ]
    for (ed, es, op, sm, sip, tm, tip) in cases:
        mine = rawpkt.build_arp(ed, es, op, sm, sip, tm, tip)
        theirs = bytes(Ether(dst=ed, src=es) /
                       ARP(op=op, hwsrc=sm, psrc=sip, hwdst=tm, pdst=tip))
        assert mine == theirs, f"ARP mismatch for {sip}->{tip}: {mine.hex()} != {theirs.hex()}"
        assert len(mine) == 42


def test_parse_ipv4_matches_scapy_src_dst_proto():
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
    pkts = [
        Ether(dst="04:d9:f5:08:0c:32", src="f0:db:f8:11:22:33") /
        IP(src="192.168.1.50", dst="93.184.216.34") / TCP(dport=443) / Raw(load=b"x" * 20),
        Ether(dst="04:d9:f5:08:0c:32", src="f0:db:f8:11:22:33") /
        IP(src="10.0.0.9", dst="8.8.8.8") / UDP(dport=53) / Raw(load=b"q"),
        # IP options (IHL > 5) must not shift src/dst/proto
        Ether() / IP(src="1.2.3.4", dst="5.6.7.8", options=[b"\x00\x00\x00\x00"]) / TCP(),
    ]
    for p in pkts:
        frame = bytes(p)
        ipl = p.getlayer(IP)
        assert rawpkt.parse_ipv4(frame) == (ipl.src, ipl.dst, ipl.proto)


def test_parse_ipv4_rejects_non_ipv4_and_short():
    from scapy.layers.l2 import Ether, ARP
    arp_frame = bytes(Ether() / ARP())
    assert rawpkt.parse_ipv4(arp_frame) is None       # ethertype 0x0806, not IPv4
    assert rawpkt.parse_ipv4(b"\x00" * 20) is None    # too short
    assert rawpkt.parse_ipv4(b"") is None


def test_build_arp_rejects_bad_mac():
    import pytest
    with pytest.raises(ValueError):
        rawpkt.build_arp("zz", "aa:bb:cc:dd:ee:ff", 2,
                         "aa:bb:cc:dd:ee:ff", "1.1.1.1", "aa:bb:cc:dd:ee:ff", "1.1.1.2")


def test_spoofer_poison_bytes_match_scapy():
    """The raw poison/restore frames the spoofer now sends must be byte-identical
    to what the old scapy Ether()/ARP() built."""
    from scapy.layers.l2 import Ether, ARP
    my, gw_mac, tgt_mac = "02:00:00:00:00:aa", "aa:bb:cc:dd:ee:ff", "de:ad:be:ef:00:01"
    gw_ip, tgt_ip = "192.168.9.1", "192.168.9.50"
    # poison frame #1 (tell target: gateway is at my MAC)
    mine = rawpkt.build_arp(tgt_mac, my, 2, my, gw_ip, tgt_mac, tgt_ip)
    theirs = bytes(Ether(dst=tgt_mac, src=my) /
                   ARP(op=2, psrc=gw_ip, hwsrc=my, pdst=tgt_ip, hwdst=tgt_mac))
    assert mine == theirs
    # restore frame (tell target: gateway is really at gw_mac)
    mine2 = rawpkt.build_arp(tgt_mac, gw_mac, 2, gw_mac, gw_ip, tgt_mac, tgt_ip)
    theirs2 = bytes(Ether(dst=tgt_mac, src=gw_mac) /
                    ARP(op=2, psrc=gw_ip, hwsrc=gw_mac, pdst=tgt_ip, hwdst=tgt_mac))
    assert mine2 == theirs2


def test_forwarder_hot_path_parses_and_forwards_raw(monkeypatch):
    """Drive the real Forwarder._handle end-to-end with the new raw IP parse +
    raw L2-splice forward. Verifies traffic is still counted and forwarded with
    the L2 header correctly rewritten and the IP payload byte-for-byte intact."""
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    from backend.engine.forwarder import Forwarder
    from backend.engine.spoofer import SPOOFER
    from backend.engine import netinfo
    from backend.state import STATE, Device

    prev_iface, prev_gw = STATE.interface, SPOOFER._gateway_mac
    try:
        STATE.interface = netinfo.Interface(
            name="t", description="t", ip="192.168.9.2", mac="02:00:00:00:00:aa",
            netmask="255.255.255.0", gateway="192.168.9.1", cidr="192.168.9.0/24")
        STATE.devices.clear()
        tgt = Device(ip="192.168.9.50", mac="de:ad:be:ef:00:01",
                     mode="limit", down_kbps=0, up_kbps=0)   # 0 = unlimited -> forwards
        STATE.devices[tgt.ip] = tgt
        SPOOFER._gateway_mac = "aa:bb:cc:dd:ee:ff"

        fw = Forwarder()
        fw._my_mac_b = fw._mac_to_bytes("02:00:00:00:00:aa")
        sent = []
        fw._inj = type("S", (), {"send": lambda self, b: sent.append(b)})()

        # outbound frame from the managed device to the internet, dst L2 = us
        frame = bytes(Ether(dst="02:00:00:00:00:aa", src="de:ad:be:ef:00:01") /
                      IP(src="192.168.9.50", dst="93.184.216.34") / TCP(dport=443))
        pkt = Ether(frame)                     # constructing from bytes sets .original
        assert pkt.original == frame
        fw._handle(pkt)

        assert sent, "packet was not forwarded"
        out = sent[0]
        assert out[0:6] == fw._mac_to_bytes("aa:bb:cc:dd:ee:ff")   # dst L2 = next hop (gateway)
        assert out[6:12] == fw._my_mac_b                            # src L2 = us
        assert out[12:] == frame[12:]                              # IP payload byte-for-byte intact
        assert fw.counters["192.168.9.50"]["up"] == len(frame)     # accounted as upload
    finally:
        STATE.devices.clear()
        STATE.interface = prev_iface
        SPOOFER._gateway_mac = prev_gw
