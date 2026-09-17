"""
Stage 2/3 (v3.0) — GATE 2: native (wpcap) vs Scapy golden equivalence.

Proves the native backend is behaviourally identical to the Scapy reference at
the byte/logic level BEFORE it could ever become default:
  - capture: same raw frame bytes / length / order (savefile round-trip)
  - filtering: same BPF accept/reject (same libpcap engine scapy uses)
  - injection: identical transmitted bytes / count / order (native vs Scapy)
  - ARP: byte-identical frames, preserved 0.002 s inter-frame gap
No policy/enforcement is touched to make these pass. Mocked sockets + offline
pcap; no admin, no live traffic (that is the later hardware gate).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest                                                        # noqa: E402
from backend.engine import _wpcap, npcap                            # noqa: E402
from backend.engine import injector as inj_mod                      # noqa: E402
from backend.engine import rawpkt                                   # noqa: E402

WP = pytest.mark.skipif(not _wpcap.HAVE_WPCAP, reason="wpcap.dll not available")


def _eth(dst, src, etype, payload=b""):
    return dst + src + etype + payload


# ---------------- capture equivalence (raw-byte fidelity) ----------------
@WP
def test_capture_bytes_length_order_equivalence():
    # Native delivers each frame's raw bytes exactly (== what scapy's
    # pkt.original yields). Proven offline via a pcap savefile round-trip.
    frames = [bytes((i & 0xff) for i in range(sz)) for sz in (60, 100, 800, 1514)]
    tmp = os.path.join(tempfile.gettempdir(), "sn_eq_capture.pcap")
    dead = _wpcap.open_dead()
    dmp = _wpcap.dump_open(dead, tmp)
    for f in frames:
        _wpcap.dump(dmp, f)
    _wpcap.dump_close(dmp)
    _wpcap.close(dead)
    h = _wpcap.open_offline(tmp)
    got = []
    while True:
        rc, raw = _wpcap.next_ex(h)
        if rc == 1:
            got.append(raw)
        else:
            break
    _wpcap.close(h)
    try:
        os.remove(tmp)
    except OSError:
        pass
    assert got == frames                                   # bytes + order
    assert [len(x) for x in got] == [len(f) for f in frames]   # lengths


# ---------------- BPF acceptance/rejection equivalence ----------------
@WP
def test_bpf_ip_ether_dst_accept_reject():
    my = b"\x02\x00\x00\x00\x00\xaa"
    other = b"\x02\x00\x00\x00\x00\xbb"
    prog = _wpcap.compile_nopcap("ip and ether dst 02:00:00:00:00:aa")
    try:
        ip_to_us = _eth(my, other, b"\x08\x00", b"\x45" + b"\x00" * 40)
        ip_to_other = _eth(other, my, b"\x08\x00", b"\x45" + b"\x00" * 40)
        arp_to_us = _eth(my, other, b"\x08\x06", b"\x00" * 28)
        assert _wpcap.offline_filter(prog, ip_to_us) is True     # IPv4 addressed to us
        assert _wpcap.offline_filter(prog, ip_to_other) is False  # wrong L2 dst
        assert _wpcap.offline_filter(prog, arp_to_us) is False    # not IPv4
    finally:
        _wpcap.free_prog(prog)


@WP
def test_bpf_arp_accept_reject():
    prog = _wpcap.compile_nopcap("arp")
    try:
        arp = _eth(b"\xff" * 6, b"\x00\x11\x22\x33\x44\x55", b"\x08\x06", b"\x00" * 28)
        ip = _eth(b"\xff" * 6, b"\x00\x11\x22\x33\x44\x55", b"\x08\x00", b"\x45" + b"\x00" * 20)
        assert _wpcap.offline_filter(prog, arp) is True
        assert _wpcap.offline_filter(prog, ip) is False
    finally:
        _wpcap.free_prog(prog)


# ---------------- injection equivalence (native vs scapy) ----------------
def _scapy_recorder(monkeypatch, sink):
    import scapy.config
    monkeypatch.setattr(
        scapy.config.conf, "L2socket",
        lambda iface=None, **k: type("S", (), {
            "send": lambda self, b: sink.append(bytes(b)),
            "close": lambda self: None})())


def _native_recorder(monkeypatch, sink):
    monkeypatch.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    monkeypatch.setattr(npcap._wpcap, "open_live", lambda *a, **k: 1)
    monkeypatch.setattr(npcap._wpcap, "sendpacket", lambda h, raw: sink.append(bytes(raw)))
    monkeypatch.setattr(npcap._wpcap, "close", lambda h: None)


def test_injection_bytes_count_order_equivalence(monkeypatch):
    frames = [b"frame-%03d" % i for i in range(6)]
    monkeypatch.setattr("time.sleep", lambda s: None)
    nsent, ssent = [], []
    _native_recorder(monkeypatch, nsent)
    npcap.NpcapInjector("Ethernet").send_batch(iter(frames), gap=0.002)
    _scapy_recorder(monkeypatch, ssent)
    inj_mod.ScapyInjector("Ethernet").send_batch(iter(frames), gap=0.002)
    assert nsent == ssent == frames           # identical bytes, count, order


def test_single_send_equivalence(monkeypatch):
    nsent, ssent = [], []
    _native_recorder(monkeypatch, nsent)
    npcap.NpcapInjector("Ethernet").send(b"\xaa\xbb\xcc")
    _scapy_recorder(monkeypatch, ssent)
    inj_mod.ScapyInjector("Ethernet").send(b"\xaa\xbb\xcc")
    assert nsent == ssent == [b"\xaa\xbb\xcc"]


def test_arp_frames_identical_through_both_injectors(monkeypatch):
    pkts = [rawpkt.build_arp("de:ad:be:ef:00:%02x" % i, "02:00:00:00:00:aa", 2,
                             "02:00:00:00:00:aa", "192.168.9.1",
                             "de:ad:be:ef:00:%02x" % i, "192.168.9.%d" % i)
            for i in (10, 11, 12)]
    monkeypatch.setattr("time.sleep", lambda s: None)
    nsent, ssent = [], []
    _native_recorder(monkeypatch, nsent)
    npcap.NpcapInjector("x").send_batch(pkts, gap=0.002)
    _scapy_recorder(monkeypatch, ssent)
    inj_mod.ScapyInjector("x").send_batch(pkts, gap=0.002)
    assert nsent == ssent == pkts             # byte-identical ARP, same count/order


def test_batch_gap_semantics_equivalent(monkeypatch):
    frames = [b"1", b"2", b"3", b"4"]
    n_sleeps, s_sleeps = [], []
    _native_recorder(monkeypatch, [])
    monkeypatch.setattr("time.sleep", lambda s: n_sleeps.append(s))
    npcap.NpcapInjector("x").send_batch(frames, gap=0.002)
    _scapy_recorder(monkeypatch, [])
    monkeypatch.setattr("time.sleep", lambda s: s_sleeps.append(s))
    inj_mod.ScapyInjector("x").send_batch(frames, gap=0.002)
    assert n_sleeps == s_sleeps == [0.002, 0.002, 0.002]   # same inter-frame gaps


def test_injector_close_equivalence(monkeypatch):
    nclosed, sclosed = [], []
    monkeypatch.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    monkeypatch.setattr(npcap._wpcap, "open_live", lambda *a, **k: 5)
    monkeypatch.setattr(npcap._wpcap, "close", lambda h: nclosed.append(h))
    n = npcap.NpcapInjector("x"); n.close(); n.close()
    import scapy.config
    monkeypatch.setattr(scapy.config.conf, "L2socket",
                        lambda iface=None, **k: type("S", (), {
                            "send": lambda self, b: None,
                            "close": lambda self: sclosed.append(True)})())
    s = inj_mod.ScapyInjector("x"); s.close()
    assert nclosed == [5] and sclosed == [True]   # both close their handle idempotently
