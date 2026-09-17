"""
Stage 2 (v3.0) — GATE 1: native wpcap backend loads, ABI binds, adapter resolves,
lifecycle is safe, error paths covered, no leaked threads/handles.

Real calls that work WITHOUT Administrator (load, findalldevs, resolve, savefile
round-trip proving the pcap_pkthdr/timeval ABI, compile_nopcap + offline_filter)
are gated on wpcap being present. Lifecycle/error tests mock the _wpcap layer so
they run anywhere and never touch a real device. Nothing here is wired to a
consumer; Scapy stays the default backend.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest                                                        # noqa: E402
from backend.engine import _wpcap, npcap                             # noqa: E402

WP = pytest.mark.skipif(not _wpcap.HAVE_WPCAP, reason="wpcap.dll not available")


# ---------------- real, offline (no admin) ----------------
@WP
def test_wpcap_loads_and_reports_version():
    assert _wpcap.WPCAP_PATH.lower().endswith("wpcap.dll")
    assert "pcap" in _wpcap.lib_version().lower()


@WP
def test_findalldevs_lists_npf_devices():
    devs = _wpcap.list_devices()
    assert devs and any(d["name"].startswith(r"\Device\NPF_") for d in devs)


@WP
def test_resolve_npf_name_matches_a_real_adapter():
    from scapy.arch.windows import get_windows_if_list
    cand = next((e for e in get_windows_if_list() if e.get("guid") and e.get("name")), None)
    if not cand:
        pytest.skip("no adapter with a GUID on this host")
    dev = _wpcap.resolve_npf_name(cand["name"])
    assert dev == r"\Device\NPF_" + cand["guid"]
    assert dev in {d["name"] for d in _wpcap.list_devices()}


@WP
def test_pkthdr_abi_and_byte_fidelity_via_savefile_roundtrip():
    # THE ABI proof, fully offline: dump known frames to a .pcap, read them back
    # via pcap_next_ex, require byte/length/order match. If the pcap_pkthdr /
    # timeval layout (caplen offset) were wrong, caplen would be garbage and this
    # would fail — so a pass empirically validates the ABI on this Npcap build.
    frames = [bytes((i & 0xff) for i in range(sz)) for sz in (60, 64, 100, 500, 1514)]
    tmp = os.path.join(tempfile.gettempdir(), "sn_stage2_roundtrip.pcap")
    dead = _wpcap.open_dead()
    dumper = _wpcap.dump_open(dead, tmp)
    for f in frames:
        _wpcap.dump(dumper, f)
    _wpcap.dump_close(dumper)
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
    assert got == frames                          # same bytes, same length, same order
    assert [len(x) for x in got] == [60, 64, 100, 500, 1514]


@WP
def test_compile_nopcap_and_offline_filter():
    prog = _wpcap.compile_nopcap("arp")
    try:
        arp = b"\xff" * 6 + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x06" + b"\x00" * 28
        ipv4 = b"\xff" * 6 + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00" + b"\x45" + b"\x00" * 40
        assert _wpcap.offline_filter(prog, arp) is True
        assert _wpcap.offline_filter(prog, ipv4) is False
    finally:
        _wpcap.free_prog(prog)


# ---------------- lifecycle via a mocked _wpcap layer ----------------
class _FakeIO:
    def __init__(self, mp, frames):
        self.frames = list(frames)
        self.opened = 0
        self.broke = 0
        self.closed = 0
        mp.setattr(npcap._wpcap, "resolve_npf_name", lambda n: r"\Device\NPF_{TEST}")
        mp.setattr(npcap._wpcap, "open_live", self._open)
        mp.setattr(npcap._wpcap, "datalink", lambda h: npcap._wpcap.DLT_EN10MB)
        mp.setattr(npcap._wpcap, "compile_and_set", lambda h, b: None)
        mp.setattr(npcap._wpcap, "next_ex", self._next)
        mp.setattr(npcap._wpcap, "breakloop", self._break)
        mp.setattr(npcap._wpcap, "close", self._close)

    def _open(self, *a, **k):
        self.opened += 1
        return 0xF00D

    def _next(self, h):
        if self.frames:
            return 1, self.frames.pop(0)
        if self.broke:
            return -2, None
        time.sleep(0.005)          # emulate the 100 ms poll (avoid a busy-spin)
        return 0, None

    def _break(self, h):
        self.broke += 1

    def _close(self, h):
        self.closed += 1


def test_capture_lifecycle_delivers_in_order_and_cleans(monkeypatch):
    got = []
    fk = _FakeIO(monkeypatch, [b"aaa", b"bbb", b"ccc"])
    cap = npcap.NpcapCapture("Ethernet", "ip and ether dst 02:00:00:00:00:aa",
                             lambda fr: got.append(fr.original))
    cap.start()
    deadline = time.time() + 3
    while len(got) < 3 and time.time() < deadline:
        time.sleep(0.01)
    cap.stop()
    assert got == [b"aaa", b"bbb", b"ccc"]        # delivered in order, as .original bytes
    assert fk.broke >= 1 and fk.closed >= 1       # breakloop happened, then close
    assert cap._thread is None and cap._handle is None   # no leaked thread / handle


def test_capture_start_is_idempotent(monkeypatch):
    fk = _FakeIO(monkeypatch, [])
    cap = npcap.NpcapCapture("Ethernet", "ip", lambda fr: None)
    cap.start()
    try:
        cap.start()
        assert fk.opened == 1
    finally:
        cap.stop()


def test_capture_stop_before_start_is_safe(monkeypatch):
    _FakeIO(monkeypatch, [])
    npcap.NpcapCapture("Ethernet", "ip", lambda fr: None).stop()   # must not raise


def test_capture_open_failure_leaves_no_handle_or_thread(monkeypatch):
    monkeypatch.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    monkeypatch.setattr(npcap._wpcap, "open_live",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no admin")))
    cap = npcap.NpcapCapture("Ethernet", "ip", lambda fr: None)
    with pytest.raises(OSError):
        cap.start()
    assert cap._handle is None and cap._thread is None


def test_capture_filter_failure_closes_handle(monkeypatch):
    closed = []
    monkeypatch.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    monkeypatch.setattr(npcap._wpcap, "open_live", lambda *a, **k: 999)
    monkeypatch.setattr(npcap._wpcap, "datalink", lambda h: npcap._wpcap.DLT_EN10MB)
    monkeypatch.setattr(npcap._wpcap, "compile_and_set",
                        lambda h, b: (_ for _ in ()).throw(OSError("bad filter")))
    monkeypatch.setattr(npcap._wpcap, "close", lambda h: closed.append(h))
    cap = npcap.NpcapCapture("Ethernet", "bad!!filter", lambda fr: None)
    with pytest.raises(OSError):
        cap.start()
    assert closed == [999] and cap._handle is None    # handle closed on failure path


def _fake_injector(mp):
    sent, closed = [], []
    mp.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    mp.setattr(npcap._wpcap, "open_live", lambda *a, **k: 0x777)
    mp.setattr(npcap._wpcap, "sendpacket", lambda h, raw: sent.append(bytes(raw)))
    mp.setattr(npcap._wpcap, "close", lambda h: closed.append(h))
    return sent, closed


def test_injector_send_and_idempotent_close(monkeypatch):
    sent, closed = _fake_injector(monkeypatch)
    inj = npcap.NpcapInjector("Ethernet")
    inj.send(b"\x01\x02\x03")
    inj.close()
    inj.close()                       # idempotent
    assert sent == [b"\x01\x02\x03"] and closed == [0x777]


def test_injector_send_batch_gap(monkeypatch):
    sent, _ = _fake_injector(monkeypatch)
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))
    npcap.NpcapInjector("Ethernet").send_batch([b"1", b"2", b"3"], gap=0.002)
    assert sent == [b"1", b"2", b"3"] and sleeps == [0.002, 0.002]


def test_frame_is_slots_only():
    f = npcap._Frame(b"xyz")
    assert f.original == b"xyz"
    with pytest.raises(AttributeError):
        f.extra = 1                   # __slots__ -> no per-frame __dict__
