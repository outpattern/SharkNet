"""
Stage 1 (v3.0) — Capture / Injector abstraction tests.

Proves the Scapy backends wrap scapy 1:1 so behavior is unchanged:
  - ScapyInjector.send IS the raw socket send (no hot-path wrapper layer)
  - send_batch equivalence to sendp(inter=): identical count / bytes / order,
    inter-frame gap preserved, matching serialization, equivalent error behavior
  - ScapyCapture constructs AsyncSniffer with identical args and passes the
    consumer callback straight through as prn (direct call, no wrapper)

Pure logic: a mock socket + a patched AsyncSniffer. No real Npcap, no admin.
Run:  python -m pytest tests/ -q
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest                                                        # noqa: E402


class _Sock:
    """Stand-in for scapy's conf.L2socket."""
    def __init__(self, fail_on: int | None = None):
        self.sent: list[bytes] = []
        self.closed = False
        self._n = 0
        self._fail_on = fail_on

    def send(self, b):
        self._n += 1
        if self._fail_on and self._n == self._fail_on:
            raise OSError("send failed")
        self.sent.append(bytes(b))

    def close(self):
        self.closed = True


def _injector(monkeypatch, sock):
    import scapy.config
    monkeypatch.setattr(scapy.config.conf, "L2socket", lambda iface=None, **k: sock)
    from backend.engine.injector import ScapyInjector
    return ScapyInjector("test-iface")


# ---------------- Injector: single send / close ----------------
def test_injector_send_is_the_raw_socket_send(monkeypatch):
    s = _Sock()
    inj = _injector(monkeypatch, s)
    assert inj.send == s.send                 # bound to the socket's own send (no wrapper layer)
    inj.send(b"\xde\xad\xbe\xef")
    assert s.sent == [b"\xde\xad\xbe\xef"]     # exact bytes through


def test_injector_close(monkeypatch):
    s = _Sock()
    _injector(monkeypatch, s).close()
    assert s.closed is True


def test_injector_close_never_raises(monkeypatch):
    class Bad:
        def send(self, b): pass
        def close(self): raise OSError("x")
    _injector(monkeypatch, Bad()).close()     # must not raise


# ---------------- send_batch equivalence to sendp(inter=0.002) ----------------
def test_send_batch_identical_count_bytes_order(monkeypatch):
    s = _Sock()
    inj = _injector(monkeypatch, s)
    monkeypatch.setattr(time, "sleep", lambda _x: None)
    frames = [b"aaa", b"bbb", b"ccc", b"ddd"]
    inj.send_batch(iter(frames), gap=0.002)   # a generator, exactly as arp.py passes
    assert s.sent == frames                   # count + bytes + ordering all identical


def test_send_batch_preserves_interframe_gap(monkeypatch):
    s = _Sock()
    inj = _injector(monkeypatch, s)
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda x: sleeps.append(x))
    inj.send_batch([b"1", b"2", b"3", b"4"], gap=0.002)
    assert sleeps == [0.002, 0.002, 0.002]    # gap BETWEEN consecutive frames (n-1), like inter=


def test_send_batch_no_gap_when_zero(monkeypatch):
    s = _Sock()
    inj = _injector(monkeypatch, s)
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda x: sleeps.append(x))
    inj.send_batch([b"1", b"2"], gap=0.0)
    assert sleeps == [] and s.sent == [b"1", b"2"]


def test_send_batch_error_behavior_matches_call_site(monkeypatch):
    # sendp errors surface to arp.py's try/except; send_batch propagates the same way
    s = _Sock(fail_on=2)
    inj = _injector(monkeypatch, s)
    monkeypatch.setattr(time, "sleep", lambda _x: None)
    with pytest.raises(OSError):
        inj.send_batch([b"a", b"b", b"c"])
    assert s.sent == [b"a"]                    # first sent, raised on the second


def test_send_batch_bytes_equal_sendp_serialization(monkeypatch):
    # what arp.py hands send_batch (bytes(p)) equals what sendp puts on the wire
    from scapy.layers.l2 import Ether, ARP
    s = _Sock()
    inj = _injector(monkeypatch, s)
    monkeypatch.setattr(time, "sleep", lambda _x: None)
    pkts = [Ether(src="02:00:00:00:00:aa", dst="ff:ff:ff:ff:ff:ff") /
            ARP(hwsrc="02:00:00:00:00:aa", psrc="192.168.9.2", pdst=f"192.168.9.{i}")
            for i in (10, 11, 12)]
    inj.send_batch((bytes(p) for p in pkts), gap=0.002)
    assert s.sent == [bytes(p) for p in pkts]  # byte-identical, same order/count


# ---------------- Capture wiring ----------------
def test_scapy_capture_wires_asyncsniffer_identically(monkeypatch):
    seen: dict = {}

    class MockSniffer:
        def __init__(self, **kw): seen.update(kw)
        def start(self): seen["started"] = True
        def stop(self): seen["stopped"] = True

    import scapy.sendrecv
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", MockSniffer)
    from backend.engine.capture import ScapyCapture
    cb = lambda p: None                                              # noqa: E731
    cap = ScapyCapture("myiface", "ip and ether dst aa:bb:cc:dd:ee:ff", cb)
    cap.start()
    assert seen["iface"] == "myiface"
    assert seen["filter"] == "ip and ether dst aa:bb:cc:dd:ee:ff"
    assert seen["prn"] is cb                   # callback passed STRAIGHT through — direct call, no wrapper
    assert seen["store"] is False
    assert seen.get("started") is True
    cap.stop()
    assert seen.get("stopped") is True


def test_scapy_capture_start_is_idempotent(monkeypatch):
    n = {"c": 0}

    class MockSniffer:
        def __init__(self, **kw): n["c"] += 1
        def start(self): pass
        def stop(self): pass

    import scapy.sendrecv
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", MockSniffer)
    from backend.engine.capture import ScapyCapture
    cap = ScapyCapture("i", "arp", lambda p: None)
    cap.start(); cap.start()                   # second start is a no-op
    assert n["c"] == 1
    cap.stop()


def test_capture_stop_before_start_is_safe():
    from backend.engine.capture import ScapyCapture
    ScapyCapture("i", "arp", lambda p: None).stop()   # must not raise


def test_capture_backend_satisfies_protocol():
    from backend.engine.capture import Capture, ScapyCapture
    assert isinstance(ScapyCapture("i", "arp", lambda p: None), Capture)
