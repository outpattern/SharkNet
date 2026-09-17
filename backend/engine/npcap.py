"""
Native packet I/O backends — ctypes -> wpcap.dll. THE production data-plane
backend (Gate 6.5 hardware-validated; scapy removed from the runtime in Gate 6.4).

`NpcapCapture` and `NpcapInjector` implement the Capture / Injector protocols
(see capture.py / injector.py) with NO scapy packet construction or dissection.
They are the only backend `iobackend` constructs for the forwarder/spoofer/etc.

Delivery contract: the object handed to the capture callback exposes `.original`
(raw frame bytes) — what every consumer reads — via a one-field `__slots__`
carrier (`_Frame`), not a heavyweight packet object.

Lifecycle is independently safe: stop() sets a flag, calls pcap_breakloop, joins
the capture thread, THEN closes the handle — pcap_close never runs while the
thread can still be inside pcap_next_ex.
"""
from __future__ import annotations

import threading
import logging
import time
from typing import Callable, Iterable

from . import _wpcap

_log = logging.getLogger("sharknet.engine")


class _Frame:
    """Minimal captured-frame carrier: `.original` is the raw Ethernet bytes,
    matching what scapy's packet exposes to the forwarder. Not a scapy Packet."""
    __slots__ = ("original",)

    def __init__(self, raw: bytes) -> None:
        self.original = raw


class NpcapCapture:
    """Native capture backend. Ctor: (iface_name, bpf, on_packet)."""

    def __init__(self, iface_name: str, bpf: str, on_packet: Callable) -> None:
        self._iface = iface_name
        self._bpf = bpf
        self._on_packet = on_packet
        self._handle = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        dev = _wpcap.resolve_npf_name(self._iface)
        self._handle = _wpcap.open_live(dev, 65535, 1, 100)   # snaplen, promisc, 100 ms poll
        try:
            if _wpcap.datalink(self._handle) != _wpcap.DLT_EN10MB:
                raise OSError("adapter is not Ethernet (DLT_EN10MB)")
            _wpcap.compile_and_set(self._handle, self._bpf)
        except Exception:
            try:
                _wpcap.close(self._handle)
            except Exception:
                pass
            self._handle = None
            raise
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="sharknet-npcap-capture")
        self._thread.start()

    def _loop(self) -> None:
        h = self._handle
        while not self._stop.is_set():
            try:
                rc, raw = _wpcap.next_ex(h)
            except Exception:
                break
            if rc == 1 and raw is not None:
                try:
                    self._on_packet(_Frame(raw))
                except Exception:
                    # a bad packet must never kill capture — but log at debug so a
                    # LOGIC bug in a handler surfaces instead of vanishing silently
                    # (this swallow once masked a defender NameError).
                    _log.debug("capture callback error (packet dropped)", exc_info=True)
            elif rc == 0:
                continue                    # timeout -> re-check stop flag
            else:
                break                       # -1 error / -2 eof

    def stop(self) -> None:
        self._stop.set()
        if self._handle is not None:
            try:
                _wpcap.breakloop(self._handle)   # wake next_ex immediately
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)         # ensure no next_ex in flight...
            self._thread = None
        if self._handle is not None:
            try:
                _wpcap.close(self._handle)        # ...before closing the handle
            except Exception:
                pass
            self._handle = None


class NpcapInjector:
    """Native injector backend. Ctor: (iface_name); send/send_batch/close."""

    def __init__(self, iface_name: str) -> None:
        dev = _wpcap.resolve_npf_name(iface_name)
        self._handle = _wpcap.open_live(dev, 65535, 1, 100)

    def send(self, raw: bytes) -> None:
        _wpcap.sendpacket(self._handle, raw)

    def send_batch(self, frames: "Iterable[bytes]", gap: float = 0.0) -> None:
        first = True
        for f in frames:
            if gap and not first:
                time.sleep(gap)     # "inter": wait between two consecutive frames
            _wpcap.sendpacket(self._handle, f)
            first = False

    def close(self) -> None:
        if self._handle is not None:
            try:
                _wpcap.close(self._handle)
            except Exception:
                pass
            self._handle = None
