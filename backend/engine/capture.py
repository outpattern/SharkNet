"""
Packet CAPTURE interface: the `Capture` Protocol + the test-only `ScapyCapture`.

The `Capture` Protocol is the architectural boundary the production backend
(`NpcapCapture`, in npcap.py) implements; consumers construct backends via
`iobackend.make_capture` and depend only on this interface.

`ScapyCapture` is a 1:1 wrapper over scapy's AsyncSniffer. As of Gate 6.4 it is
NOT a production backend and is imported by NO production module — it is retained
ONLY as the golden EQUIVALENCE ORACLE for the test suite (test_stage1_io.py,
test_stage23_equivalence.py), which prove the native backend is byte/behaviour-
identical to scapy. Scapy is a dev/test-only dependency (requirements-dev.txt),
and can never become the runtime backend: iobackend only constructs the native one.
"""
from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable


@runtime_checkable
class Capture(Protocol):
    """Lifecycle-only capture handle. Frames are delivered to the callback the
    concrete backend was constructed with."""

    def start(self) -> None: ...
    def stop(self) -> None: ...


class ScapyCapture:
    """TEST-ONLY equivalence oracle — NOT a production backend (no production
    module imports it). AsyncSniffer wrapper; `on_packet` is used verbatim as
    scapy's `prn`. Used by the test suite to prove NpcapCapture is identical."""

    def __init__(self, iface_name: str, bpf: str, on_packet: Callable) -> None:
        self._iface = iface_name
        self._bpf = bpf
        self._on_packet = on_packet
        self._sniffer = None

    def start(self) -> None:
        if self._sniffer is not None:
            return
        from scapy.sendrecv import AsyncSniffer
        self._sniffer = AsyncSniffer(
            iface=self._iface, filter=self._bpf, prn=self._on_packet, store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
