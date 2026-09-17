"""
Packet INJECTION interface: the `Injector` Protocol + the test-only `ScapyInjector`.

The `Injector` Protocol is the architectural boundary the production backend
(`NpcapInjector`, in npcap.py) implements; consumers construct backends via
`iobackend.make_injector` and depend only on this interface.

`ScapyInjector` is a 1:1 wrapper over scapy's L2 socket (conf.L2socket). As of
Gate 6.4 it is NOT a production backend and is imported by NO production module —
it is retained ONLY as the golden EQUIVALENCE ORACLE for the test suite
(test_stage1_io.py, test_stage23_equivalence.py), which prove NpcapInjector sends
byte-identical frames. Scapy is a dev/test-only dependency (requirements-dev.txt).
"""
from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable


@runtime_checkable
class Injector(Protocol):
    def send(self, raw: bytes) -> None: ...
    def send_batch(self, frames: "Iterable[bytes]", gap: float = 0.0) -> None: ...
    def close(self) -> None: ...


class ScapyInjector:
    """TEST-ONLY equivalence oracle — NOT a production backend (no production
    module imports it). conf.L2socket wrapper; `send` is the socket's bound
    method. Used by the test suite to prove NpcapInjector is byte-identical."""

    def __init__(self, iface_name: str) -> None:
        from scapy.config import conf
        self._sock = conf.L2socket(iface=iface_name)
        # bind the raw socket send so hot-path callers add no extra call layer
        self.send = self._sock.send

    def send_batch(self, frames: "Iterable[bytes]", gap: float = 0.0) -> None:
        import time
        send = self._sock.send
        first = True
        for f in frames:
            if gap and not first:
                time.sleep(gap)     # "inter": wait between two consecutive frames
            send(f)
            first = False

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
