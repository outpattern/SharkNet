"""
Production packet-I/O backend construction (v3.0).

The Native (Npcap) Capture/Injector path is the SOLE production data-plane
backend — hardware-validated across Gate 5, and the last scapy paths were removed
in Gate 6.4. These helpers keep the Capture/Injector Protocols (capture.py /
injector.py) as the architectural boundary: a caller receives an object that
implements the interface and never hard-codes a concrete backend class.

There is a single backend; these helpers exist so consumers depend on the
Capture/Injector interface rather than a concrete class.
"""
from __future__ import annotations

from typing import Callable


def active_backend() -> str:
    return "native"


def make_capture(iface_name: str, bpf: str, on_packet: Callable):
    from .npcap import NpcapCapture
    return NpcapCapture(iface_name, bpf, on_packet)


def make_injector(iface_name: str):
    from .npcap import NpcapInjector
    return NpcapInjector(iface_name)
