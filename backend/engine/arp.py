"""
ARP scanning/resolution that works on BOTH Ethernet and Wi-Fi under Npcap.

We sniff ARP replies natively (Npcap) and parse them with rawpkt.parse_arp while
we send the requests, then match manually — works on Ethernet and Wi-Fi.
"""
from __future__ import annotations

import ipaddress
import time

from . import netinfo, rawpkt
from .iobackend import make_capture, make_injector


def _os_getmac(ip: str) -> str | None:
    """Resolve ip -> MAC via the OS (iphlpapi SendARP) — the scapy-free
    equivalent of getmacbyip (uses the ARP cache / one ARP resolution)."""
    import ctypes
    import socket as _s
    import struct as _st
    from ctypes import wintypes
    try:
        dest = _st.unpack("<I", _s.inet_aton(ip))[0]
        mac = (ctypes.c_ubyte * 6)()
        length = wintypes.ULONG(6)
        rc = ctypes.WinDLL("iphlpapi").SendARP(
            wintypes.DWORD(dest), wintypes.DWORD(0), mac, ctypes.byref(length))
        if rc == 0 and length.value >= 6:
            return ":".join(f"{b:02x}" for b in mac[:6])
    except Exception:
        pass
    return None


def arp_scan(iface: "netinfo.Interface", ips, timeout: float = 3.0) -> dict[str, str]:
    """Return {ip: mac} for hosts that answer ARP on the interface."""
    ips = list(ips)
    found: dict[str, str] = {}

    # only accept replies within our subnet (avoid cross-network noise)
    try:
        net = ipaddress.IPv4Network(iface.cidr, strict=False)
    except Exception:
        net = None

    my_mac = (iface.mac or "").lower()

    def cap(fr):
        info = rawpkt.parse_arp(getattr(fr, "original", fr))
        if not info or info[0] != 2:          # ARP replies only (op == 2)
            return
        _op, hwsrc, ip, _tmac, _tip = info    # (op, sender_mac, sender_ip, ...)
        # ignore replies carrying OUR OWN mac (our spoofing) so the Defender
        # never mistakes our enforcement for an attacker
        if hwsrc.lower() == my_mac:
            return
        if net is not None:
            try:
                if ipaddress.IPv4Address(ip) not in net:
                    return
            except Exception:
                return
        found[ip] = hwsrc.lower()

    sniffer = make_capture(iface.name, "arp", cap)
    try:
        sniffer.start()
    except Exception:
        return found
    time.sleep(0.3)

    # raw ARP requests (op=1), byte-identical to the former Ether()/ARP() build
    pkts = [rawpkt.build_arp("ff:ff:ff:ff:ff:ff", iface.mac, 1, iface.mac, iface.ip,
                             "00:00:00:00:00:00", str(ip)) for ip in ips]
    try:
        inj = make_injector(iface.name)
        try:
            inj.send_batch(iter(pkts), gap=0.002)
        finally:
            inj.close()
    except Exception:
        pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.2)
    try:
        sniffer.stop()
    except Exception:
        pass
    return found


def arp_resolve(iface: "netinfo.Interface", ip: str,
                timeout: float = 2.0, tries: int = 3) -> str | None:
    """Resolve a single IP's MAC (gateway/target). Retries a few times."""
    for _ in range(tries):
        res = arp_scan(iface, [ip], timeout=timeout)
        mac = res.get(ip)
        if mac:
            return mac
    return _os_getmac(ip)     # last resort: the OS ARP cache (iphlpapi SendARP)
