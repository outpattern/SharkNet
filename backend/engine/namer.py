"""
Passive device naming: sniff DHCP (option 12 hostname), mDNS (.local names),
and NetBIOS to learn real device names automatically — the way LANtern/Fing do.
Runs a passive sniffer; updates device hostnames (never overrides a user name).
"""
from __future__ import annotations

import threading

from . import rawpkt
from .iobackend import make_capture
from .nameresolver import NAME_RESOLVER
from .. import db
from ..state import STATE


def _clean(name: str) -> str:
    name = (name or "").strip().strip(".")
    # strip trailing .local / .lan
    for suf in (".local", ".lan", ".home"):
        if name.lower().endswith(suf):
            name = name[: -len(suf)]
    return name[:40]


class Namer:
    def __init__(self):
        self._cap = None        # Capture backend (Native via iobackend)
        self.iface = None

    def start(self):
        if self._cap:
            return
        self.iface = STATE.interface
        if self.iface is None:
            return
        bpf = "udp port 67 or udp port 68 or udp port 5353 or udp port 137"
        try:
            self._cap = make_capture(self.iface.name, bpf, self._on)
            self._cap.start()
        except Exception:
            self._cap = None

    def stop(self):
        if self._cap:
            self._cap.stop()
            self._cap = None

    def probe(self):
        """Actively prompt devices to announce mDNS names (they reply, we sniff)."""
        import socket as _s, struct
        queries = ["_services._dns-sd._udp.local", "_device-info._tcp.local",
                   "_airplay._tcp.local", "_googlecast._tcp.local", "_companion-link._tcp.local"]
        try:
            sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
            sock.settimeout(1)
            for q in queries:
                body = b"".join(bytes([len(p)]) + p.encode() for p in q.split(".")) + b"\x00"
                pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + body + struct.pack(">HH", 12, 1)
                sock.sendto(pkt, ("224.0.0.251", 5353))
            sock.close()
        except Exception:
            pass

    def _apply(self, name: str, source: str, mac: str | None = None,
               ip: str | None = None):
        name = _clean(name)
        if not name or len(name) < 2:
            return
        with STATE.lock:
            for d in STATE.devices.values():
                match = (mac and d.mac and d.mac.lower() == mac.lower()) or (ip and d.ip == ip)
                if match:
                    # feed the candidate to the priority resolver; only adopt the
                    # winning (highest-priority) name so a weaker source can never
                    # clobber a stronger one (no name flapping).
                    NAME_RESOLVER.submit(d.mac, source, name)
                    best = NAME_RESOLVER.best(d.mac)
                    if best and d.hostname != best:
                        d.hostname = best
                        d.name_source = NAME_RESOLVER.source_of(d.mac)
                        try:
                            db.save_device(d.mac, d.name, d.vendor, d.dtype,
                                           d.hostname, d.first_seen, d.last_seen)
                        except Exception:
                            pass
                    return

    def _on(self, fr):
        try:
            raw = getattr(fr, "original", None)
            if raw is None and isinstance(fr, (bytes, bytearray)):
                raw = bytes(fr)
            if not raw:
                return
            info = rawpkt.l4_payload(raw)
            if info is None:
                return
            _proto, sport, dport, payload = info
            # ---- DHCP: client hostname (option 12) ----
            if dport in (67, 68) or sport in (67, 68):
                host, cmac = rawpkt.dhcp_hostname(payload)
                if host:
                    mac = cmac or (":".join(f"{b:02x}" for b in raw[6:12]) if len(raw) >= 12 else None)
                    self._apply(host, "dhcp", mac=mac)
                return
            # ---- mDNS / DNS answers: .local names -> IP ----
            if dport == 5353 or sport == 5353 or dport == 53:
                for nm, ip in rawpkt.dns_a_answers(payload):
                    if nm and ".local" in nm.lower():
                        self._apply(nm, "mdns", ip=ip)
        except Exception:
            pass


NAMER = Namer()
