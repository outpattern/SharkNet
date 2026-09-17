"""
Network Health + Traffic Intelligence.

- Real throughput/packets for the selected NIC via psutil counters.
- Latency + packet loss + gateway/DNS/internet reachability via ping/DNS.
Runs one background thread, publishes a status dict the server streams to the UI.
"""
from __future__ import annotations

import socket
import subprocess
import threading
import time

import psutil

from ..state import STATE

_NOWINDOW = 0x08000000


def _ping(host: str, count: int = 1, timeout_ms: int = 800):
    """Return (avg_latency_ms | None, loss_pct)."""
    try:
        out = subprocess.run(
            ["ping", "-n", str(count), "-w", str(timeout_ms), host],
            capture_output=True, text=True, timeout=count * (timeout_ms / 1000) + 3,
            creationflags=_NOWINDOW,
        ).stdout
    except Exception:
        return None, 100.0
    sent = recv = 0
    lat = None
    for line in out.splitlines():
        low = line.lower()
        if "sent =" in low or "الأصل" in low:
            # "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
            import re
            m = re.search(r"sent = (\d+), received = (\d+)", low)
            if m:
                sent, recv = int(m.group(1)), int(m.group(2))
        if "average =" in low or "average=" in low:
            import re
            m = re.search(r"average = (\d+)", low)
            if m:
                lat = float(m.group(1))
    loss = 0.0 if sent == 0 else round((sent - recv) / sent * 100, 1)
    return lat, loss


def _tcp_reach(host: str, port: int, timeout: float = 1.2) -> bool:
    """True if `host:port` answers at L3/L4 — either a completed TCP handshake OR a
    connection refusal (a RST still proves the host is REACHABLE). Unlike ICMP,
    this survives our own MITM/Npcap load: ping is frequently dropped or
    deprioritized while the forwarder is busy, which used to false-report the
    internet as OFFLINE. The PC's own TCP goes through the normal stack (the
    forwarder only touches INTERCEPTED devices' traffic, never our own)."""
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        return True
    except ConnectionRefusedError:
        return True             # host answered with a RST -> reachable
    except OSError:
        return False
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def _dns_ok() -> bool:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname("cloudflare.com")
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(old)   # don't leak the global default


class Health:
    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last = None
        self.data = {
            "down_bps": 0.0, "up_bps": 0.0, "pps": 0.0,
            "latency_ms": None, "packet_loss": 0.0,
            "gateway_online": False, "dns_online": False, "internet_online": False,
            "grade": "unknown",
            # item 9: the grade reflects PHYSICAL network health; when SharkNet's own
            # enforcement load inflates this host's latency/loss while the path is
            # fully reachable, the grade stays >= "good" and this flag is set so the
            # UI can say "Healthy · Policy active" instead of a misleading "Poor".
            "policy_influenced": False,
        }

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _nic_counters(self):
        iface = STATE.interface
        if iface is None:
            return None
        per = psutil.net_io_counters(pernic=True)
        c = per.get(iface.name)
        if c is None:
            # try matching by description-ish; else sum all
            c = psutil.net_io_counters()
        return c

    def _loop(self):
        last_conn = 0.0
        while not self._stop.is_set():
            self._stop.wait(2.0)
            if self._stop.is_set():
                break
            c = self._nic_counters()
            now = time.time()
            if c and self._last:
                prev, pt = self._last
                dt = max(now - pt, 1e-6)
                self.data["down_bps"] = max(0, (c.bytes_recv - prev.bytes_recv) / dt)
                self.data["up_bps"] = max(0, (c.bytes_sent - prev.bytes_sent) / dt)
                pkts = (c.packets_recv + c.packets_sent) - (prev.packets_recv + prev.packets_sent)
                self.data["pps"] = max(0, pkts / dt)
            if c:
                self._last = (c, now)

            # connectivity + latency every ~6s
            if now - last_conn > 6:
                last_conn = now
                self._check_connectivity()

    def _check_connectivity(self) -> None:
        """Measure gateway/DNS/internet reachability + latency/loss. ICMP first (for
        latency), then a TCP handshake fallback so a dropped ping under our own
        MITM/Npcap load never false-reports 'offline'. Extracted for testability."""
        iface = STATE.interface
        gw = iface.gateway if iface else ""
        if gw:
            glat, gloss = _ping(gw, count=1, timeout_ms=700)
            # ICMP first (also gives latency); fall back to a TCP knock on the
            # router's usual admin/DNS ports so a dropped ping isn't "offline".
            self.data["gateway_online"] = (glat is not None or _tcp_reach(gw, 80)
                                           or _tcp_reach(gw, 443) or _tcp_reach(gw, 53))
        ilat, iloss = _ping("1.1.1.1", count=3, timeout_ms=800)
        icmp_ok = ilat is not None
        # A dropped ICMP echo does NOT mean the internet is down — especially while
        # SharkNet is enforcing/monitoring (our own load drops pings). Confirm with a
        # real TCP handshake before ever declaring an outage.
        inet_ok = icmp_ok or _tcp_reach("1.1.1.1", 443) or _tcp_reach("8.8.8.8", 53)
        self.data["internet_online"] = inet_ok
        self.data["latency_ms"] = ilat
        # trust the ICMP loss figure only when ICMP actually answered; if reachable
        # via TCP but ping was fully dropped, report 0 (no real sample) not 100%.
        self.data["packet_loss"] = iloss if icmp_ok else (0.0 if inet_ok else 100.0)
        self.data["dns_online"] = _dns_ok() or inet_ok
        self.data["grade"] = self._grade()

    def _grade(self) -> str:
        lat = self.data["latency_ms"]
        loss = self.data["packet_loss"]
        self.data["policy_influenced"] = False
        if not self.data["internet_online"]:
            return "offline"                 # genuine outage — never masked
        reachable = (self.data["gateway_online"] and self.data["dns_online"]
                     and self.data["internet_online"])
        enforcing = bool(getattr(STATE, "enforcing", False))
        if lat is None:
            # internet reachable (TCP) but ICMP gave no latency — under our own
            # enforcement load that's our artifact, not a fault: show a healthy
            # policy-influenced grade rather than "unknown"/"poor".
            if reachable and enforcing:
                self.data["policy_influenced"] = True
                return "good"
            return "unknown"
        raw = ("excellent" if lat < 20 and loss < 1 else
               "good" if lat < 60 and loss < 3 else
               "fair" if lat < 120 and loss < 8 else "poor")
        # POLICY-AWARE (item 9): SharkNet's own MITM/forward load can inflate THIS
        # host's latency/loss while it is intercepting (LIMIT/CUT/MONITOR) other
        # devices — that is not a physical network fault. When the path is fully
        # reachable and we are enforcing, don't let latency/loss alone drop the
        # NETWORK grade below "good"; flag it so the UI shows "Healthy · Policy
        # active". Genuine unreachability still grades fair/poor/offline normally.
        if raw in ("fair", "poor") and reachable and enforcing:
            self.data["policy_influenced"] = True
            return "good"
        return raw

    def status(self) -> dict:
        return dict(self.data)


HEALTH = Health()
