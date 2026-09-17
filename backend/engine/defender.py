"""
SharkNet Defender: detects ARP-spoofing attacks against THIS machine and
identifies the attacker.

Two detectors:
  - Active probe: every few seconds resolve the gateway's real MAC; alert if it
    changes from the baseline.
  - Passive monitor: sniff ARP and flag anyone claiming to be the gateway with a
    different MAC, any IP that maps to multiple MACs (spoofing), or ARP floods.

On an attack it identifies the attacker (rogue MAC + its device IP/vendor) and,
if Static ARP Lock is enabled, auto-heals by re-asserting the correct mapping.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque

from . import arp, rawpkt, vendors
from .iobackend import make_capture
from .protection import PROTECTION
from .. import db
from ..state import STATE


class Defender:
    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._cap = None        # Capture backend (Native via iobackend)
        self._stop = threading.Event()
        self.active = False
        self.baseline_mac: str | None = None
        self.current_mac: str | None = None
        self.anomalies = 0
        self.alert: dict | None = None
        self.iface = None
        self._arp_times = deque(maxlen=200)   # timestamps for flood detection
        self._seen: dict[str, str] = {}       # ip -> mac (last legit mapping)

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.iface = STATE.interface
        if self.iface is None or not self.iface.gateway:
            return
        self.baseline_mac = arp.arp_resolve(self.iface, self.iface.gateway, timeout=2, tries=2)
        self.current_mac = self.baseline_mac
        self.alert = None
        self.anomalies = 0
        self._seen = {}
        self._stop.clear()
        self.active = True
        # passive ARP monitor
        try:
            self._cap = make_capture(self.iface.name, "arp", self._on_arp)
            self._cap.start()
        except Exception:
            self._cap = None
        # active probe thread
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._cap:
            self._cap.stop()
            self._cap = None
        if self._thread:
            self._thread.join(timeout=3)
        self.active = False

    def acknowledge(self) -> None:
        """Clear the current alert and re-baseline the gateway MAC. Safe to call
        when the defender is stopped or the interface/gateway is unavailable
        (never raises — /api/defender/ack must not 500)."""
        iface = self.iface
        if iface is not None and iface.gateway:
            try:
                mac = arp.arp_resolve(iface, iface.gateway, timeout=2, tries=1)
                if mac:
                    self.current_mac = mac
            except Exception:
                pass
        self.baseline_mac = self.current_mac
        self.alert = None

    # ---------- attacker identification ----------
    def _identify(self, mac: str) -> dict:
        mac = (mac or "").lower()
        ip = ""
        with STATE.lock:
            for d in STATE.devices.values():
                if d.mac and d.mac.lower() == mac:
                    ip = d.ip
                    break
        if not ip:
            # maybe seen in passive ARP observations (copy: the sniffer thread
            # writes _seen concurrently — iterating it live could raise)
            for oip, omac in list(self._seen.items()):
                if omac == mac:
                    ip = oip
                    break
        return {"mac": mac, "ip": ip, "vendor": vendors.lookup(mac)}

    def _raise(self, kind: str, message: str, attacker_mac: str, extra: dict | None = None):
        self.anomalies += 1
        attacker = self._identify(attacker_mac) if attacker_mac else None
        self.alert = {
            "type": kind, "message": message,
            "attacker": attacker, "ts": time.time(),
            **(extra or {}),
        }
        STATE.push_event("attack", message=message,
                         attacker=(attacker or {}).get("ip") or attacker_mac)
        # auto-heal if we have the static lock enabled
        try:
            if PROTECTION.locked:
                PROTECTION.heal()
        except Exception:
            pass

    # ---------- passive discovery ----------
    def _discover(self, ip: str, mac: str) -> None:
        """Learn devices from observed ARP (fills the list without active scan)."""
        iface = self.iface
        if not iface or ip == iface.ip:
            return
        try:
            if ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(iface.cidr, strict=False):
                return
        except Exception:
            return
        if STATE.get(ip) is not None:
            reset_ip = None
            with STATE.lock:
                d = STATE.devices.get(ip)
                if d:
                    d.online = True
                    d.last_seen = time.time()
                    # Identity change on the SAME IP (e.g. DHCP reassigned this
                    # address to a DIFFERENT device). Never let the new occupant
                    # inherit the previous device's enforcement/observation — that
                    # would blackhole a device the user never cut (the gateway-side
                    # ARP poison is IP-keyed). Re-key to the new MAC and reset to a
                    # clean, neutral, un-intercepted state. The gateway is EXCLUDED:
                    # its identity is guarded by the dedicated gateway-spoof
                    # detection and is never re-keyed from a passive ARP.
                    new = (mac or "").lower()
                    if (new and d.mac and d.mac.lower() != new
                            and ip != iface.gateway and not d.is_gateway):
                        d.mac = mac
                        d.mode = "allow"
                        d.down_kbps = 0
                        d.up_kbps = 0
                        d.blocked = []
                        d.services = []
                        d.monitor = False
                        if getattr(d, "blocked_ips", None):
                            d.blocked_ips.clear()
                        d.vendor = vendors.lookup(mac)
                        d.dtype = vendors.guess_type(d.vendor)
                        d.name = ""
                        d.hostname = ""
                        STATE.recompute_effective(d)
                        reset_ip = ip
            if reset_ip:
                # un-poison immediately so the new device's inbound traffic is not
                # held by the previous occupant's cut until the next full scan
                try:
                    from .spoofer import SPOOFER
                    SPOOFER.restore_device(reset_ip)
                except Exception:
                    pass
            return
        is_gw = (ip == iface.gateway)
        vendor = "Router / Gateway" if is_gw else vendors.lookup(mac)
        dtype = "router" if is_gw else vendors.guess_type(vendor)
        dev = STATE.upsert_device(ip, mac, vendor=vendor, dtype=dtype,
                                  is_gateway=is_gw, online=True)
        # apply any saved name
        try:
            p = db.load_devices().get(mac)
            if p and p.get("name"):
                dev.name = p["name"]
            if p and p.get("hostname"):
                dev.hostname = p["hostname"]
        except Exception:
            pass
        if is_gw and not dev.name:
            dev.name = "Gateway (Router)"
        STATE.push_event("new_device", ip=ip, mac=mac, vendor=vendor)

    # ---------- passive ARP handler ----------
    def _on_arp(self, fr) -> None:
        info = rawpkt.parse_arp(getattr(fr, "original", fr))
        if not info:
            return
        _op, sender_mac, sender_ip, _tm, _ti = info
        psrc = sender_ip
        hwsrc = (sender_mac or "").lower()
        if not psrc or not hwsrc:
            return
        # ignore our OWN ARP (scanning/spoofing) so it never counts as an attack
        my_mac = (self.iface.mac if self.iface else "").lower()
        if hwsrc == my_mac:
            return
        self._arp_times.append(time.time())
        self._discover(psrc, hwsrc)          # passive discovery
        gw = self.iface.gateway if self.iface else None

        # someone claiming to be the gateway with a wrong MAC
        if gw and psrc == gw and self.baseline_mac and hwsrc != self.baseline_mac:
            self._raise("gateway_spoof",
                        "Someone is impersonating the gateway (ARP spoofing).",
                        hwsrc, {"old": self.baseline_mac, "new": hwsrc})
            return

        # an IP suddenly mapping to a different MAC (generic spoof) — ARP reply only
        prev = self._seen.get(psrc)
        if prev and prev != hwsrc and _op == 2:
            self._raise("mac_conflict",
                        f"IP {psrc} changed MAC ({prev} -> {hwsrc}).", hwsrc,
                        {"ip": psrc, "old": prev, "new": hwsrc})
        else:
            self._seen[psrc] = hwsrc

        # ARP flood: a sustained burst of ARP from OTHER hosts (our own is ignored)
        now = time.time()
        recent = sum(1 for t in self._arp_times if now - t < 2)
        if recent > 250 and self.alert is None:
            self._raise("arp_flood", "ARP flood detected on the network.", "",
                        {"rate": recent})

    # ---------- active probe loop ----------
    def _loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            mac = arp.arp_resolve(self.iface, self.iface.gateway, timeout=2, tries=1)
            if not mac:
                continue
            self.current_mac = mac
            if self.baseline_mac and mac != self.baseline_mac and \
               (not self.alert or self.alert.get("type") == "arp_flood"):
                self._raise("gateway_mac_change",
                            "Gateway MAC changed — possible ARP spoofing.", mac,
                            {"old": self.baseline_mac, "new": mac})

    def status(self) -> dict:
        iface = self.iface or STATE.interface
        return {
            "active": self.active,
            "gateway_ip": iface.gateway if iface else "",
            "gateway_mac": self.baseline_mac or "",
            "current_mac": self.current_mac or "",
            "secure": self.alert is None,
            "anomalies": self.anomalies,
            "alert": self.alert,
            "protection": PROTECTION.status(),
        }


DEFENDER = Defender()
