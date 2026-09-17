"""
Shared application state: the selected interface, discovered devices and
their rules, plus live traffic counters. Thread-safe via a single lock.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    dtype: str = "unknown"
    hostname: str = ""          # resolved network hostname
    name: str = ""              # user-friendly label (defaults to hostname/ip)
    name_source: str = ""       # which source produced hostname (dhcp/mdns/...)
    is_gateway: bool = False
    is_self: bool = False
    online: bool = True
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # ENFORCEMENT rule
    mode: str = "allow"         # allow | limit | cut
    down_kbps: int = 0          # KB/s, 0 = unlimited
    up_kbps: int = 0

    # OBSERVATION intent (P0) — deliberately ORTHOGONAL to enforcement `mode`.
    # When True the device is intercepted (ARP-MITM) so its traffic is observed,
    # but it is NEVER dropped/limited/blocked by the act of monitoring. Set only by
    # the explicit per-device Monitor action (P1). Enforcement state must never
    # implicitly set this, and this must never imply CUT/LIMIT/BLOCK.
    monitor: bool = False       # observation: OFF (False) | MONITOR (True)

    # live traffic (bytes/sec)
    down_bps: float = 0.0
    up_bps: float = 0.0

    # domains
    domains: dict = field(default_factory=dict)   # domain -> last_seen ts
    blocked: list = field(default_factory=list)   # ad-hoc blocked domain keywords (device scope)
    services: list = field(default_factory=list)  # blocked SERVICE ids (device scope, Phase 7)

    # precomputed EFFECTIVE blocked-domain keywords for this device =
    # device ad-hoc domains ∪ device services ∪ network domains ∪ network services.
    # Maintained by recompute_effective() at mutation time so the enforcement hot
    # path never rebuilds it (no per-packet JSON/catalog work). policy reads this.
    eff_blocked: tuple = ()
    # scoped-QUIC pinning (Phase 7, D1-A): dest IPs a blocked domain resolved to
    # for THIS device -> expiry ts. Populated from observed DNS A answers; used to
    # drop UDP/443 (QUIC) to those IPs ONLY (never broad IP blocking). Bounded+TTL.
    blocked_ips: dict = field(default_factory=dict)
    # F3 retroactive enforcement: RECENT domain->(ips, expiry) resolutions observed
    # for this device WHILE it was managed, even for not-yet-blocked domains. When a
    # block is applied we pin the already-resolved IPs of the newly-blocked domain
    # immediately (existing connections), scoped + TTL'd. Bounded.
    recent_dns: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        # Build explicitly (NOT dataclasses.asdict): asdict deep-copies every
        # field, which means iterating self.domains — a dict the forwarder
        # thread mutates live. That race raises "dictionary changed size during
        # iteration" and would kill the 1 Hz broadcaster. We never stream
        # domains anyway (only the count), and len()/list() below are safe.
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor, "dtype": self.dtype,
            "hostname": self.hostname, "name": self.name, "name_source": self.name_source,
            "is_gateway": self.is_gateway, "is_self": self.is_self, "online": self.online,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "mode": self.mode, "down_kbps": self.down_kbps, "up_kbps": self.up_kbps,
            "down_bps": self.down_bps, "up_bps": self.up_bps,
            "blocked": list(self.blocked),
            "services": list(self.services),
            "monitor": bool(self.monitor),          # observation intent (OFF | MONITOR)
            "domain_count": len(self.domains),
            "label": self.name or self.hostname or self.ip,
        }


def is_managed(dev: "Device") -> bool:
    """ENFORCEMENT predicate: does this device have an active enforcement rule?
    (For "must this device be MITM'd" — enforcement OR observation — use
    is_intercepted, NOT this.) Managed if it has a rule (cut/limit), any
    device-scope domain/service block, OR any NETWORK-scope rule is active (a
    network-wide block must be enforced on every device, so every real device
    becomes managed). `allow` with
    no blocks and no network rule is never managed. self/gateway are NEVER managed.
    STATE.managed() and every enforcement engine use this same predicate so they
    can never disagree (the set we spoof == the set we forward)."""
    if dev.is_self or dev.is_gateway:
        return False
    # "hardcut" (V3.1) is an enforcement mode exactly like cut/limit for the purpose
    # of "must this device be MITM'd" — it is intercepted, poisoned and restored by
    # the SAME machinery. It differs ONLY in the forwarder hot path (blackhole drop,
    # no observation); ALLOW/LIMIT/CUT semantics are untouched.
    if dev.mode in ("cut", "limit", "hardcut") or dev.blocked or dev.services:
        return True
    return bool(STATE.net_services or STATE.net_domains)


def is_intercepted(dev: "Device") -> bool:
    """Single source of truth for "this device's traffic must be MITM'd" — the
    OBSERVATION-vs-ENFORCEMENT split (P0).

    A device is intercepted (ARP-poisoned + forwarded through us) if it either
      * needs ENFORCEMENT  -> is_managed(dev)  (cut/limit/block/service/network), OR
      * is under OBSERVATION -> dev.monitor    (explicit Monitor, no enforcement).

    Enforcement state no longer *implicitly* decides interception: an ALLOW device
    the user chose to Monitor is intercepted and observed, but `action_for` still
    returns FORWARD for it (never DROP/LIMIT). The spoofer and the forwarder both
    use THIS predicate, so the set we poison == the set we forward+observe.
    self/gateway are NEVER intercepted."""
    if dev.is_self or dev.is_gateway:
        return False
    return is_managed(dev) or bool(getattr(dev, "monitor", False))


class AppState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.interface = None          # netinfo.Interface
        self.devices: dict[str, Device] = {}   # keyed by ip
        self.scanning = False
        self.scanned = False                    # at least one scan completed
        self.enforcing = False
        self.controlling = False                # engine armed (Active vs Idle)
        # V3.1 opt-in persistence: saved disk rules are reapplied AT MOST ONCE per
        # control session (guard against re-seeding a device the user changed this
        # run). Reset when going Idle so a stop->start re-restores. Only consulted
        # when settings.restore_rules is True; default posture is untouched.
        self.rules_restored = False
        self.events: list[dict] = []            # transient UI notifications
        # ---- NETWORK-scope policy (Phase 7). SESSION-ONLY: never persisted, so
        # it can't silently become standing configuration (decision D4). A rule
        # here applies to ALL devices; effective per-device blocks = device ∪
        # network (union, most-restrictive wins — a device ALLOW can't override a
        # network BLOCK). See recompute_all_effective / policy.py.
        self.net_services: list[str] = []       # blocked SERVICE ids (network scope)
        self.net_domains: list[str] = []        # blocked ad-hoc domains (network scope)

    def push_event(self, kind: str, **data) -> None:
        with self.lock:
            self.events.append({"kind": kind, "ts": __import__("time").time(), **data})
            self.events = self.events[-20:]

    def drain_events(self) -> list[dict]:
        with self.lock:
            ev = self.events
            self.events = []
            return ev

    # ---- devices ----
    def upsert_device(self, ip: str, mac: str, **kw) -> Device:
        with self.lock:
            dev = self.devices.get(ip)
            if dev is None:
                dev = Device(ip=ip, mac=mac, **kw)
                self.devices[ip] = dev
            else:
                dev.mac = mac or dev.mac
                dev.last_seen = time.time()
                dev.online = True
                for k, v in kw.items():
                    setattr(dev, k, v)
            # A3 fix: every discovered/updated device must reflect the CURRENT
            # effective policy — otherwise a device found by the passive Defender
            # sniffer (outside a reconcile/scan) while a NETWORK rule is active is
            # is_managed==True but keeps eff_blocked==() and is never enforced.
            # recompute is cheap (small set union) and only runs on discovery/update.
            self.recompute_effective(dev)
            return dev

    def get(self, ip: str) -> Optional[Device]:
        with self.lock:
            return self.devices.get(ip)

    def managed(self) -> list[Device]:
        """Devices with an ENFORCEMENT rule (cut/limit/block/service/network).
        This is the enforcement set; use intercepted() for "who do we MITM"."""
        with self.lock:
            return [d for d in self.devices.values() if is_managed(d)]

    def intercepted(self) -> list[Device]:
        """Devices to MITM = ENFORCEMENT (managed) ∪ OBSERVATION (monitor). The
        spoofer poisons this set and the forwarder forwards+observes it; enforcement
        (drop/limit) is decided separately per packet by policy.action_for, so a
        monitored ALLOW device is observed but never dropped/limited."""
        with self.lock:
            return [d for d in self.devices.values() if is_intercepted(d)]

    # ---- effective-block precompute (Phase 7) ----
    def recompute_effective(self, dev: "Device") -> None:
        """Precompute dev.eff_blocked = union of device ad-hoc domains, device
        services' domains, network ad-hoc domains, and network services' domains.
        Called at mutation time (rule/block/service/network change) so the hot
        path only reads a tuple — never rebuilds it or touches the catalog/JSON.
        Also drops the scoped-QUIC pin set when the device is no longer blocking."""
        from .engine.services import CATALOG   # local import: no import-time cycle
        from .engine.domains import normalize_domain   # THE one canonical path (F3 item 6)
        eff = set(dev.blocked or [])
        eff |= set(self.net_domains or [])
        eff |= set(CATALOG.domains_for(dev.services))
        eff |= set(CATALOG.domains_for(self.net_services))
        # canonicalize every keyword the SAME way observed domains are, so the hot
        # path compares like-for-like (no www./trailing-dot/case mismatches).
        dev.eff_blocked = tuple(sorted({nd for d in eff if (nd := normalize_domain(d))}))
        if not dev.eff_blocked and dev.blocked_ips:
            dev.blocked_ips.clear()             # nothing blocked -> forget pinned IPs

    def recompute_all_effective(self) -> None:
        """Recompute every device's effective block set (after a NETWORK-scope
        change, which affects all devices). Holds the lock once."""
        with self.lock:
            for d in self.devices.values():
                self.recompute_effective(d)

    def network_active(self) -> bool:
        return bool(self.net_services or self.net_domains)

    def network_snapshot(self) -> dict:
        with self.lock:
            return {"services": list(self.net_services), "domains": list(self.net_domains)}

    def begin_scan(self) -> bool:
        """Atomically claim the scanning flag. Returns False if a scan is
        already running (closes the TOCTOU that allowed two concurrent scans)."""
        with self.lock:
            if self.scanning:
                return False
            self.scanning = True
            return True

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [d.to_dict() for d in self._sorted()]

    def _sorted(self) -> list[Device]:
        def key(d: Device):
            try:
                octets = tuple(int(x) for x in d.ip.split("."))
            except Exception:
                octets = (999,)
            return (not d.is_gateway, d.is_self, octets)
        return sorted(self.devices.values(), key=key)


STATE = AppState()
