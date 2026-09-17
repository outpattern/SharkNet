"""
ARP scanner: sweeps the subnet with ARP requests and collects IP/MAC pairs.
Also loads persisted names/rules, resolves hostnames, and flags new devices.
Runs in a background thread; results are pushed into AppState.
"""
from __future__ import annotations

import logging
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor

from . import netinfo, vendors, host_resolver, arp
from .nameresolver import NAME_RESOLVER
from .. import db
from ..state import STATE, is_intercepted

# quiet by default (root logger is INFO); set SHARKNET level to DEBUG to surface
log = logging.getLogger("sharknet.engine")


def _scan_once(iface: "netinfo.Interface", timeout: float = 3.0) -> list[tuple[str, str]]:
    try:
        net = ipaddress.IPv4Network(iface.cidr, strict=False)
    except Exception:
        return []
    if net.num_addresses > 1024:
        base = ".".join(iface.ip.split(".")[:3])
        hosts = [f"{base}.{i}" for i in range(1, 255)]
    else:
        hosts = [str(h) for h in net.hosts()]
    # send + sniff + match (works on Wi-Fi too, unlike scapy's srp)
    found = arp.arp_scan(iface, hosts, timeout=timeout)
    return [(ip, mac) for ip, mac in found.items()]


def scan(on_update=None) -> None:
    iface = STATE.interface
    if iface is None:
        return
    # atomically claim the scanning flag; bail if a scan is already running
    # (closes the race where two rapid requests started two concurrent scans)
    if not STATE.begin_scan():
        return
    try:
        persisted = db.load_devices()
        known_macs = set(persisted)

        # fresh scan: clear the table each time (so devices that changed IP or
        # left the network don't linger). BUT snapshot this session's active
        # rules by MAC first so a mid-session "Refresh devices" never silently
        # drops an active CUT/LIMIT/BLOCK. (Persisted/disk rules are still NOT
        # auto-applied — a fresh session always starts `allow`; only rules set
        # during THIS run are carried across the refresh.)
        with STATE.lock:
            # carry EVERYTHING this session is doing to a device across the refresh:
            # enforcement (mode/limits/domain-block/service-block) AND observation
            # (monitor). Keyed by MAC; is_intercepted covers both so a monitored
            # ALLOW device (not is_managed) is preserved too.
            prior_rules = {d.mac: (d.mode, d.down_kbps, d.up_kbps,
                                   list(d.blocked), list(d.services), bool(d.monitor))
                           for d in STATE.devices.values()
                           if d.mac and not d.is_self and is_intercepted(d)}
            STATE.devices.clear()

        STATE.upsert_device(iface.ip, iface.mac, is_self=True,
                            vendor="This PC", dtype="computer", name="This PC (You)")
        results = _scan_once(iface)
        seen_ips = {iface.ip}
        touched = []

        for ip, mac in results:
            seen_ips.add(ip)
            is_gw = (ip == iface.gateway)
            vendor = "Router / Gateway" if is_gw else vendors.lookup(mac)
            dtype = "router" if is_gw else vendors.guess_type(vendor)
            prev = STATE.get(ip)
            is_new = (mac not in known_macs) and (prev is None)

            dev = STATE.upsert_device(ip, mac, vendor=vendor, dtype=dtype,
                                     is_gateway=is_gw, online=True)
            p = persisted.get(mac)
            if p:
                dev.name = p.get("name") or dev.name
                # seed the resolver with the previously-saved name (medium
                # priority) so a fresh weak rDNS can't downgrade it, but a fresh
                # DHCP/mDNS name still upgrades it.
                if p.get("hostname"):
                    NAME_RESOLVER.submit(mac, "saved", p["hostname"])
                    dev.hostname = NAME_RESOLVER.best(mac) or dev.hostname
                    dev.name_source = NAME_RESOLVER.source_of(mac)
                if p.get("first_seen"):
                    dev.first_seen = p["first_seen"]
            # carry this session's active rule + monitor across the refresh (see
            # above). We do NOT load rules from disk — only state set during this run.
            pr = prior_rules.get(mac)
            if pr:
                dev.mode, dev.down_kbps, dev.up_kbps, dev.blocked, dev.services, dev.monitor = pr
                STATE.recompute_effective(dev)   # rebuild eff_blocked (domain + service + network)
            if is_gw and not dev.name:
                dev.name = "Gateway (Router)"
            if is_new:
                STATE.push_event("new_device", ip=ip, mac=mac, vendor=vendor)
            touched.append(dev)

        with STATE.lock:
            for ip, dev in STATE.devices.items():
                if ip not in seen_ips and not dev.is_self:
                    dev.online = False

        # V3.1 OPT-IN persistence (default OFF): reapply the user's saved disk
        # rules to freshly-discovered devices, ONCE per control session. When the
        # setting is off this is a no-op and the safe fresh-session posture is
        # unchanged. Runs before the caller's reconcile() so the restored managed
        # set is enforced in the same pass. Never touches self/gateway.
        _maybe_restore_saved_rules()
    finally:
        STATE.scanning = False
        STATE.scanned = True
        if on_update:
            on_update()

    # prompt devices to announce mDNS names (namer sniffs the replies)
    try:
        from .namer import NAMER
        NAMER.probe()
    except Exception:
        pass

    # resolve hostnames + friendly names in the background (non-blocking)
    threading.Thread(target=_enrich, args=(touched, on_update), daemon=True).start()


_VALID_MODES = ("allow", "limit", "cut", "hardcut")


def _maybe_restore_saved_rules() -> None:
    """Reapply saved enforcement to known devices — ONLY when the user opted in
    (settings.restore_rules) and at most ONCE per control session.

    Reuses the existing persisted model (db.rules + db.domain_blocks); it does not
    introduce a parallel rules engine or a second source of truth. Services are
    not persisted, so they are not restored. Fails safe: any error leaves every
    device at its current (neutral) state — a diagnostics/persistence failure can
    never itself cut a device.
    """
    try:
        from .. import settings as app_settings
        if STATE.rules_restored:
            return
        if not bool(app_settings.load().get("restore_rules")):
            return
    except Exception:
        return
    # mark restored up-front so a mid-scan retry / concurrent scan can't double-run
    STATE.rules_restored = True
    try:
        saved_rules = db.load_rules()
        saved_blocked = db.load_blocked()
    except Exception as e:
        log.warning("restore_rules: could not read saved rules (%s)", e)
        return
    with STATE.lock:
        for dev in STATE.devices.values():
            if dev.is_self or dev.is_gateway or not dev.mac:
                continue          # self/gateway are never managed (unchanged guard)
            # Only SEED a device that is still neutral this session, so a rule the
            # user already set/cleared during this run is never clobbered.
            if dev.mode != "allow" or dev.blocked or dev.services or dev.monitor:
                continue
            r = saved_rules.get(dev.mac)
            b = saved_blocked.get(dev.mac)
            changed = False
            if r:
                mode = r.get("mode", "allow")
                if mode in _VALID_MODES and mode != "allow":   # never a destructive no-op
                    dev.mode = mode
                    dev.down_kbps = max(0, int(r.get("down_kbps") or 0))
                    dev.up_kbps = max(0, int(r.get("up_kbps") or 0))
                    changed = True
                elif mode not in _VALID_MODES:
                    log.warning("restore_rules: skipping bad mode %r for %s", mode, dev.mac)
            if b and isinstance(b, list):
                clean = [d for d in b if isinstance(d, str) and d]
                if clean:
                    dev.blocked = clean
                    changed = True
            if changed:
                STATE.recompute_effective(dev)


def _enrich(devices, on_update) -> None:
    def work(dev):
        if dev.is_self or dev.is_gateway:
            _persist(dev)
            return
        # Only probe the network when we still have no name (avoid unnecessary
        # rDNS/NetBIOS probes when a passive DHCP/mDNS name already arrived).
        # Feed the result through the priority resolver rather than overwriting.
        if not dev.hostname:
            nm, src = host_resolver.reverse_dns(dev.ip), "rdns"
            if not nm:
                nm, src = host_resolver.netbios_name(dev.ip), "netbios"
            if nm:
                NAME_RESOLVER.submit(dev.mac, src, nm)
                best = NAME_RESOLVER.best(dev.mac)
                if best:
                    dev.hostname = best
                    dev.name_source = NAME_RESOLVER.source_of(dev.mac)
        # NOTE: never invent a name (e.g. "Private Device") — the display label
        # falls back to hostname then IP. `name` is reserved for user renames.
        _persist(dev)

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(work, devices))
    if on_update:
        on_update()


def _persist(dev) -> None:
    try:
        db.save_device(dev.mac, dev.name, dev.vendor, dev.dtype,
                       dev.hostname, dev.first_seen, dev.last_seen)
    except Exception as e:
        log.debug("persist failed for %s: %s", dev.mac, e)
