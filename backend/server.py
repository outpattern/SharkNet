"""
SharkNet local server: FastAPI + WebSocket. Serves the UI, exposes control
actions, and streams live device/traffic state to the frontend.
"""
from __future__ import annotations

import asyncio
import atexit
import collections
import secrets
import threading
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .state import STATE, is_managed, is_intercepted
from . import db
from .engine import netinfo, scanner
from .engine.spoofer import SPOOFER
from .engine.forwarder import FORWARDER
from .engine.monitor import get_monitor
from .engine.defender import DEFENDER
from .engine.health import HEALTH
from .engine.protection import PROTECTION
from .engine.namer import NAMER
from .engine import fingerprint as fp_engine, speedtest as st_engine, recovery
from .engine import domains as domains_engine
from .engine.domains import normalize_domain
from .engine.services import CATALOG, block_signals
from .engine import sharkmac, macadapter
from .engine.notifications import MANAGER as NOTIFY      # V3.1 notification layer
from . import settings as app_settings                  # V3.1 settings store
from . import localization                              # V3.1 backend-side i18n loader
from .notify_router import ROUTER as NOTIFY_ROUTER, Notice   # V3.1 presentation router

import sys
if getattr(sys, "frozen", False):
    FRONTEND = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "frontend"
else:
    FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

SHARKNET_VERSION = "v3.2.0"

# V3.1: notices the router decided to show IN-APP (the window is visible). They
# ride the existing WS state tick — no second channel — and are drained once so a
# notice is delivered exactly once. Bounded: a storm can never grow memory.
_INAPP_TOASTS: "collections.deque" = collections.deque(maxlen=16)


def _queue_inapp(notice) -> None:
    """Router in-app sink. Presentation only; never touches policy."""
    try:
        _INAPP_TOASTS.append(notice.to_dict())
    except Exception:
        pass


def drain_inapp_toasts() -> list:
    out = []
    while _INAPP_TOASTS:
        out.append(_INAPP_TOASTS.popleft())
    return out
app = FastAPI(title="SharkNet")

# ---------------- local capability token ----------------
# The server binds to 127.0.0.1 only, but a malicious web page in the user's
# browser could still try to drive the API via DNS-rebinding or a cross-site
# WebSocket. We mint a random per-process token, inject it into index.html
# (only same-origin JS on our own page can read it), and require it on every
# /api call and on the WebSocket handshake. Cross-origin pages can neither read
# the token nor forge a local Origin, so they are rejected. No login UX.
API_TOKEN = secrets.token_urlsafe(24)


def _host_is_local(netloc: str) -> bool:
    host = netloc.split("@")[-1].rsplit(":", 1)[0].strip("[]").lower()
    return host in ("127.0.0.1", "localhost", "::1")


def _origin_ok(origin: str | None) -> bool:
    """A missing Origin (non-browser local client / same-origin GET) is allowed;
    a browser cross-origin request carries a foreign Origin and is rejected."""
    if not origin:
        return True
    try:
        return _host_is_local(urlparse(origin).netloc)
    except Exception:
        return False


@app.middleware("http")
async def _security_guard(request, call_next):
    if request.url.path.startswith("/api/"):
        if not _origin_ok(request.headers.get("origin")):
            return JSONResponse({"ok": False, "error": "cross-origin blocked"},
                                status_code=403)
        if request.headers.get("x-sharknet-token") != API_TOKEN:
            return JSONResponse({"ok": False, "error": "missing or invalid app token"},
                                status_code=403)
    return await call_next(request)


# ---------------- websocket manager ----------------
class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)
        await ws.send_json(self.state_msg())

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    def state_msg(self) -> dict:
        iface = STATE.interface
        return {
            "type": "state",
            "devices": STATE.snapshot(),
            "status": {
                "interface": iface.to_dict() if iface else None,
                "scanning": STATE.scanning,
                "enforcing": STATE.enforcing,
                "controlling": STATE.controlling,
                "version": SHARKNET_VERSION,
            },
            "health": HEALTH.status(),
            "defender": DEFENDER.status(),
            "network": STATE.network_snapshot(),
            "policy": _policy_summary(),
            "events": STATE.drain_events(),
            # V3.1: in-app notifications chosen by the presentation router. When
            # the window is hidden the router draws a desktop toast instead and
            # this stays empty, so an event is never shown twice.
            "toasts": drain_inapp_toasts(),
            "advice": _advice(),
        }

    async def broadcast(self) -> None:
        # Build the tick payload ONCE (this drains STATE.events). V3.1: feed the
        # NotificationManager REGARDLESS of whether a UI client is connected, so
        # notifications work in background mode (UI closed => no WS client). This
        # is the single event tap — no second network monitor. Notifications can
        # never destabilize the broadcaster (wrapped) or block it (feed() only
        # diffs + enqueues; the OS toast runs on the manager's own worker thread).
        try:
            msg = self.state_msg()
        except Exception:
            return  # a transient snapshot error must never kill the broadcaster
        try:
            NOTIFY.feed(msg.get("devices", []), msg.get("events", []))
        except Exception:
            pass
        if not self.clients:
            return
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


def _policy_summary() -> dict:
    """What the UI needs to make Network Health POLICY-AWARE (Phase 7, D5):
    whether SharkNet is actively enforcing and how many devices it is limiting/
    cutting, so a throughput reduction caused by OUR OWN policy is distinguished
    from a genuine network/device problem (never misreported as "poor network").
    Genuine reachability (gateway/DNS/internet) still comes from HEALTH untouched."""
    with STATE.lock:
        limited = sum(1 for d in STATE.devices.values() if d.mode == "limit")
        # "Cut" stat counts BOTH cut and hard cut (both = zero access); hardcut is
        # also reported on its own so the UI can distinguish the two if it wants.
        hardcut = sum(1 for d in STATE.devices.values() if d.mode == "hardcut")
        cut = sum(1 for d in STATE.devices.values() if d.mode in ("cut", "hardcut"))
        managed = sum(1 for d in STATE.devices.values() if is_managed(d))
        # OBSERVATION-only devices: monitored but with no enforcement rule (P0).
        # Reported separately so the UI never conflates observing with enforcing.
        monitored = sum(1 for d in STATE.devices.values()
                        if d.monitor and not is_managed(d))
    return {"enforcing": bool(STATE.enforcing), "controlling": bool(STATE.controlling),
            "limited": limited, "cut": cut, "hardcut": hardcut,
            "managed": managed, "monitored": monitored,
            "network": STATE.network_active()}


def _advice() -> list[dict]:
    """Context-aware hints for the UI (Wi-Fi limitation / topology)."""
    out = []
    if netinfo.pcap_driver() == "winpcap":
        out.append({
            "kind": "winpcap",
            "title": "WinPcap detected — please switch to Npcap",
            "text": "WinPcap (2013, unmaintained) is unreliable on Windows 10/11 and "
                    "causes intermittent scans, lag, and weak LIMIT. Uninstall WinPcap "
                    "and install Npcap for stable results.",
        })
    iface = STATE.interface
    if iface is None:
        return out
    if STATE.scanned and not STATE.scanning:
        with STATE.lock:
            controllable = [d for d in STATE.devices.values()
                            if d.online and not d.is_self and not d.is_gateway]
        if len(controllable) == 0:
            out.append({
                "kind": "topology",
                "title": "No other devices found",
                "text": "Your phones/other devices are likely on a different router "
                        "(behind NAT), which ARP can't reach. Connect this PC (by cable) "
                        "to the SAME network your devices are on, then scan again.",
            })
    return out


HUB = Hub()


# ---------------- enforcement reconciliation ----------------
# Serialize the engine start/stop transition. F1 runs reconcile() on daemon threads
# (_reconcile_async), and SPOOFER.start()'s ~6 s gateway-ARP resolve sets STATE.enforcing
# only when it completes — so two overlapping reconciles could both pass the (non-atomic)
# start guards and double-start the engine (leaking the first capture handle), or an async
# start could finish AFTER an explicit Stop and re-arm the ARP poison. One lock across the
# whole decision+transition makes each reconcile observe the latest STATE and act once.
_reconcile_lock = threading.Lock()


def reconcile() -> str | None:
    """Start/stop the MITM engine based on whether any device is INTERCEPTED
    (enforcement ∪ observation — P0). The engine is the same for both; whether a
    given packet is dropped/limited or merely forwarded+observed is decided per
    packet by policy.action_for. Returns an error string if the engine could not
    start (e.g. no Npcap). Serialized by _reconcile_lock so overlapping async
    reconciles can't double-start the engine or re-arm after Stop."""
    import os
    if os.environ.get("SHARKNET_DEMO"):
        return None  # UI-only preview: never touch the network
    with _reconcile_lock:
        # a NETWORK-scope rule makes every device managed, and a fresh scan may have
        # added devices since the last change -> refresh effective blocks for all so
        # newly-seen devices pick up the network rule. Off the hot path (scan/rule
        # changes only), and only when a network rule actually exists.
        if STATE.network_active():
            STATE.recompute_all_effective()
        intercepted = STATE.intercepted()      # managed (enforce) ∪ monitored (observe)
        try:
            if intercepted and not STATE.enforcing:
                SPOOFER.start()        # take the MITM position (ARP spoof)
                FORWARDER.start()      # userspace forward + policy (enforce or observe-only)
                get_monitor().start()
            elif not intercepted and STATE.enforcing:
                FORWARDER.stop()
                SPOOFER.stop()
        except Exception as e:
            # roll back so we don't claim to be enforcing
            try:
                FORWARDER.stop(); SPOOFER.stop()
            except Exception:
                pass
            return str(e)
    return None


def _reconcile_async() -> None:
    """Run reconcile() OFF the request thread (Phase 7 F1). The FIRST block/rule
    that makes a device managed starts the MITM engine, and SPOOFER.start() does
    a blocking gateway-ARP resolve (up to ~6 s) — which used to stall the Block
    response. The rule mutation is already applied + persisted before this runs,
    so the response is honest ("rule stored"); if the engine cannot actually
    start, we surface it as an event (never a fake success). Idempotent: the
    spoofer/forwarder start()s guard against a second concurrent start."""
    import os
    if os.environ.get("SHARKNET_DEMO"):
        reconcile()            # demo/tests: reconcile is a no-op — stay synchronous (no thread)
        return
    def _work():
        try:
            err = reconcile()
            if err:
                STATE.push_event("enforce_error", message=str(err))
        except Exception as e:
            STATE.push_event("enforce_error", message=str(e))
    threading.Thread(target=_work, daemon=True).start()


# ---------------- REST API ----------------
@app.get("/api/interfaces")
def api_interfaces():
    # only real network adapters: have a gateway and a routable IP (no APIPA/virtual)
    ifaces = [i.to_dict() for i in netinfo.list_interfaces()
              if i.gateway and not i.ip.startswith("169.254")]
    return {"interfaces": ifaces,
            "selected": STATE.interface.name if STATE.interface else None}


class IfaceReq(BaseModel):
    name: str


def stop_control() -> None:
    """Tear down everything and restore the network to normal (go Idle)."""
    try:
        with STATE.lock:
            for dev in STATE.devices.values():
                dev.mode = "allow"
                dev.down_bps = dev.up_bps = 0.0
                dev.services = []
                dev.monitor = False              # observation intent is session-only (P1)
                dev.blocked_ips.clear()
                STATE.recompute_effective(dev)
            # NETWORK-scope rules are session-only -> clear them when going Idle
            STATE.net_services = []
            STATE.net_domains = []
        reconcile()            # stops forwarder/spoofer + restores ARP
        FORWARDER.stop()
        SPOOFER.stop()
        DEFENDER.stop()
        NAMER.stop()
        PROTECTION.unlock()
    except Exception:
        pass
    STATE.controlling = False
    # allow opt-in rule restoration to run again on the next control session
    STATE.rules_restored = False


_cleanup_lock = threading.Lock()


def cleanup() -> None:
    """Idempotent full teardown of ALL network/background state — restores ARP,
    stops every engine + thread, and removes the static ARP lock. Safe to call
    multiple times and safe when nothing was ever started (partial init).
    Called on window close, server shutdown, and via atexit."""
    with _cleanup_lock:
        for stop in (
            NOTIFY_ROUTER.stop,    # V3.1: drop any pending grouped burst first
            NOTIFY.stop,           # V3.1: stop notification dispatch FIRST (Phase 12 order)
            FORWARDER.stop,        # stop the sniffer/socket
            SPOOFER.stop,          # restore every poisoned device's ARP
            DEFENDER.stop,
            NAMER.stop,
            HEALTH.stop,
            lambda: get_monitor().stop(),
            PROTECTION.unlock,     # remove the static ARP neighbor
        ):
            try:
                stop()
            except Exception:
                pass


atexit.register(cleanup)


@app.post("/api/interface")
def api_select_interface(req: IfaceReq):
    for i in netinfo.list_interfaces():
        if i.name == req.name:
            changed = STATE.interface is None or STATE.interface.name != i.name
            if changed:
                stop_control()            # switching NIC -> go Idle, restore
                with STATE.lock:
                    STATE.devices.clear()
            STATE.interface = i
            STATE.scanned = False
            return {"ok": True, "interface": i.to_dict()}
    return JSONResponse({"ok": False, "error": "interface not found"}, status_code=404)


@app.post("/api/control/start")
def api_control_start():
    if STATE.interface is None:
        return JSONResponse({"ok": False, "error": "no interface selected"}, status_code=400)
    STATE.controlling = True
    try:
        DEFENDER.stop(); DEFENDER.start()
        NAMER.stop(); NAMER.start()
    except Exception:
        pass
    if not STATE.scanning:
        threading.Thread(target=lambda: scanner.scan(on_update=reconcile), daemon=True).start()
    return {"ok": True}


@app.post("/api/control/stop")
def api_control_stop():
    stop_control()
    with STATE.lock:
        STATE.devices.clear()
    STATE.scanned = False
    return {"ok": True}


@app.post("/api/scan")
def api_scan():
    if STATE.interface is None:
        return JSONResponse({"ok": False, "error": "no interface selected"}, status_code=400)
    if STATE.scanning:
        return {"ok": True, "already": True}
    # re-discovers devices; the scanner preserves this session's active rules
    threading.Thread(target=lambda: scanner.scan(on_update=reconcile), daemon=True).start()
    return {"ok": True}


class RuleReq(BaseModel):
    ip: str
    mode: str            # allow | limit | cut
    down_kbps: int = 0
    up_kbps: int = 0


def _apply_device_rule(dev, mode: str, down_kbps: int, up_kbps: int) -> None:
    """Set a device's traffic mode + limits, recompute its effective blocks,
    persist, and restore ARP if it just left the INTERCEPTED set. Does NOT reconcile —
    the caller reconciles once (so a bulk op reconciles a single time). Uses
    is_intercepted so removing an enforcement rule does NOT un-intercept a device
    that is still being monitored (P0)."""
    was = is_intercepted(dev)
    dev.mode = mode if mode in ("allow", "limit", "cut", "hardcut") else "allow"
    dev.down_kbps = max(0, int(down_kbps))
    dev.up_kbps = max(0, int(up_kbps))
    if dev.mode in ("allow", "hardcut"):
        # allow: no rule. hard cut: intentionally not observed, so its live traffic
        # reads zero (the forwarder never counts its bytes). CUT is unchanged — it is
        # still counted, so a cut device keeps showing its blocked attempts.
        dev.down_bps = dev.up_bps = 0.0
    STATE.recompute_effective(dev)
    if was and STATE.enforcing and not is_intercepted(dev):
        SPOOFER.restore_device(dev.ip)
    db.save_rule(dev.mac, dev.mode, dev.down_kbps, dev.up_kbps)


@app.post("/api/rule")
def api_rule(req: RuleReq):
    dev = STATE.get(req.ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    if dev.is_self or dev.is_gateway:
        return JSONResponse({"ok": False, "error": "cannot manage self/gateway"}, status_code=400)
    _apply_device_rule(dev, req.mode, req.down_kbps, req.up_kbps)
    # F1: engine start/stop OFF the request thread. The first cut/limit starts the
    # spoofer, whose gateway-ARP resolve blocks up to ~6 s — doing it synchronously
    # froze the response. The rule is already applied + persisted (honest state); if
    # the engine can't actually start, that surfaces as an `enforce_error` event.
    # Same pattern the block/service/network endpoints already use.
    _reconcile_async()
    return {"ok": True, "device": dev.to_dict()}


class MonitorReq(BaseModel):
    ip: str
    on: bool = True


@app.post("/api/monitor")
def api_monitor(req: MonitorReq):
    """Explicit OBSERVATION intent (P1) — turn Monitor on/off for ONE device.

    Monitor intercepts the device (via the SAME ARP-MITM path) so its traffic is
    OBSERVED, but it is NEVER dropped/limited/blocked: enforcement `mode` and the
    block lists are left completely untouched. Monitor ⇒ ALLOW + observe. Turning
    it off, when no enforcement rule remains, restores the device's ARP cleanly and
    (if nothing else is intercepted) stops the engine. Session-only: not persisted,
    so it never survives a restart/engine-stop as stale state."""
    dev = STATE.get(req.ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    if dev.is_self or dev.is_gateway:
        return JSONResponse({"ok": False, "error": "cannot monitor self/gateway"}, status_code=400)
    was = is_intercepted(dev)
    dev.monitor = bool(req.on)                   # OBSERVATION ONLY — mode/blocked/services unchanged
    # turning Monitor OFF on a device with no enforcement rule -> stop intercepting it
    if was and STATE.enforcing and not is_intercepted(dev):
        SPOOFER.restore_device(dev.ip)
    # F1: start/stop the engine OFF the request thread (Monitor's first interception
    # otherwise blocks ~6 s on the gateway-ARP resolve). Errors surface as events.
    _reconcile_async()
    return {"ok": True, "device": dev.to_dict()}


class BulkRuleReq(BaseModel):
    ips: list[str]
    mode: str                # allow | limit | cut
    down_kbps: int = 0
    up_kbps: int = 0


@app.post("/api/bulk/rule")
def api_bulk_rule(req: BulkRuleReq):
    """Apply ONE action (allow|limit|cut|hardcut) to many selected devices, reconciling
    once. Returns a PER-DEVICE result so the UI never reports success for devices
    that failed — unknown/offline (disappeared mid-op), self/gateway, or an
    enforcement error. `ok` is true only when every requested device succeeded."""
    mode = req.mode if req.mode in ("allow", "limit", "cut", "hardcut") else "allow"
    results = []
    for ip in req.ips or []:
        dev = STATE.get(ip)
        if dev is None:
            results.append({"ip": ip, "ok": False, "error": "not found (offline?)"})
            continue
        if dev.is_self or dev.is_gateway:
            results.append({"ip": ip, "ok": False, "error": "cannot manage self/gateway"})
            continue
        try:
            _apply_device_rule(dev, mode, req.down_kbps, req.up_kbps)
            results.append({"ip": ip, "ok": True})
        except Exception as e:
            results.append({"ip": ip, "ok": False, "error": str(e)})
    _reconcile_async()          # F1: engine start/stop off the request thread (no ~6s block)
    applied = sum(1 for r in results if r["ok"])
    failed = len(results) - applied
    return {"ok": failed == 0, "results": results, "applied": applied, "failed": failed}


class RenameReq(BaseModel):
    ip: str
    name: str


@app.post("/api/rename")
def api_rename(req: RenameReq):
    dev = STATE.get(req.ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    dev.name = req.name.strip()[:40]
    db.set_name(dev.mac, dev.name)
    return {"ok": True}


@app.post("/api/stop_all")
def api_stop_all():
    with STATE.lock:
        for dev in STATE.devices.values():
            dev.mode = "allow"
            dev.down_bps = dev.up_bps = 0.0
            db.save_rule(dev.mac, "allow", 0, 0)
    reconcile()  # will stop enforcing + restore all
    return {"ok": True}


@app.post("/api/cut_all_except_me")
def api_cut_all_except_me():
    """Cut every online device except this PC and the gateway."""
    with STATE.lock:
        for dev in STATE.devices.values():
            if dev.is_self or dev.is_gateway or not dev.online:
                continue
            dev.mode = "cut"
            db.save_rule(dev.mac, "cut", 0, 0)
    err = reconcile()
    if err:
        return JSONResponse({"ok": False, "error": err}, status_code=500)
    return {"ok": True}


@app.post("/api/defender/ack")
def api_defender_ack():
    DEFENDER.acknowledge()
    return {"ok": True, "defender": DEFENDER.status()}


@app.get("/api/history/{ip}")
def api_history(ip: str, seconds: int = 600):
    dev = STATE.get(ip)
    if dev is None:
        return JSONResponse({"ok": False}, status_code=404)
    # live 10-minute window from the in-memory ring (covers cut/limit/block-only
    # and needs no SQLite reads). Real samples only — empty until the device is
    # managed and traffic has been observed.
    from .engine.history import HISTORY
    return {"ok": True, "history": HISTORY.get(dev.mac, seconds)}


class ProtReq(BaseModel):
    enable: bool


@app.post("/api/protection")
def api_protection(req: ProtReq):
    iface = STATE.interface
    if iface is None or not iface.gateway:
        return JSONResponse({"ok": False, "error": "no interface/gateway"}, status_code=400)
    if req.enable:
        gw_mac = DEFENDER.baseline_mac
        if not gw_mac:
            from .engine import arp as arp_engine
            gw_mac = arp_engine.arp_resolve(iface, iface.gateway, timeout=2, tries=2)
        if not gw_mac:
            return JSONResponse({"ok": False, "error": "could not resolve gateway MAC"}, status_code=500)
        ok, msg = PROTECTION.lock(iface.name, iface.gateway, gw_mac)
    else:
        ok, msg = PROTECTION.unlock()
    return {"ok": ok, "message": msg, "protection": PROTECTION.status()}


@app.get("/api/fingerprint/{ip}")
def api_fingerprint_get(ip: str):
    dev = STATE.get(ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    return {"ok": True, "result": fp_engine.fingerprint(ip)}


@app.get("/api/speedtest")
def api_speedtest():
    return {"ok": True, "result": st_engine.run()}


@app.get("/api/domains/presets")
def api_domain_presets():
    return {"ok": True, "presets": domains_engine.PRESETS}


@app.get("/api/domains/{ip}")
def api_domains_get(ip: str):
    dev = STATE.get(ip)
    if dev is None:
        return JSONResponse({"ok": False}, status_code=404)
    # snapshot under the lock: the forwarder thread mutates dev.domains live
    with STATE.lock:
        visited = sorted(dev.domains.items(), key=lambda kv: kv[1], reverse=True)
        blocked = list(dev.blocked)
        services = list(dev.services)
    # tag each visited domain with the service it belongs to (identified vs
    # unknown) so the UI can classify traffic without extra round-trips
    vis = [{"domain": d, "ts": t, "service": CATALOG.identify(d)} for d, t in visited[:100]]
    return {"ok": True, "visited": vis, "blocked": blocked, "services": services}


class BlockReq(BaseModel):
    ip: str
    domains: list[str]


@app.post("/api/domains/block")
def api_domains_block(req: BlockReq):
    dev = STATE.get(req.ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    if dev.is_self or dev.is_gateway:
        return JSONResponse({"ok": False, "error": "cannot block self/gateway"}, status_code=400)
    # store CANONICAL domains (F3 item 6) so a rule typed as www./TRAILING-DOT/CASE
    # matches observed traffic; de-dupe while preserving order.
    clean = list(dict.fromkeys(d for d in (normalize_domain(x) for x in req.domains) if d))
    was_intercepted = is_intercepted(dev)
    dev.blocked = clean
    STATE.recompute_effective(dev)          # rule applied + effective set updated (synchronous)
    FORWARDER.pin_recent(dev)               # F3 retroactive: enforce already-resolved IPs immediately
    db.save_blocked(dev.mac, clean)
    # unblocking everything (and no cut/limit/service/network AND not monitored) ->
    # restore ARP so we stop intercepting a device we no longer need to touch
    if was_intercepted and STATE.enforcing and not is_intercepted(dev):
        SPOOFER.restore_device(dev.ip)
    _reconcile_async()                       # F1: engine start/stop off the request path
    return {"ok": True, "blocked": dev.blocked}


# ---------------- services (data-driven app/service blocking) ----------------
@app.get("/api/services")
def api_services():
    """The Service catalog (data-driven, backend/data/services.json). Metadata
    only — the UI groups by category/region and toggles by id."""
    return {"ok": True, "services": CATALOG.meta()}


class ServiceBlockReq(BaseModel):
    ip: str
    services: list[str]


@app.post("/api/services/block")
def api_services_block(req: ServiceBlockReq):
    """Set the blocked SERVICE ids for a device (device scope). Unknown ids are
    ignored. Effective blocks = device ∪ network (recomputed here)."""
    dev = STATE.get(req.ip)
    if dev is None:
        return JSONResponse({"ok": False, "error": "unknown device"}, status_code=404)
    if dev.is_self or dev.is_gateway:
        return JSONResponse({"ok": False, "error": "cannot block self/gateway"}, status_code=400)
    ids = [s.strip().lower() for s in req.services if s and CATALOG.exists(s)]
    was_intercepted = is_intercepted(dev)
    dev.services = ids
    STATE.recompute_effective(dev)          # rule applied + effective set updated (synchronous)
    FORWARDER.pin_recent(dev)               # F3: pin already-resolved IPs / unpin unblocked
    if was_intercepted and STATE.enforcing and not is_intercepted(dev):
        SPOOFER.restore_device(dev.ip)
    _reconcile_async()                       # F1: engine start/stop off the request path
    return {"ok": True, "services": dev.services,
            "signals": {s: block_signals(s) for s in dev.services}}


# ---------------- NETWORK-scope rules (session-only, decision D4) ----------------
@app.get("/api/network")
def api_network_get():
    return {"ok": True, "network": STATE.network_snapshot()}


class NetworkRuleReq(BaseModel):
    services: list[str] = []
    domains: list[str] = []


@app.post("/api/network/block")
def api_network_block(req: NetworkRuleReq):
    """Set the NETWORK-wide blocked services + domains (applies to ALL devices,
    union with each device's own rules — most-restrictive wins). Session-only:
    never persisted. Setting both lists empty clears the network scope."""
    ids = list(dict.fromkeys(s.strip().lower() for s in req.services if s and CATALOG.exists(s)))
    doms = list(dict.fromkeys(d for d in (normalize_domain(x) for x in req.domains) if d))  # canonical (F3 item 6)
    with STATE.lock:
        STATE.net_services = ids
        STATE.net_domains = doms
    STATE.recompute_all_effective()          # every device's effective set changes (synchronous)
    with STATE.lock:                          # F3: reconcile pins on every device (retro + cleanup)
        for d in STATE.devices.values():
            FORWARDER.pin_recent(d)
    _reconcile_async()                        # F1: spoof/forward the (now) managed set off-path
    return {"ok": True, "network": STATE.network_snapshot(),
            "signals": {s: block_signals(s) for s in ids}}


# ---------------- SHARKmac: MAC address manager ----------------
# SHARKmac is deliberately isolated from the Cut/Limit core. It only ever calls
# BACK into the session via the existing stop_control()/scanner.scan() — it holds
# no enforcement logic of its own. A successful change starts a brand-new session
# (fresh scan, rules cleared); a failed change auto-reverts the MAC and restores
# the previous session's rules (best effort), so a failure never costs the user
# their active cuts/limits.

@app.get("/api/mac/adapters")
def api_mac_adapters():
    return {"ok": True, "adapters": macadapter.list_adapters(),
            "selected_guid": _selected_guid()}


@app.get("/api/mac/vendors")
def api_mac_vendors(q: str = ""):
    return {"ok": True, "vendors": sharkmac.VENDORS.search(q)}


class MacGenReq(BaseModel):
    preset: str                      # random | vendor | custom
    vendor: str = ""
    mac: str = ""                    # for custom (echoed back validated)
    current: str = ""                # adapter's current MAC (client-supplied, to avoid it)


@app.post("/api/mac/generate")
def api_mac_generate(req: MacGenReq):
    # the client already knows the adapter's current MAC, so avoid a second
    # Get-NetAdapter round-trip here (keeps Generate instant)
    cur = sharkmac.normalize_mac(req.current) or ""
    avoid = {cur} if cur else set()
    if req.preset == "random":
        return {"ok": True, "mac": sharkmac.random_mac(avoid)}
    if req.preset == "vendor":
        m = sharkmac.VENDORS.generate(req.vendor, avoid)
        if not m:
            return {"ok": False, "error": "Unknown vendor."}
        return {"ok": True, "mac": m}
    if req.preset == "custom":
        ok, why = sharkmac.validate_for_apply(req.mac, current=cur)
        norm = sharkmac.normalize_mac(req.mac)
        return {"ok": ok, "mac": norm or req.mac, "error": "" if ok else why}
    return {"ok": False, "error": "Unknown preset."}


def _selected_guid() -> str:
    """GUID of the adapter SharkNet is currently bound to (best effort)."""
    iface = STATE.interface
    if not iface:
        return ""
    ad = macadapter.find_adapter(iface.name) or macadapter.find_adapter(iface.mac)
    return ad["guid"] if ad else ""


def _is_active_adapter(guid: str) -> bool:
    """True only if `guid` is the adapter SharkNet is currently enforcing on.
    Changing any OTHER adapter must NOT touch the active session/interface."""
    sg = _selected_guid()
    return bool(sg) and bool(guid) and sg.lower() == guid.lower()


def _snapshot_rules() -> dict:
    with STATE.lock:
        return {d.mac: (d.mode, d.down_kbps, d.up_kbps, list(d.blocked), list(d.services))
                for d in STATE.devices.values()
                if d.mac and not d.is_self and is_managed(d)}


def _reselect_interface(adapter_name: str) -> None:
    """After a MAC/IP change, re-read interfaces and re-bind to the same adapter
    (its IP may have changed via DHCP)."""
    try:
        for i in netinfo.list_interfaces():
            if i.name == adapter_name:
                STATE.interface = i
                return
    except Exception:
        pass


def _fresh_scan() -> None:
    STATE.scanned = False
    with STATE.lock:
        STATE.devices.clear()
    scanner.scan(on_update=reconcile)


def _restore_session(snapshot: dict, net_snap: dict | None = None) -> None:
    """Best-effort: re-scan and re-apply the pre-change rules by MAC (mode, limits,
    domain blocks, service blocks) plus the network-scope rules, then re-arm
    enforcement — used when a MAC change FAILED (keep the user's session)."""
    try:
        scanner.scan(on_update=None)
        with STATE.lock:
            if net_snap is not None:
                STATE.net_services = list(net_snap.get("services", []))
                STATE.net_domains = list(net_snap.get("domains", []))
            for dev in STATE.devices.values():
                pr = snapshot.get(dev.mac)
                if pr:
                    dev.mode, dev.down_kbps, dev.up_kbps, dev.blocked, dev.services = pr
                STATE.recompute_effective(dev)
        reconcile()
    except Exception:
        pass


def _run_mac_change(guid: str, mac: str, restore: bool) -> None:
    """Coordinator (runs in a background thread). restore=True means 'restore the
    adapter's original/permanent MAC' rather than apply `mac`.

    Only the adapter SharkNet is actively enforcing on resets the session; a
    change to any OTHER adapter is fully isolated — it never stops enforcement,
    never re-selects the interface, and never disturbs the device list."""
    ad = macadapter.find_adapter(guid, force=True)
    if not ad:
        STATE.push_event("mac_change_failed", message="Adapter not found.")
        return
    name = ad["name"]
    original = ad["permanent"] or ad["current"]
    target = original if restore else mac
    active = _is_active_adapter(guid)
    snapshot = _snapshot_rules() if active else {}
    net_snap = STATE.network_snapshot() if active else {}   # session-only net rules to restore on failure
    try:
        if active:
            stop_control()                # release the NIC we enforce on before bouncing it
        if restore:
            okw, msgw = macadapter.clear_mac(guid)
        else:
            okw, msgw = macadapter.set_mac(guid, target)
        if not okw:
            if active:
                _restore_session(snapshot, net_snap)
            STATE.push_event("mac_change_failed", message=msgw or "Could not write MAC.")
            return

        okc, msgc = macadapter.cycle_adapter(name)
        ok = okc if restore else (okc and macadapter.verify_effective(guid, target))

        if ok:
            eff = macadapter.effective_mac(guid)
            if active:
                _reselect_interface(name)
                _fresh_scan()             # brand-new session (only for the active NIC)
            STATE.push_event("mac_changed", adapter=name, mac=eff,
                             restored=restore, session_reset=active)
            return

        # FAILED -> auto-revert the TARGET adapter only; restore the session if
        # it was the active one.
        macadapter.clear_mac(guid)
        macadapter.cycle_adapter(name)
        reverted = macadapter.verify_effective(guid, original) if original else False
        if active:
            _reselect_interface(name)
            _restore_session(snapshot, net_snap)
        STATE.push_event("mac_change_failed",
                         message=(msgc or "The adapter did not accept the new MAC."),
                         reverted=reverted)
    except Exception as e:
        try:
            macadapter.clear_mac(guid); macadapter.cycle_adapter(name)
            if active:
                _reselect_interface(name); _restore_session(snapshot, net_snap)
        except Exception:
            pass
        STATE.push_event("mac_change_failed", message=f"Unexpected error: {e}")


class MacChangeReq(BaseModel):
    guid: str
    mac: str = ""
    restore: bool = False


@app.post("/api/mac/change")
def api_mac_change(req: MacChangeReq):
    import os
    if os.environ.get("SHARKNET_DEMO"):
        return JSONResponse({"ok": False, "error": "MAC change is disabled in demo mode."},
                            status_code=400)
    ad = macadapter.find_adapter(req.guid)
    if not ad:
        return JSONResponse({"ok": False, "error": "Adapter not found."}, status_code=404)
    if ad["capability"] == "unsupported":
        return JSONResponse({"ok": False, "error": ad["reason"]}, status_code=400)
    if not req.restore:
        ok, why = sharkmac.validate_for_apply(req.mac, current=ad["current"])
        if not ok:
            return JSONResponse({"ok": False, "error": why}, status_code=400)
    # long-running (adapter bounce ~6-10s) -> run in the background, report via events
    threading.Thread(target=_run_mac_change,
                     args=(req.guid, req.mac, req.restore), daemon=True).start()
    return {"ok": True, "started": True}


# ---------------- websocket ----------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # reject cross-site WebSocket hijacking + connections without the app token
    if ws.query_params.get("token") != API_TOKEN or not _origin_ok(ws.headers.get("origin")):
        await ws.close(code=1008)   # 1008 = policy violation
        return
    await HUB.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keepalive / ignore
    except WebSocketDisconnect:
        HUB.disconnect(ws)
    except Exception:
        HUB.disconnect(ws)


# ---------------- V3.1 settings + notification wiring ----------------
def _notif_translator(locale: str):
    """Return fn(key, **kw)->str localizing notif.* strings from the BUNDLED
    frontend i18n file for `locale` (so background notifications are localized even
    with the UI closed). Falls back to the manager's built-in English on any miss.
    Never raises. (The tray menu uses the same loader with the `tray.` prefix.)"""
    return localization.translator(locale, "notif.")


# Callables invoked (best-effort) after any settings change, so presentation-layer
# surfaces owned by the launcher can re-sync — e.g. the tray menu's Notifications
# checkbox when the toggle was flipped in the UI. Appended to by run.py; empty in
# headless runs. Listeners are UX-only and can never affect network policy.
SETTINGS_LISTENERS: list = []


def _apply_settings(s: dict) -> None:
    """Push persisted settings into the running notification subsystem (policy +
    locale). Tray/autostart are applied by the launcher. Never raises; the
    notification layer never affects network policy."""
    try:
        NOTIFY.set_policy(s.get("notifications", {}))
        NOTIFY.set_translator(_notif_translator(s.get("locale", "en")))
    except Exception:
        pass
    for fn in list(SETTINGS_LISTENERS):
        try:
            fn(s)
        except Exception:
            pass


# Launcher-owned runtime facts the UI must not guess. run.py fills these in; in a
# headless run they stay False, so the UI's background indicator reports the truth
# (no tray => closing really does quit) instead of assuming the tray exists.
RUNTIME = {"tray": False, "windowed": False, "window_visible": True}


@app.get("/api/runtime")
def api_runtime():
    """Background/tray capability + the effective close behavior, for the UI's
    status indicator. Presentation only."""
    s = app_settings.load()
    tray = bool(RUNTIME.get("tray"))
    return {
        "ok": True,
        "tray": tray,
        "windowed": bool(RUNTIME.get("windowed")),
        # REAL window state published by the launcher — drives notification
        # routing and the Runtime section's "Application mode" row.
        "window_visible": bool(RUNTIME.get("window_visible", True)),
        # background mode is only real when a tray icon actually exists to restore
        # from — otherwise closing the window ends the process.
        "background": tray and bool(s.get("tray", {}).get("keep_running_on_close")),
    }


# ---------------- Diagnostics (READ-ONLY; observes existing state/counters) ----
@app.get("/api/diagnostics")
def api_diagnostics():
    """One cheap read-only resource/workload sample. Presentation only — reads
    existing counters/state and this process's own metrics; never mutates any
    enforcement/monitor/interception state. Fails soft (fields become
    'Unavailable'), never raises into the request loop."""
    from . import diagnostics
    try:
        snap = diagnostics.snapshot()
    except Exception:
        snap = {}
    snap["version"] = SHARKNET_VERSION
    return {"ok": True, "diagnostics": snap}


@app.post("/api/diagnostics/perfcheck")
def api_diagnostics_perfcheck():
    """Observe the REAL current workload for ~12 s and summarise it. Runs in
    uvicorn's threadpool (sync endpoint), so it never blocks the event loop, the
    packet path, or enforcement. Generates NO traffic and changes NO state."""
    from . import diagnostics
    try:
        result = diagnostics.performance_check()
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    result["version"] = SHARKNET_VERSION
    return {"ok": True, "result": result}


@app.get("/api/settings")
def api_get_settings():
    return {"ok": True, "settings": app_settings.load()}


@app.post("/api/settings")
async def api_set_settings(request: Request):
    try:
        patch = await request.json()
    except Exception:
        patch = None
    if not isinstance(patch, dict):
        return JSONResponse({"ok": False, "error": "invalid settings"}, status_code=400)
    return {"ok": True, "settings": apply_settings_patch(patch)}


def apply_settings_patch(patch: dict) -> dict:
    """Persist a settings patch and make it take effect immediately. THE single
    write path — the HTTP endpoint and the tray's Notifications toggle both go
    through here, so the two can never drift apart. Returns the full settings."""
    s = app_settings.save(patch)
    _apply_settings(s)          # notification policy/locale take effect immediately
    try:
        app_settings.apply_autostart(bool(s.get("tray", {}).get("start_with_windows")))
    except Exception:
        pass
    return s


# ---------------- background broadcaster ----------------
def _seed_demo() -> None:
    """Populate fake devices for UI preview (no admin/Npcap needed).
    Enable with env var SHARKNET_DEMO=1."""
    import os
    if not os.environ.get("SHARKNET_DEMO"):
        return
    ifs = netinfo.list_interfaces()
    if ifs:
        STATE.interface = ifs[0]
    demo = [
        ("192.168.100.1", "78:eb:46:96:b2:be", "Router / Gateway", "router", True, False, "Gateway (Router)"),
        ("192.168.100.7", "04:d9:f5:08:0c:32", "This PC", "computer", False, True, "This PC (You)"),
        ("192.168.100.12", "f0:db:f8:11:22:33", "Apple", "phone", False, False, "Ahmed iPhone"),
        ("192.168.100.20", "f8:bc:12:aa:bb:cc", "Dell", "computer", False, False, "Work Laptop"),
        ("192.168.100.30", "84:25:db:44:55:66", "Samsung", "phone", False, False, "Smart TV"),
        ("192.168.100.41", "a8:e3:ee:77:88:99", "Sony (PlayStation)", "console", False, False, "PS5"),
    ]
    for ip, mac, vendor, dtype, gw, me, name in demo:
        STATE.upsert_device(ip, mac, vendor=vendor, dtype=dtype,
                            is_gateway=gw, is_self=me, name=name, online=True)


@app.on_event("startup")
async def _startup():
    _seed_demo()
    # crash-safe: if a previous run died while spoofing, heal those devices now
    try:
        healed = recovery.recover()
        if healed:
            STATE.push_event("recovered", message=f"Restored {healed} device(s) after a previous crash.")
    except Exception:
        pass
    # speed monitor + real-time network health always run
    get_monitor().start()
    try:
        HEALTH.start()
    except Exception:
        pass
    # V3.1: load persisted settings -> notification policy + locale, then start the
    # notification worker (async, non-blocking). The OS toast dispatch is wired by
    # the launcher (run.py); until then dispatch is a no-op, so this is safe here
    # and in headless/server-only runs.
    try:
        _apply_settings(app_settings.load())
        # ONE producer -> ONE router -> ONE renderer. run.py adds the desktop sink
        # and the real window-visibility feed; headless runs keep the in-app path
        # (the UI is a WS client), so behaviour is identical without a launcher.
        NOTIFY_ROUTER.set_sinks(inapp_sink=_queue_inapp)
        NOTIFY.set_dispatch(NOTIFY_ROUTER.dispatch)
        NOTIFY.start()
    except Exception:
        pass

    async def pump():
        while True:
            try:
                await HUB.broadcast()
            except Exception:
                pass  # keep the live-update loop alive no matter what
            await asyncio.sleep(1.0)

    asyncio.create_task(pump())


@app.on_event("shutdown")
def _shutdown():
    cleanup()


# ---------------- static frontend ----------------
@app.get("/")
def index():
    # inject the per-process token so only our own page's JS can call the API, and
    # the persisted locale as the FIRST-RUN language seed. The frontend uses the
    # seed only when the user has not chosen a language yet (empty localStorage);
    # once they pick one, localStorage/setLang() stay authoritative. This is how
    # the installer's initial-language choice reaches the very first paint without
    # a second language state.
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    try:
        lang = app_settings.load().get("locale") or "en"
    except Exception:
        lang = "en"
    html = html.replace("__SHARKNET_TOKEN__", API_TOKEN)
    html = html.replace("__SHARKNET_LANG__", lang)
    return HTMLResponse(html)


app.mount("/", StaticFiles(directory=str(FRONTEND)), name="static")
