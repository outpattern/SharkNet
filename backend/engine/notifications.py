"""
NotificationManager (V3.1) — event-driven Windows notifications.

STRICT LAYER BOUNDARY: this module turns EXISTING SharkNet events/state into
notifications. It NEVER touches network policy, enforcement, ARP, or packet
handling. The flow is one-way:

    pump tick (devices snapshot + drained events)
        -> NotificationManager.feed()          [cheap diff, on the caller's thread]
        -> should_notify(category)              [policy gate]
        -> enqueue                              [bounded queue]
        -> worker thread -> dispatch(title,body)  [the OS toast call, OFF the hot path]

Design guarantees (map to the V3.1 hard invariants):
  * feed() only diffs dicts and enqueues — it never blocks on the OS. The actual
    toast call runs on a daemon worker thread, so notification delivery can never
    delay the pump / WebSocket / API / packet engine (invariant 8).
  * dispatch failures are swallowed — a failed toast never crashes SharkNet
    (invariant: notification failure must not destabilize the engine).
  * NO second network monitor: transitions (offline/online, cut/hardcut/limit)
    are DERIVED by diffing the snapshots the pump already produces (invariant 9).
  * stop() is idempotent and part of the coordinated shutdown.

Notifications are NOT the source of truth for anything; dropping one is always safe.
"""
from __future__ import annotations

import logging
import os
import queue
import threading

log = logging.getLogger("sharknet.engine")


def _accepts_category(fn) -> bool:
    """True if `fn` can take the notification category as a third argument.
    Detected once at injection time so the hot path never inspects signatures and
    a legacy two-argument sink keeps working unchanged."""
    if fn is None:
        return False
    try:
        import inspect
        sig = inspect.signature(fn)
        params = [p for p in sig.parameters.values()
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        if any(p.kind == p.VAR_POSITIONAL for p in sig.parameters.values()):
            return True
        return len(params) >= 3
    except (TypeError, ValueError):
        return False

# Canonical notification categories. These map 1:1 to policy keys and to the
# real SharkNet signals (events + derived mode/online transitions) — no parallel
# event taxonomy is invented.
CATEGORIES = (
    "new_device", "device_offline", "device_online",
    "cut", "hardcut", "limit",
    "domain_block", "service_block",
    "monitor_started", "monitor_stopped",
    "speedtest", "security",
)

# Phase 7 default policy. Master switch + per-category + sound.
DEFAULT_POLICY = {
    "enabled": True,
    "sound": True,
    "new_device": True,
    "device_offline": True,
    "device_online": False,
    "cut": True,
    "hardcut": True,
    "limit": False,
    "domain_block": False,
    "service_block": False,
    "monitor_started": False,
    "monitor_stopped": False,
    "speedtest": False,
    "security": True,
}

_QUEUE_MAX = 64            # bounded — a notification storm never grows memory unbounded


class Notification:
    __slots__ = ("category", "title", "body")

    def __init__(self, category: str, title: str, body: str):
        self.category = category
        self.title = title
        self.body = body

    def __repr__(self) -> str:      # for test readability
        return f"Notification({self.category!r}, {self.title!r}, {self.body!r})"

    def __eq__(self, other) -> bool:
        return (isinstance(other, Notification) and self.category == other.category
                and self.title == other.title and self.body == other.body)


class NotificationManager:
    """Event/state -> notification policy -> async OS dispatch.

    `dispatch(title, body)` is injected (the pystray balloon in production, a
    recording fake in tests). `translate(key, **kw)` is an optional localizer;
    when absent, built-in English strings are used so the manager is fully usable
    (and testable) with zero UI/i18n coupling.
    """

    def __init__(self, dispatch=None, translate=None, policy=None):
        self._dispatch = dispatch          # fn(title, body[, category]) ; may be None (drop)
        self._dispatch_wants_category = _accepts_category(dispatch)
        self._translate = translate        # fn(key, **kw) -> str ; may be None (English)
        self._lock = threading.Lock()      # guards _policy; created before any set_policy
        self._policy = dict(DEFAULT_POLICY)
        if policy:
            self.set_policy(policy)
        self._q: "queue.Queue" = queue.Queue(maxsize=_QUEUE_MAX)
        self._prev: dict[str, dict] = {}   # key(ip) -> {"online":bool,"mode":str,"label":str}
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()

    # ---------- wiring ----------
    def set_dispatch(self, dispatch) -> None:
        """Inject the presentation sink (V3.1: the NotificationRouter, which then
        picks the in-app or desktop renderer). `dispatch` is
        fn(title, body[, category]) -> None, or None to drop notifications.

        The optional third argument is detected once here, so a plain two-argument
        sink (e.g. a tray balloon, or a recording fake in a test) still works.
        Safe to call before/after start(): the worker reads it per item, so the
        headless/server-only case (no launcher) simply drops silently."""
        self._dispatch = dispatch
        self._dispatch_wants_category = _accepts_category(dispatch)

    def set_translator(self, translate) -> None:
        """Inject fn(key, **kw) -> str|None used to localize notification text.
        None restores the built-in English strings."""
        self._translate = translate

    # ---------- policy ----------
    def set_policy(self, policy: dict) -> None:
        """Merge a (possibly partial) policy dict. Unknown keys ignored; values
        coerced to bool. Master `enabled`/`sound` respected."""
        if not isinstance(policy, dict):
            return
        with self._lock:
            for k, v in policy.items():
                if k in self._policy:
                    self._policy[k] = bool(v)

    def get_policy(self) -> dict:
        with self._lock:
            return dict(self._policy)

    def should_notify(self, category: str) -> bool:
        with self._lock:
            return bool(self._policy.get("enabled")) and bool(self._policy.get(category))

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="notif-worker", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        """Idempotent. Signals the worker and unblocks it with a sentinel."""
        self._stop.set()
        try:
            self._q.put_nowait(None)      # sentinel to wake a blocked get()
        except queue.Full:
            pass
        w = self._worker
        if w and w.is_alive() and w is not threading.current_thread():
            w.join(timeout=2.0)
        self._worker = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:              # sentinel
                continue
            # accept (category, title, body) and the older (title, body)
            if len(item) == 3:
                category, title, body = item
            else:
                title, body = item
                category = None
            try:
                if self._dispatch:
                    # the ONLY place a notification leaves the engine
                    if self._dispatch_wants_category:
                        self._dispatch(title, body, category)
                    else:
                        self._dispatch(title, body)
            except Exception as e:                # a failed toast never crashes SharkNet
                log.debug("notification dispatch failed: %s", e)

    # ---------- translation ----------
    def _t(self, key: str, **kw) -> str:
        if self._translate:
            try:
                s = self._translate(key, **kw)
                if s:
                    return s
            except Exception:
                pass
        s = _EN.get(key, key)
        try:
            return s.format(**kw) if kw else s
        except Exception:
            return s

    # ---------- the tap: called once per pump tick (NEVER blocks) ----------
    def feed(self, devices, events) -> list:
        """Diff the device snapshot + consume events, emit notifications for the
        enabled categories. Returns the list of Notification emitted (for tests);
        also enqueues them for async dispatch. Pure/cheap: dict diffing only.

        `devices` = list of device dicts (STATE.snapshot()); `events` = list of
        {kind, ...} (STATE.drain_events()). Self/gateway are ignored for
        device-centric notifications."""
        emitted: list = []
        if not bool(self._policy.get("enabled")):
            # still advance _prev so re-enabling later doesn't dump a backlog
            self._prev = self._snapshot_map(devices or [])
            return emitted

        fresh_ips: set = set()

        # 1) explicit EVENTS (authoritative, carry their own data)
        for ev in events or []:
            kind = (ev or {}).get("kind")
            if kind == "new_device" and self.should_notify("new_device"):
                ip = ev.get("ip", "")
                label = ev.get("vendor") or ip
                emitted.append(self._emit("new_device",
                                          self._t("notif.new_device.title"),
                                          self._body(label, ip)))
                fresh_ips.add(ip)
            elif kind == "attack" and self.should_notify("security"):
                msg = ev.get("message") or self._t("notif.security.body")
                emitted.append(self._emit("security",
                                          self._t("notif.security.title"), msg))

        # 2) DERIVED transitions (no second monitor — diff the snapshot we're given)
        cur = self._snapshot_map(devices or [])
        for ip, d in cur.items():
            if d.get("is_self") or d.get("is_gateway"):
                continue
            prev = self._prev.get(ip)
            label = d.get("label") or ip
            # offline / online transition
            if prev is not None and prev.get("online") and not d.get("online"):
                if self.should_notify("device_offline"):
                    emitted.append(self._emit("device_offline",
                                              self._t("notif.device_offline.title"),
                                              self._body(label, ip)))
            elif prev is not None and not prev.get("online") and d.get("online"):
                if self.should_notify("device_online"):
                    emitted.append(self._emit("device_online",
                                              self._t("notif.device_online.title"),
                                              self._body(label, ip)))
            # enforcement mode transition (cut / hardcut / limit)
            pmode = prev.get("mode") if prev else "allow"
            cmode = d.get("mode", "allow")
            if cmode != pmode and ip not in fresh_ips:
                if cmode == "cut" and self.should_notify("cut"):
                    emitted.append(self._emit("cut", self._t("notif.cut.title"),
                                              self._t("notif.cut.body", name=label)))
                elif cmode == "hardcut" and self.should_notify("hardcut"):
                    emitted.append(self._emit("hardcut", self._t("notif.hardcut.title"),
                                              self._t("notif.hardcut.body", name=label)))
                elif cmode == "limit" and self.should_notify("limit"):
                    emitted.append(self._emit("limit", self._t("notif.limit.title"),
                                              self._t("notif.limit.body", name=label)))
        self._prev = cur
        return emitted

    # ---------- helpers ----------
    @staticmethod
    def _snapshot_map(devices) -> dict:
        out = {}
        for d in devices:
            ip = d.get("ip")
            if not ip:
                continue
            out[ip] = {"online": bool(d.get("online", True)), "mode": d.get("mode", "allow"),
                       "label": d.get("label") or d.get("name") or d.get("hostname") or ip,
                       "is_self": bool(d.get("is_self")), "is_gateway": bool(d.get("is_gateway"))}
        return out

    def _body(self, label: str, ip: str) -> str:
        # never fabricate: if the label already IS the ip (no name), show just the ip
        if label and ip and label != ip:
            return f"{label}\n{ip}"
        return ip or label or ""

    def _emit(self, category: str, title: str, body: str) -> Notification:
        n = Notification(category, title, body)
        try:
            self._q.put_nowait((category, title, body))
        except queue.Full:
            pass          # storm protection: drop rather than block/grow
        return n


# Built-in English fallback strings (used when no translator is injected). The
# UI-facing i18n keys mirror these so the frontend/locale files can localize.
_EN = {
    "notif.new_device.title": "New device detected",
    "notif.device_offline.title": "Device offline",
    "notif.device_online.title": "Device online",
    "notif.cut.title": "Device blocked",
    "notif.cut.body": "{name} has been cut from the network.",
    "notif.hardcut.title": "Hard Cut",
    "notif.hardcut.body": "{name} has been completely cut from the network.",
    "notif.limit.title": "Device limited",
    "notif.limit.body": "{name}'s bandwidth is now limited.",
    "notif.security.title": "Security alert",
    "notif.security.body": "Suspicious network activity detected.",
}


# process-wide singleton (wired to a dispatcher at runtime by the launcher)
MANAGER = NotificationManager()
