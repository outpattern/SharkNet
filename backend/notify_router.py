"""
Notification presentation router (V3.1).

ONE event -> ONE user-facing notification. The NotificationManager stays the
single producer (it already derives transitions from the pump snapshot, so there
is no second event engine); this module only decides WHICH renderer draws it:

        NotificationManager.feed()        <- the only producer
                   |
                   v
            NotificationRouter            <- this module (presentation only)
             /                \\
    window visible          window hidden / minimized / tray
             |                        |
             v                        v
      in-app toast             custom SharkNet desktop toast
      (WS -> frontend)         (frameless window; native balloon only if it fails)

Hard rules enforced here:
  * exactly one sink is called per notification — never in-app AND desktop, and
    never a custom toast AND the native Windows balloon;
  * ONE event -> ONE card. Notices are NEVER merged/aggregated into a "X new
    devices detected" summary — every device event is its own card. Storm
    protection lives upstream (the manager's transition diff) and downstream (the
    renderer's max-3-visible + bounded queue), not in a merge here;
  * the native balloon is a LAST-RESORT fallback, used only when the desktop
    renderer raises or is absent;
  * routing follows the REAL window state fed in by run.py's AppRuntime, never a
    stored preference;
  * every sink failure is swallowed: a notification can never disturb monitoring
    or enforcement.

This module contains no policy and no enforcement.
"""
from __future__ import annotations

import logging
import threading
from collections import deque

log = logging.getLogger("sharknet.engine")

# NOTE: visual burst-grouping was removed by request — new-device bursts now show
# as individual cards (capped/queued by the renderer), not a merged summary.
GROUPED_CATEGORY = "new_device"     # kept only for back-compat of the category name
_QUEUE_MAX = 32


class Notice:
    """One user-facing notification, renderer-agnostic."""
    __slots__ = ("category", "title", "body", "count")

    def __init__(self, category, title, body, count=1):
        self.category = category
        self.title = title
        self.body = body
        self.count = count

    def to_dict(self) -> dict:
        return {"category": self.category, "title": self.title,
                "body": self.body, "count": self.count}

    def __repr__(self):
        return f"Notice({self.category!r}, {self.title!r}, {self.body!r}, n={self.count})"

    def __eq__(self, other):
        return (isinstance(other, Notice) and self.category == other.category
                and self.title == other.title and self.body == other.body
                and self.count == other.count)


class NotificationRouter:
    """Routes notifications to exactly one renderer.

    Sinks are injected by the launcher:
      inapp_sink(notice)    -> queue it for the visible UI (WS payload)
      desktop_sink(notice)  -> draw the custom frameless desktop toast
      fallback_sink(title, body) -> native OS balloon; LAST RESORT only
    """

    def __init__(self, inapp_sink=None, desktop_sink=None, fallback_sink=None):
        self._inapp = inapp_sink
        self._desktop = desktop_sink
        self._fallback = fallback_sink
        self._lock = threading.RLock()
        self._visible = True           # assume visible until the launcher says otherwise
        self._stopped = False
        self.delivered: deque = deque(maxlen=_QUEUE_MAX)   # for tests/inspection

    # ---------- window state (fed by run.py AppRuntime — the real thing) ----------
    def set_window_visible(self, visible: bool) -> None:
        with self._lock:
            self._visible = bool(visible)

    def is_window_visible(self) -> bool:
        with self._lock:
            return self._visible

    # ---------- sinks ----------
    def set_sinks(self, inapp_sink=None, desktop_sink=None, fallback_sink=None) -> None:
        with self._lock:
            if inapp_sink is not None:
                self._inapp = inapp_sink
            if desktop_sink is not None:
                self._desktop = desktop_sink
            if fallback_sink is not None:
                self._fallback = fallback_sink

    # ---------- the NotificationManager dispatch sink ----------
    def dispatch(self, title: str, body: str, category: str | None = None) -> None:
        """Called by NotificationManager's worker thread. Never raises.

        Every event renders as its own card — there is no merge/aggregation. The
        renderer caps how many are visible (3) and queues the rest; the manager's
        transition diff already suppresses repeats, so this stays one-in one-out.
        """
        try:
            self._render(Notice(category or "", title or "", body or ""))
        except Exception as e:                    # never destabilise the engine
            log.debug("notification routing failed: %s", e)

    # ---------- routing: exactly one renderer ----------
    def _render(self, notice: Notice) -> None:
        with self._lock:
            visible = self._visible
            inapp, desktop, fallback = self._inapp, self._desktop, self._fallback
        self.delivered.append((("inapp" if visible else "desktop"), notice))
        if visible:
            # window is on screen -> in-app toast ONLY. No OS notification at all.
            self._safe(inapp, notice, "in-app")
            return
        # hidden / minimised / tray -> the custom desktop toast
        if desktop is not None:
            try:
                desktop(notice)
                return                       # rendered: never also raise a balloon
            except Exception as e:
                log.warning("custom desktop notification failed, falling back: %s", e)
        # LAST RESORT only — the custom renderer is missing or broke
        if fallback is not None:
            try:
                fallback(notice.title, notice.body)
            except Exception as e:
                log.debug("fallback notification failed: %s", e)

    @staticmethod
    def _safe(sink, notice, what) -> None:
        if sink is None:
            return
        try:
            sink(notice)
        except Exception as e:
            log.debug("%s notification sink failed: %s", what, e)

    # ---------- lifecycle ----------
    def stop(self) -> None:
        """Idempotent. No timers/buffers to tear down (grouping was removed); just
        mark stopped so a late dispatch is a harmless no-op path."""
        with self._lock:
            self._stopped = True


# process-wide router; sinks + window state are wired by run.py
ROUTER = NotificationRouter()
