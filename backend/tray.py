"""
System-tray controller (V3.1) — Windows notification-area icon, menu and balloons.

STRICT LAYER BOUNDARY (same rule as notifications.py): this module is pure
presentation/UX. It never touches network policy, enforcement, ARP or packets. It
owns exactly three things:

  * the tray icon + menu:  Open · Notifications (checkable) · Exit
  * the OS balloon sink the NotificationManager dispatches into
  * its own idempotent stop()

The pystray dependency is OPTIONAL and lazily imported: if pystray/Pillow are
missing (or we are off Windows, or in a test run), `start()` returns False and
SharkNet runs exactly as it did in V3.0 — windowed, no tray. Nothing here may be
load-bearing for the engine.

The backend module (pystray) and the icon loader are injectable so the whole
controller is testable without a display, a tray or the real library.
"""
from __future__ import annotations

import logging
import threading

from . import localization

log = logging.getLogger("sharknet.engine")

# Built-in English fallbacks for the menu (mirrored by the `tray.*` i18n keys, so
# the bundled locale files localize the menu while the UI is closed).
_EN = {
    "tray.open": "Open SharkNet",
    "tray.notifications": "Notifications",
    "tray.cut_others": "Cut Others",
    "tray.uncut_others": "Uncut Others",
    "tray.exit": "Exit",
}

# The hover tooltip is the product name — never translated, so it has no i18n key.
_TOOLTIP = "SharkNet"


def _load_pystray():
    """Import pystray lazily. Returns the module, or None when unavailable."""
    try:
        import pystray                       # noqa: PLC0415  (optional dependency)
        return pystray
    except Exception as e:
        log.info("pystray unavailable — running without a tray icon (%s)", e)
        return None


def _load_image(icon_path: str | None):
    """Load the tray image with Pillow. Falls back to a small generated square so a
    missing/corrupt .ico never prevents the tray from appearing. None if Pillow is
    unavailable."""
    try:
        from PIL import Image                # noqa: PLC0415  (optional dependency)
    except Exception as e:
        log.info("Pillow unavailable — no tray image (%s)", e)
        return None
    if icon_path:
        try:
            img = Image.open(icon_path)
            return img.convert("RGBA")
        except Exception as e:
            log.warning("tray icon %s unreadable (%s) — using fallback", icon_path, e)
    try:
        from PIL import Image as _I
        return _I.new("RGBA", (64, 64), (0, 212, 255, 255))   # SharkNet accent
    except Exception:
        return None


class TrayController:
    """Owns the tray icon lifecycle.

    Callbacks are injected by the launcher:
      on_open()   -> restore/focus the app window
      on_exit()   -> begin the coordinated shutdown
      get_settings() -> dict   (current persisted settings; for the checkbox state)
      save_settings(patch) -> None   (persist a settings patch)
      on_cut_others() / on_uncut_others() -> the EXACT existing main-UI bulk
          actions (server.api_cut_all_except_me / server.api_stop_all). The tray
          only exposes them; it never reimplements the bulk logic.
      network_ready() -> bool   (authoritative "usable LAN" state — the same
          STATE.controlling flag that shows/hides the main-UI buttons). When
          False the two items are HIDDEN entirely (not greyed out).
    """

    def __init__(self, on_open=None, on_exit=None, get_settings=None,
                 save_settings=None, icon_path=None, locale="en",
                 backend=None, image=None,
                 on_cut_others=None, on_uncut_others=None, network_ready=None):
        self._on_open = on_open
        self._on_exit = on_exit
        self._get_settings = get_settings
        self._save_settings = save_settings
        self._on_cut_others = on_cut_others
        self._on_uncut_others = on_uncut_others
        self._network_ready = network_ready
        self._icon_path = icon_path
        self._backend = backend                  # injected pystray (or a fake)
        self._image = image                      # injected image (or a fake)
        self._icon = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self._t = localization.translator(locale, "tray.")

    # ---------- i18n ----------
    def _label(self, key: str) -> str:
        try:
            s = self._t(key)
            if s:
                return s
        except Exception:
            pass
        return _EN.get(key, key)

    # ---------- settings-backed checkbox ----------
    def notifications_enabled(self) -> bool:
        """Master notification switch, read from the SAME settings store the UI and
        the NotificationManager use (no second source of truth)."""
        try:
            s = self._get_settings() if self._get_settings else {}
            return bool((s or {}).get("notifications", {}).get("enabled", True))
        except Exception:
            return True

    def toggle_notifications(self) -> bool:
        """Flip the master switch and persist it. Returns the new value. The save
        path is the normal settings API, so the running NotificationManager picks
        the change up exactly like a UI change would."""
        new = not self.notifications_enabled()
        try:
            if self._save_settings:
                self._save_settings({"notifications": {"enabled": new}})
        except Exception as e:
            log.warning("tray could not persist notification toggle: %s", e)
        self.refresh()
        return new

    # ---------- network readiness (authoritative, not "any adapter exists") ----
    def network_ready(self) -> bool:
        """True when SharkNet has a usable LAN context (engine armed) — the SAME
        condition that shows the main-UI Cut/Uncut Others buttons. The two tray
        items are shown only then; otherwise they are hidden completely."""
        if not (self._on_cut_others or self._on_uncut_others):
            return False
        try:
            return bool(self._network_ready()) if self._network_ready else False
        except Exception:
            return False

    # ---------- menu ----------
    def _build_menu(self, pystray):
        # Cut/Uncut Others are DYNAMIC items: pystray re-evaluates `visible` each
        # time the menu opens, so they appear/disappear as the network state
        # changes, with no separate detector and no greyed-out placeholder.
        ready = lambda _item: self.network_ready()   # noqa: E731
        # Two SEPARATORs bracket the dynamic pair. pystray automatically drops a
        # separator that is leading, trailing, or adjacent to another separator —
        # so when Cut/Uncut are hidden the two separators collapse and the menu
        # cleanly reads: Open · Notifications · --- · Exit (no greyed items).
        return pystray.Menu(
            pystray.MenuItem(self._label("tray.open"),
                             lambda *_: self._safe(self._on_open), default=True),
            pystray.MenuItem(self._label("tray.notifications"),
                             lambda *_: self.toggle_notifications(),
                             checked=lambda _item: self.notifications_enabled()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self._label("tray.cut_others"),
                             lambda *_: self._safe(self._on_cut_others),
                             visible=ready),
            pystray.MenuItem(self._label("tray.uncut_others"),
                             lambda *_: self._safe(self._on_uncut_others),
                             visible=ready),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self._label("tray.exit"),
                             lambda *_: self._safe(self._on_exit)),
        )

    @staticmethod
    def _safe(fn):
        """Run a menu callback without ever letting it kill the tray thread."""
        if not fn:
            return
        try:
            fn()
        except Exception as e:
            log.error("tray menu action failed: %s", e)

    # ---------- lifecycle ----------
    def start(self) -> bool:
        """Create and run the tray icon on its own daemon thread.
        Returns True if the tray is live, False if unavailable (missing pystray /
        Pillow / no tray). A False return is NOT an error — the app runs windowed."""
        if self._icon is not None:
            return True
        pystray = self._backend or _load_pystray()
        if pystray is None:
            return False
        image = self._image if self._image is not None else _load_image(self._icon_path)
        if image is None:
            return False
        try:
            self._icon = pystray.Icon("SharkNet", image, _TOOLTIP,
                                      self._build_menu(pystray))
        except Exception as e:
            log.error("tray icon creation failed: %s", e)
            self._icon = None
            return False
        self._stopped.clear()

        def _run():
            try:
                self._icon.run()
            except Exception as e:
                log.error("tray loop ended: %s", e)

        self._thread = threading.Thread(target=_run, name="tray", daemon=True)
        self._thread.start()
        return True

    def is_live(self) -> bool:
        """True when a tray icon actually exists right now. The launcher asks this
        before honoring close-to-tray — hiding the window with no tray to restore
        from would strand the user."""
        return self._icon is not None and not self._stopped.is_set()

    def refresh(self) -> None:
        """Ask the tray to re-evaluate the menu (checkbox state). Best-effort."""
        icon = self._icon
        if not icon:
            return
        try:
            icon.update_menu()
        except Exception:
            pass

    def notify(self, title: str, body: str) -> None:
        """OS balloon sink for the NotificationManager. Best-effort and silent on
        failure — a dropped toast must never disturb the engine."""
        icon = self._icon
        if not icon:
            return
        try:
            icon.notify(str(body or ""), str(title or "SharkNet"))
        except Exception as e:
            log.debug("tray notify failed: %s", e)

    def stop(self) -> None:
        """Idempotent: remove the icon and end its thread. Safe if never started and
        safe to call from several shutdown paths."""
        if self._stopped.is_set():
            return
        self._stopped.set()
        icon = self._icon
        self._icon = None
        if icon is not None:
            try:
                icon.visible = False
            except Exception:
                pass
            try:
                icon.stop()
            except Exception:
                pass
        th = self._thread
        self._thread = None
        if th and th.is_alive() and th is not threading.current_thread():
            th.join(timeout=2.0)
