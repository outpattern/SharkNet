"""
SharkNet launcher (desktop UI).

- Ensures the process is elevated (Administrator) -- required for raw packets.
- Checks that Npcap is installed; if not, opens the official download page
  (Npcap is an external prerequisite -- SharkNet does not bundle it).
- Starts the local engine server in a background thread.
- Opens the UI in a native desktop window (PyWebView / Edge WebView2).

No console window in the packaged build: status goes to a log file and any
blocking error is shown as a message box.
"""
from __future__ import annotations

import ctypes
import logging
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# In a windowed (console=False) build, sys.stdout/stderr are None. Many libs
# (uvicorn, click) call stream.isatty() and crash. Give them a real stream.
if sys.stdout is None or sys.stderr is None:
    _null = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = _null
    if sys.stderr is None:
        sys.stderr = _null

HOST = "127.0.0.1"
PORT = 8734  # may be bumped to a free port at startup
NPCAP_URL = "https://npcap.com/#download"
ROOT = Path(__file__).resolve().parent
FROZEN = getattr(sys, "frozen", False)


# ---------------- logging / user messages ----------------
def _log_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(ROOT)
    d = Path(base) / "SharkNet"
    d.mkdir(parents=True, exist_ok=True)
    return d / "sharknet.log"


logging.basicConfig(
    filename=str(_log_path()), level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("sharknet")


def info(msg: str) -> None:
    log.info(msg)
    if not FROZEN:
        print(f"[SharkNet] {msg}")


def msgbox(msg: str, title: str = "SharkNet") -> None:
    log.info(msg)
    try:
        ctypes.windll.user32.MessageBoxW(None, msg, title, 0x40)  # MB_ICONINFORMATION
    except Exception:
        if not FROZEN:
            print(f"[SharkNet] {msg}")


# ---------------- admin elevation ----------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    params = " ".join(f'"{a}"' for a in sys.argv[1:]) if FROZEN else \
             " ".join(f'"{a}"' for a in sys.argv)
    exe = sys.executable
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(ROOT), 1)


# ---------------- npcap check ----------------
def npcap_present() -> bool:
    """Npcap installed AND usable: the wpcap.dll library must be present (not
    merely the folder). SharkNet loads it at runtime via backend.engine._wpcap."""
    sysdir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    return (sysdir / "Npcap" / "wpcap.dll").exists() or (sysdir / "wpcap.dll").exists()


def ensure_npcap() -> bool:
    """Npcap is an EXTERNAL PREREQUISITE (SharkNet does not bundle it). If it is
    missing/unusable, refuse to start and direct the user to the official
    download — never silently continue without it."""
    if npcap_present():
        return True
    msgbox("Npcap is required but was not found on this PC.\n\n"
           "SharkNet needs the Npcap driver to capture/inject packets. Opening the "
           "official download page now — install it (default options), then start "
           "SharkNet again.")
    webbrowser.open(NPCAP_URL)
    return False


# ---------------- server ----------------
def pick_free_port(start: int = 8734, tries: int = 12) -> int:
    import socket
    for p in range(start, start + tries):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((HOST, p))
            s.close()
            return p
        except OSError:
            s.close()
            continue
    return start


def start_server() -> None:
    try:
        import uvicorn
        from backend.server import app
        # log_config=None avoids uvicorn's dictConfig (which touches stdout.isatty)
        config = uvicorn.Config(app, host=HOST, port=PORT,
                                log_level="warning", log_config=None)
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        server.run()
    except Exception:
        import traceback
        log.error("SERVER CRASH:\n" + traceback.format_exc())


def wait_for_server(timeout: float = 25.0) -> bool:
    """Robust readiness check: raw TCP connect (proxy/urllib-immune)."""
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            if s.connect_ex((HOST, PORT)) == 0:
                return True
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.3)
    return False


def _log_tail(n: int = 12) -> str:
    try:
        lines = _log_path().read_text(errors="ignore").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return ""


# ---------------- V3.1 runtime: tray + background + coordinated shutdown ----------------
class AppRuntime:
    """Owns the desktop-session lifecycle that V3.1 adds around the window:
    close-to-tray, restore (from the tray or a second launch), and ONE coordinated,
    idempotent shutdown shared by every exit path (window X, tray Exit, server
    shutdown, atexit).

    It is strictly a launcher/UX object: it never touches network policy. All
    teardown of engine state goes through backend.server.cleanup(), which is itself
    idempotent — this class only guarantees the *order* and that it runs once."""

    def __init__(self, guard=None, tray=None, get_settings=None, router=None,
                 toaster=None):
        self._window = None
        self._guard = guard
        self._tray = tray
        self._get_settings = get_settings or (lambda: {})
        self._router = router                 # NotificationRouter (presentation)
        self._toaster = toaster               # custom desktop toast window
        self._visible = True                  # REAL window state, not a preference
        self._exiting = threading.Event()     # a real quit was requested
        self._done = threading.Event()        # shutdown already ran
        self._lock = threading.Lock()

    def attach(self, window) -> None:
        self._window = window

    def attach_tray(self, tray) -> None:
        """Set after construction: the tray's menu callbacks are this object's
        methods, so the runtime has to exist first."""
        self._tray = tray

    def attach_notifications(self, router, toaster=None) -> None:
        self._router = router
        self._toaster = toaster
        self.set_visible(self._visible)

    # ---- window visibility: the ONLY source of truth for notification routing ----
    def set_visible(self, visible: bool) -> None:
        """Record the REAL window state and tell the notification router, so a
        notice is drawn in-app when the window is on screen and as a desktop toast
        when it is hidden/minimised/in the tray. Never derived from a setting."""
        self._visible = bool(visible)
        if self._router is not None:
            try:
                self._router.set_window_visible(self._visible)
            except Exception:
                pass
        try:
            from backend import server as _s
            _s.RUNTIME["window_visible"] = self._visible
        except Exception:
            pass
        # a visible window renders its own stack; drop any desktop cards
        if self._visible and self._toaster is not None:
            try:
                self._toaster.hide()
            except Exception:
                pass

    def is_visible(self) -> bool:
        return self._visible

    def on_minimized(self) -> None:
        self.set_visible(False)

    def on_restored(self) -> None:
        self.set_visible(True)

    # ---- background policy ----
    def keep_running_on_close(self) -> bool:
        """True when X should hide to the tray instead of quitting. Requires a live
        tray — without one, hiding would strand the app with no way back, so we
        quit (honest behavior beats a setting we can't honor)."""
        if self._exiting.is_set():
            return False
        if not (self._tray and self._tray.is_live()):
            return False
        try:
            s = self._get_settings() or {}
            return bool(s.get("tray", {}).get("keep_running_on_close"))
        except Exception:
            return False

    # ---- window ----
    def show_window(self) -> None:
        """Restore + focus the window. Called from the tray thread, the
        single-instance listener thread and a clicked desktop notification, so it
        must never raise. It only ever restores the EXISTING window."""
        self.set_visible(True)
        w = self._window
        if w is not None:
            for call in ("show", "restore"):
                try:
                    getattr(w, call)()
                except Exception:
                    pass
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, "SharkNet")
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)          # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass

    def hide_window(self) -> None:
        self.set_visible(False)
        w = self._window
        if w is None:
            return
        try:
            w.hide()
        except Exception:
            pass

    # ---- pywebview events ----
    def on_closing(self):
        """pywebview `closing` handler. Returning False cancels the close, which is
        how close-to-tray works; returning True lets the window be destroyed."""
        if self.keep_running_on_close():
            info("close -> staying in the background (tray)")
            self.hide_window()
            return False
        return True

    def on_closed(self) -> None:
        self.shutdown()

    # ---- exit paths ----
    def is_done(self) -> bool:
        return self._done.is_set()

    def request_exit(self) -> None:
        """Tray 'Exit': mark a real quit, then destroy the window so pywebview's
        loop ends. If there is no window (fallback mode) shut down directly."""
        self._exiting.set()
        w = self._window
        if w is None:
            self.shutdown()
            return
        try:
            w.destroy()          # -> pywebview fires closed -> shutdown()
        except Exception as e:
            log.error(f"window destroy failed: {e}")
            self.shutdown()

    def shutdown(self) -> None:
        """Idempotent coordinated teardown. Order matters: stop presentation first
        (tray + notification dispatch sink) so nothing tries to draw during engine
        teardown, then the engine, then release the instance guard last so a new
        launch can only win the guard once we are really finished."""
        with self._lock:
            if self._done.is_set():
                return
            self._done.set()
        info("shutting down")
        if self._router is not None:
            try:
                self._router.stop()          # drop any pending grouped burst
            except Exception as e:
                log.error(f"notification router stop failed: {e}")
        if self._toaster is not None:
            try:
                self._toaster.stop()         # destroy the desktop toast window
            except Exception as e:
                log.error(f"notification window stop failed: {e}")
        if self._tray:
            try:
                self._tray.stop()
            except Exception as e:
                log.error(f"tray stop failed: {e}")
        try:
            from backend.engine.notifications import MANAGER as NOTIFY
            NOTIFY.set_dispatch(None)    # the tray is gone; drop any queued toasts
        except Exception:
            pass
        try:
            # idempotent full engine teardown: restores ARP, stops every engine/
            # thread, and removes the static ARP lock (safe if never started)
            from backend.server import cleanup
            cleanup()
        except Exception as e:
            log.error(f"shutdown cleanup failed: {e}")
        if self._guard:
            try:
                self._guard.release()
            except Exception as e:
                log.error(f"instance guard release failed: {e}")


# ---------------- main ----------------
def main() -> None:
    if os.name != "nt":
        msgbox("SharkNet targets Windows.")
        return
    # LIMIT diagnostics: a command-line flag survives UAC elevation (argv is
    # forwarded to the elevated process; env vars are NOT). The forwarder also
    # honors the marker file %LOCALAPPDATA%\SharkNet\limit-debug.on.
    if "--limit-debug" in sys.argv:
        os.environ["SHARKNET_LIMIT_DEBUG"] = "1"
    # diagnostic mode: run the server in the foreground, no elevation/webview,
    # so import/startup errors surface directly. (SHARKNET_DIAG=1)
    if os.environ.get("SHARKNET_DIAG"):
        log.info("[DIAG] replicating threaded startup path...")
        threading.Thread(target=start_server, daemon=True).start()
        ok = wait_for_server()
        log.info(f"[DIAG] wait_for_server -> {ok}")
        if not ok:
            log.error("[DIAG] server did NOT come up in time")
        else:
            log.info("[DIAG] server up OK via threaded path")
        time.sleep(2)
        return
    if not is_admin():
        info("Requesting administrator privileges...")
        relaunch_as_admin()
        return

    # V3.1 single instance — HIGH PRIORITY: two ARP spoofers on one LAN is
    # dangerous. Claimed AFTER elevation (the pre-elevation process exits) and
    # BEFORE any UI/engine work, so a second launch just activates the first.
    from backend.single_instance import SingleInstance
    guard = SingleInstance()
    if not guard.acquire():
        info("SharkNet is already running — activating the existing window")
        guard.signal_existing()
        return

    if not ensure_npcap():
        guard.release()
        return

    # Consume the installer's one-time initial-language seed BEFORE the server
    # serves index.html, so a fresh install opens in the language chosen in Setup.
    # Fail-safe and locale-only: it can never affect the engine/adapters (an
    # upgrade with a saved language is left untouched — see settings.seed_*).
    try:
        from backend import settings as _settings
        _settings.seed_initial_language()
    except Exception as e:
        log.warning("initial-language seed skipped: %s", e)

    global PORT
    PORT = pick_free_port()
    info(f"starting engine on {HOST}:{PORT}")
    threading.Thread(target=start_server, daemon=True).start()
    if not wait_for_server():
        msgbox("SharkNet engine failed to start.\n\nLast log lines:\n"
               + _log_tail() + "\n\nFull log:\n" + str(_log_path()))
        guard.release()
        return

    def _apply_titlebar(is_dark: bool):
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, "SharkNet")
            if not hwnd:
                return
            val = ctypes.c_int(1 if is_dark else 0)
            for attr in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE (20 new, 19 old)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
            # force the title bar to repaint with the new colour
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0027)
        except Exception:
            pass

    class TitleBarApi:
        def __init__(self, toaster=None, get_lang=None):
            self._toaster = toaster
            self._get_lang = get_lang

        def set_theme(self, is_dark):
            _apply_titlebar(bool(is_dark))
            # Propagate the SAME authoritative theme (frontend applyTheme() -> this
            # api) to the desktop toast host, so a light-theme app shows light-theme
            # desktop notifications and switching updates them live. The toast's
            # language reuses the existing persisted locale — one source of truth,
            # no second theme/notification preference.
            try:
                if self._toaster is not None:
                    lang = self._get_lang() if self._get_lang else "en"
                    self._toaster.set_theme("dark" if is_dark else "light", lang)
            except Exception:
                pass
            return True

    def _initial_titlebar():
        time.sleep(1.2)
        _apply_titlebar(True)   # dark by default; UI re-syncs to its saved theme

    # ---- V3.1 tray + background runtime ----
    from backend import server as bserver
    from backend import settings as app_settings
    from backend.engine.notifications import MANAGER as NOTIFY
    from backend.notify_router import ROUTER as NOTIFY_ROUTER
    from backend.desktop_toast import DesktopToaster
    from backend.tray import TrayController

    settings = app_settings.load()
    runtime = AppRuntime(guard=guard, get_settings=app_settings.load)

    icon_file = ROOT / "assets" / "sharknet.ico"
    tray = TrayController(
        on_open=runtime.show_window,
        on_exit=runtime.request_exit,
        get_settings=app_settings.load,
        # the tray's Notifications toggle takes the SAME write path as the UI's, so
        # policy/autostart stay consistent no matter where the change came from
        save_settings=bserver.apply_settings_patch,
        # Tray "Cut Others" / "Uncut Others" call the EXACT existing main-UI bulk
        # endpoints (same functions the HTTP routes call) — no duplicate logic,
        # no second state path. Shown only when STATE.controlling is True, the
        # same authoritative "usable LAN" flag that gates the main-UI buttons.
        on_cut_others=bserver.api_cut_all_except_me,
        on_uncut_others=bserver.api_stop_all,
        network_ready=lambda: bool(bserver.STATE.controlling),
        icon_path=str(icon_file) if icon_file.exists() else None,
        locale=str(settings.get("locale", "en")),
    )
    runtime.attach_tray(tray)
    tray_ok = tray.start()
    info(f"system tray: {'active' if tray_ok else 'unavailable (running windowed)'}")
    if tray_ok:
        # the ONLY OS-toast sink. Without a tray this stays None and notifications
        # are simply dropped — never an error, and never anything the engine waits on.
        NOTIFY.set_dispatch(tray.notify)
        # keep the tray's Notifications checkbox in sync with UI-side changes
        bserver.SETTINGS_LISTENERS.append(lambda _s: tray.refresh())
    bserver.RUNTIME["tray"] = bool(tray_ok)

    # ---- V3.1 notifications: ONE producer -> ONE router -> ONE renderer ----
    # The router already has the in-app sink (wired by the server). Here we add the
    # custom desktop renderer and, ONLY as a last resort, the native tray balloon.
    toaster = DesktopToaster(f"http://{HOST}:{PORT}/toast.html",
                             activate_cb=runtime.show_window)
    NOTIFY_ROUTER.set_sinks(
        desktop_sink=toaster.show,
        fallback_sink=(tray.notify if tray_ok else None),
    )
    runtime.attach_notifications(NOTIFY_ROUTER, toaster)
    # the manager dispatches into the router (set at server startup); make sure the
    # launcher's richer wiring is the one in force
    NOTIFY.set_dispatch(NOTIFY_ROUTER.dispatch)

    # a second launch pings the guard -> restore this window instead of starting
    # a second engine
    guard.start_listener(runtime.show_window)

    url = f"http://{HOST}:{PORT}/"
    try:
        import webview
        window = webview.create_window(
            "SharkNet", url, width=1180, height=820, min_size=(940, 660),
            # native window background = the SharkNet dark-deep ground, so the frame
            # shown before WebView2 first-paints is SharkNet-colored, not black
            # (item 10: eliminate the black startup flash at the native layer).
            background_color="#070810",
            js_api=TitleBarApi(
                toaster=toaster,
                get_lang=lambda: app_settings.load().get("locale", "en")),
        )
        runtime.attach(window)
        bserver.RUNTIME["windowed"] = True
        threading.Thread(target=_initial_titlebar, daemon=True).start()

        # closing -> may be vetoed (close-to-tray); closed -> the one shutdown path
        try:
            window.events.closing += runtime.on_closing
        except Exception as e:
            # older pywebview without a cancellable `closing` event: close always
            # quits (V3.0 behavior). Background mode then simply isn't offered.
            log.warning(f"close-to-tray unavailable on this pywebview: {e}")
        window.events.closed += runtime.on_closed
        # REAL window state drives notification routing (never a saved preference).
        # Not every pywebview version exposes all three, so each is optional —
        # show_window()/hide_window() already keep the flag correct on their own.
        try:
            window.events.minimized += runtime.on_minimized
        except Exception as e:
            log.info(f"no 'minimized' event on this pywebview: {e}")
        try:
            window.events.restored += runtime.on_restored
        except Exception as e:
            log.info(f"no 'restored' event on this pywebview: {e}")
        try:
            window.events.shown += runtime.on_restored
        except Exception as e:
            log.info(f"no 'shown' event on this pywebview: {e}")
        runtime.set_visible(True)
        webview.start()
        runtime.shutdown()      # belt-and-braces: idempotent, no-op if already done
    except Exception as e:
        log.error(f"PyWebView unavailable: {e}")
        webbrowser.open(url)
        try:
            while not runtime.is_done():
                time.sleep(1)
        finally:
            runtime.shutdown()


if __name__ == "__main__":
    main()
