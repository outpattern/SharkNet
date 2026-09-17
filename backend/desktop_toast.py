"""
Custom SharkNet desktop notification window (V3.1).

A single frameless, always-hidden-until-needed PyWebView window that renders the
SAME notification card as the in-app stack (frontend/toast.html -> h-notify.js),
so SharkNet never shows a native Windows balloon during normal operation.

Window rules (all enforced in _harden()):
  * WS_EX_NOACTIVATE  — showing a notification must NEVER steal focus or
    interrupt typing in another application
  * WS_EX_TOOLWINDOW  — hidden from the taskbar AND from Alt+Tab
  * WS_EX_TOPMOST     — above other windows, but only while it is visible
  * positioned in the Windows WORK AREA (respects the taskbar), bottom-right,
    DPI-aware because the work area is queried in physical pixels

Everything here is OPTIONAL and fail-safe: if PyWebView, the window, or the JS
bridge is unavailable, start()/show() return False and the router falls back to a
single native balloon. A notification failure can never affect monitoring or
enforcement.

The webview module is injected so the whole class is unit-testable without a
desktop, a display, or WebView2.
"""
from __future__ import annotations

import ctypes
import logging
import threading

log = logging.getLogger("sharknet.engine")

# Win32 extended styles
GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_TOPMOST = 0x00000008
WS_EX_NOACTIVATE = 0x08000000
# WS_EX_APPWINDOW forces a taskbar button (and a hover thumbnail) even when
# WS_EX_TOOLWINDOW is set — it WINS. WinForms sets it because its Form defaults to
# ShowInTaskbar=True, which is why TOOLWINDOW alone did not remove the second
# "SharkNet Notification" thumbnail. It must be CLEARED, not just have TOOLWINDOW
# added alongside it.
WS_EX_APPWINDOW = 0x00040000

SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040
HWND_TOPMOST = -1

SPI_GETWORKAREA = 0x0030

# DWM rounded window corners (Windows 11): soften the opaque host's outline.
DWMWA_WINDOW_CORNER_PREFERENCE = 33
DWMWCP_ROUND = 2

DEFAULT_WIDTH = 360
MARGIN = 14                 # gap from the work-area edges (12–16px anchor)
MIN_HEIGHT = 48
MAX_HEIGHT = 460            # ≥ three cards + gaps; clamps a pathological measure

# The host is an OPAQUE surface painted the SharkNet ground. WebView2 on this stack
# does not composite a transparent window to the desktop (verified: neither the
# TransparencyKey-less WinForms form nor a DWM sheet-of-glass shows the wallpaper —
# transparent HTML falls back to the form's white BackColor). An opaque ground sized
# EXACTLY to the card stack is what removes the white rectangle, the scrollbar and
# the oversized/blank host. The ground FOLLOWS the current SharkNet theme: the
# create-time background_color matches the theme known when the window is first made,
# and the page's theme-aware body (snTheme) paints over it for live switches.
GROUND = "#0a0a0f"          # == CSS --bg-deep (dark)
GROUND_LIGHT = "#eef0f5"    # == CSS --bg-deep (light)


def ground_for(theme: str) -> str:
    """The opaque host background for the given SharkNet theme (light/dark)."""
    return GROUND_LIGHT if str(theme) == "light" else GROUND


def toolwindow_exstyle(ex: int) -> int:
    """Pure transform of an extended-window-style bitmask into the notification
    host's target: add WS_EX_TOOLWINDOW|NOACTIVATE|TOPMOST and CLEAR WS_EX_APPWINDOW.

    Clearing APPWINDOW is the crux of the taskbar fix — WinForms sets it and it
    overrides TOOLWINDOW, so the observed live style 0x08050088 (TOOLWINDOW *and*
    APPWINDOW) still produced a taskbar thumbnail. This yields 0x08010088."""
    return (ex | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST) & ~WS_EX_APPWINDOW


class _RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def work_area() -> tuple[int, int, int, int]:
    """Primary monitor work area (excludes the taskbar), in physical pixels.
    Falls back to a sane desktop size if the call fails."""
    try:
        r = _RECT()
        if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0,
                                                      ctypes.byref(r), 0):
            return r.left, r.top, r.right, r.bottom
    except Exception:
        pass
    return 0, 0, 1920, 1040


def bottom_right(width: int, height: int) -> tuple[int, int]:
    """Top-left coordinate that places a width x height window at the bottom-right
    of the work area, with a margin. Stays on-screen for small work areas."""
    left, top, right, bottom = work_area()
    x = max(left, right - width - MARGIN)
    y = max(top, bottom - height - MARGIN)
    return x, y


class DesktopToaster:
    """Owns the notification window's lifecycle.

    `webview` is the pywebview module (injected for tests). `activate_cb` is
    called when the user clicks a card — it must restore the EXISTING SharkNet
    window (never spawn a second instance)."""

    def __init__(self, url: str, webview=None, activate_cb=None,
                 width: int = DEFAULT_WIDTH):
        self._url = url
        self._webview = webview
        self._activate = activate_cb
        self._width = width
        self._window = None
        self._lock = threading.RLock()
        self._stopped = False
        self._hidden = True
        # current SharkNet theme/lang, fed by the launcher from the SAME authoritative
        # applyTheme()/locale state as the main UI (never a separate preference). The
        # ground + card styling follow these so a light-theme toast is a light toast.
        self._theme = "dark"
        self._lang = "en"

    # ---------- the JS bridge object exposed to toast.html ----------
    class _Api:
        def __init__(self, activate_cb, empty_cb=None, reflow_cb=None):
            self._cb = activate_cb
            self._empty = empty_cb
            self._reflow = reflow_cb

        def activate(self):
            """Clicked notification -> restore the existing window."""
            try:
                if self._cb:
                    self._cb()
            except Exception as e:
                log.warning("notification activate failed: %s", e)
            return True

        def empty(self):
            """The card stack drained (last card auto-dismissed / closed) ->
            hide the host window so no ghost rectangle or shadow lingers on the
            desktop after the notification disappears."""
            try:
                if self._empty:
                    self._empty()
            except Exception as e:
                log.debug("notification empty hook failed: %s", e)
            return True

        def reflow(self, height):
            """The visible card count changed in the page (a card expired or a
            queued one was promoted) -> resize the host to hug the new stack,
            keeping the bottom-right anchor fixed so the stack grows UPWARD and
            shrinks from the TOP, never moving the bottom card."""
            try:
                if self._reflow:
                    self._reflow(height)
            except Exception as e:
                log.debug("notification reflow failed: %s", e)
            return True

    # ---------- lifecycle ----------
    def start(self) -> bool:
        """Create the hidden notification window. False if unavailable — the
        caller then falls back to a native balloon."""
        with self._lock:
            if self._stopped:
                return False
            if self._window is not None:
                return True
            wv = self._webview
            if wv is None:
                try:
                    import webview as wv           # noqa: PLC0415
                except Exception as e:
                    log.info("pywebview unavailable — no custom desktop toasts (%s)", e)
                    return False
                self._webview = wv
            x, y = bottom_right(self._width, 120)
            try:
                self._window = wv.create_window(
                    "SharkNet Notification", self._url,
                    width=self._width, height=120, x=x, y=y,
                    frameless=True, easy_drag=False, on_top=True,
                    focus=False,                   # never take focus
                    # OPAQUE host on the SharkNet ground for the CURRENT theme — NOT
                    # transparent=True, which exposes the WinForms form's white
                    # BackColor on this WebView2 stack (the white rectangle defect).
                    transparent=False, background_color=ground_for(self._theme),
                    hidden=True, resizable=False, minimized=False,
                    # pywebview's default min_size is (200,100); a single ~88px card
                    # would be clamped to 100 while the move used the un-clamped
                    # height, pushing the bottom edge DOWN ~12px (the bottom card
                    # jumped between 1 and 2 cards). Allow the host to be as short as
                    # one card so the bottom anchor stays fixed for every count.
                    min_size=(self._width, MIN_HEIGHT),
                    js_api=self._Api(self._activate, self.hide, self._reflow),
                )
            except Exception as e:
                log.warning("could not create the notification window: %s", e)
                self._window = None
                return False
            self._hidden = True
            return True

    # ---------- showing ----------
    def show(self, notice) -> bool:
        """Render one notice. Returns False if it could not be shown, so the
        caller can fall back. Never raises."""
        with self._lock:
            if self._stopped:
                return False
            if self._window is None and not self.start():
                return False
            win = self._window
        try:
            payload = {
                "title": str(getattr(notice, "title", "") or ""),
                "body": str(getattr(notice, "body", "") or ""),
                "category": str(getattr(notice, "category", "") or ""),
            }
            import json
            # apply the CURRENT theme/lang BEFORE rendering the card, so a freshly
            # created or previously-hidden host renders in the right theme (a
            # light-theme toast is a light toast), not the create-time default.
            win.evaluate_js("window.snTheme(%s,%s)"
                            % (json.dumps(self._theme), json.dumps(self._lang)))
            win.evaluate_js("window.snPush(%s)" % json.dumps(payload))
            self._resize_and_show(win)
            return True
        except Exception as e:
            log.warning("desktop notification render failed: %s", e)
            return False

    def _measure(self, win) -> int:
        """Exact rendered height of the card stack (CSS px == the window's DIP)."""
        height = 120
        try:
            h = win.evaluate_js("window.snHeight()")
            if isinstance(h, (int, float)) and h > 0:
                height = int(h)
        except Exception:
            pass
        return min(max(height, MIN_HEIGHT), MAX_HEIGHT)

    def _place(self, win, height: int) -> None:
        """Size the host to EXACTLY `height` and park it bottom-right of the work
        area. y = bottom - height - margin, so the BOTTOM edge is fixed: adding a
        card grows the window upward, removing one shrinks it from the top, and the
        bottom card never jumps."""
        try:
            win.resize(self._width, height)
        except Exception:
            pass
        x, y = bottom_right(self._width, height)
        try:
            win.move(x, y)
        except Exception:
            pass

    def _reflow(self, height) -> None:
        """JS bridge target: re-fit the already-visible host when the page's card
        count changes (expiry / promotion)."""
        with self._lock:
            win = self._window
            if win is None or self._stopped or self._hidden:
                return
        try:
            h = int(height)
        except (TypeError, ValueError):
            return
        self._place(win, min(max(h, MIN_HEIGHT), MAX_HEIGHT))

    def _resize_and_show(self, win) -> None:
        """Hug the card stack and park it bottom-right, without activating."""
        height = self._measure(win)
        self._place(win, height)
        if self._hidden:
            # Apply the tool-window ex-style while the window is STILL hidden, so
            # Windows never creates a taskbar button or Alt+Tab entry for it: a
            # button created on the FIRST show (before WS_EX_TOOLWINDOW is set)
            # would persist for the window's lifetime even after the style is
            # added later. This is the real fix for "SharkNet Notification" showing
            # up as a separate taskbar/Alt+Tab window.
            self._apply_exstyle(win)
            try:
                win.show()
            except Exception:
                pass
            self._hidden = False
        self._harden(win)
        self._round_corners(win)

    # ---------- Win32 hardening ----------
    def _apply_exstyle(self, win) -> None:
        """Add WS_EX_TOOLWINDOW|NOACTIVATE|TOPMOST AND clear WS_EX_APPWINDOW — no
        taskbar button, no Alt+Tab entry, no hover thumbnail, never activated.
        Clearing APPWINDOW is the crucial part: WinForms sets it (ShowInTaskbar) and
        it overrides TOOLWINDOW, so adding TOOLWINDOW alone left the second taskbar
        thumbnail. Must run while the window is hidden, before the first show, so
        the button/thumbnail is never registered. Also owns the toast to the main
        SharkNet window when known, so the shell can never treat it as its own app."""
        try:
            hwnd = self._hwnd(win)
            if not hwnd:
                return
            user32 = ctypes.windll.user32
            get_long = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
            set_long = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
            ex = get_long(hwnd, GWL_EXSTYLE)
            new = toolwindow_exstyle(ex)
            if new != ex:
                set_long(hwnd, GWL_EXSTYLE, new)
            # NOTE: deliberately NOT made an OWNED window (no owner HWND is set).
            # Windows hides an owned window whenever its owner is hidden or minimised
            # — but the desktop toast exists precisely for when the main SharkNet
            # window is hidden in the tray, so ownership would suppress the toast in
            # its main use case. Clearing WS_EX_APPWINDOW + WS_EX_TOOLWINDOW already
            # removes the taskbar button, the hover thumbnail and the Alt+Tab entry
            # (verified on the live HWND), with no coupling to the main window.
        except Exception as e:
            log.debug("notification ex-style failed: %s", e)

    def _harden(self, win) -> None:
        """Re-assert the ex-style and keep the window topmost without activating."""
        self._apply_exstyle(win)
        try:
            hwnd = self._hwnd(win)
            if not hwnd:
                return
            ctypes.windll.user32.SetWindowPos(
                hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW)
        except Exception as e:
            log.debug("notification window hardening failed: %s", e)

    def _round_corners(self, win) -> None:
        """Round the opaque host's outer corners on Windows 11 (no-op elsewhere)."""
        try:
            hwnd = self._hwnd(win)
            if not hwnd:
                return
            pref = ctypes.c_int(DWMWCP_ROUND)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_WINDOW_CORNER_PREFERENCE,
                ctypes.byref(pref), ctypes.sizeof(pref))
        except Exception as e:
            log.debug("notification corner rounding failed: %s", e)

    @staticmethod
    def _hwnd(win):
        """Best-effort handle lookup across pywebview versions."""
        for attr in ("native", "gui"):
            obj = getattr(win, attr, None)
            for h in ("Handle", "handle", "hwnd", "winfo_id"):
                v = getattr(obj, h, None)
                if v is None:
                    continue
                try:
                    v = v() if callable(v) else v
                    return int(v)
                except Exception:
                    continue
        try:
            return int(ctypes.windll.user32.FindWindowW(None, "SharkNet Notification"))
        except Exception:
            return 0

    def hide(self) -> None:
        with self._lock:
            win = self._window
        if win is None or self._hidden:
            return
        try:
            win.hide()
        except Exception:
            pass
        self._hidden = True

    def set_theme(self, theme: str, lang: str | None = None) -> None:
        """Feed the CURRENT SharkNet theme/lang (from the authoritative applyTheme()
        / locale state). Always STORED so the next-shown toast uses it even if the
        host isn't created yet; applied LIVE to a visible/hidden host so a running
        stack re-styles without a restart and without touching the queue."""
        with self._lock:
            self._theme = "light" if str(theme) == "light" else "dark"
            if lang is not None:
                self._lang = str(lang) or "en"
            win = self._window
        if win is None:
            return
        try:
            import json
            win.evaluate_js("window.snTheme(%s,%s)"
                            % (json.dumps(self._theme), json.dumps(self._lang)))
        except Exception:
            pass

    # ---------- shutdown ----------
    def stop(self) -> None:
        """Idempotent: destroy the notification window so nothing is orphaned.
        Safe if it was never created and safe from several shutdown paths."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
            win, self._window = self._window, None
        if win is None:
            return
        try:
            win.destroy()
        except Exception as e:
            log.debug("notification window destroy failed: %s", e)
