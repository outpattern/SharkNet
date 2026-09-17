"""
Backend-side locale loading (V3.1).

The frontend owns localization, but two BACKGROUND surfaces need strings while the
UI is closed (so there is no JS runtime to ask):

  * notification toasts  (`notif.*`)  -- dispatched by the NotificationManager
  * the system-tray menu (`tray.*`)   -- built by backend/tray.py

Both read the SAME bundled `frontend/i18n/<locale>.json` files the UI uses, so
there is exactly one translation source; no parallel backend string table.

Pure I/O + dict filtering. Never raises, never touches network policy.
"""
from __future__ import annotations

import json
import logging
import os
import sys

log = logging.getLogger("sharknet.engine")


def locale_path(locale: str) -> str | None:
    """Absolute path of the bundled locale file, or None if it isn't there.
    Handles both the source tree and a PyInstaller bundle (`sys._MEIPASS`)."""
    name = f"{locale}.json"
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(here, "..", "frontend", "i18n", name)]
    base = getattr(sys, "_MEIPASS", None)
    if base:
        cands.append(os.path.join(base, "frontend", "i18n", name))
    for p in cands:
        if os.path.exists(p):
            return p
    return None


def load_table(locale: str, prefix: str) -> dict:
    """Return {key: string} for every flat key in `locale` starting with `prefix`.
    Empty dict on any failure (missing file, bad JSON) -- callers fall back to
    their own built-in English."""
    try:
        p = locale_path(locale)
        if not p:
            return {}
        with open(p, encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict):
            return {}
        return {k: v for k, v in d.items()
                if isinstance(k, str) and isinstance(v, str) and k.startswith(prefix)}
    except Exception as e:
        log.debug("locale load failed (%s/%s): %s", locale, prefix, e)
        return {}


def translator(locale: str, prefix: str):
    """Return fn(key, **kw) -> str|None. Returns None when the key is absent so the
    caller can apply its own fallback. `{name}`-style interpolation is applied when
    kwargs are given; a bad format string degrades to the raw string."""
    table = load_table(locale, prefix)

    def tr(key, **kw):
        s = table.get(key)
        if not s:
            return None
        try:
            return s.format(**kw) if kw else s
        except Exception:
            return s
    return tr
