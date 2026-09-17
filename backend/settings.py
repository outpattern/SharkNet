"""
SharkNet settings store (V3.1).

Until V3.1, all user preferences (theme/units/lang) lived in the frontend's
localStorage. V3.1 adds settings the BACKEND must read even when the UI is closed
(notification policy, tray/background behavior, and the locale for background
notification text), so they persist server-side as a small JSON file next to the
log/db under %LOCALAPPDATA%\\SharkNet.

This module is pure persistence + defaults + the Windows "start with Windows"
registry helper. It never touches network policy or enforcement.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

from .engine.notifications import DEFAULT_POLICY

log = logging.getLogger("sharknet.engine")

_APP_NAME = "SharkNet"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# Full default settings tree. `notifications` mirrors the NotificationManager
# policy so a single source drives both.
# the five shipped application locales (== frontend/i18n/*.json and i18n.js LANGS)
VALID_LOCALES = ("en", "ar", "es", "fr", "zh-CN")

DEFAULTS = {
    "locale": "en",
    # V3.1: OPT-IN persistent enforcement. OFF by default preserves the deliberate
    # safe-by-default posture (a fresh session starts every device at ALLOW; see
    # db.py header + scanner.py). When True, the rules the user saved on disk
    # (rules + domain_blocks tables) are reapplied to known devices once per
    # control session. Services are NOT part of the persisted model, so they are
    # never restored (see db.py).
    "restore_rules": False,
    "tray": {
        "start_with_windows": False,
        "keep_running_on_close": True,   # X -> minimize to tray (background) by default
        "minimize_to_tray": True,
    },
    "notifications": dict(DEFAULT_POLICY),
}

_lock = threading.RLock()


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = Path(base) / _APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path() -> Path:
    return _data_dir() / "settings.json"


def _deep_merge(base: dict, over: dict) -> dict:
    """Merge `over` onto a copy of `base`, one level deep for nested dicts. Unknown
    top-level keys in `over` are ignored so a corrupt/old file can't inject junk."""
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in (over or {}).items():
        if k not in out:
            continue
        if isinstance(out[k], dict) and isinstance(v, dict):
            for kk, vv in v.items():
                if kk in out[k]:
                    out[k][kk] = vv
        else:
            out[k] = v
    return out


def load() -> dict:
    """Return the persisted settings merged onto DEFAULTS. Never raises — a
    missing/corrupt file falls back to defaults (so settings can never crash
    startup)."""
    with _lock:
        try:
            raw = json.loads(_path().read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return _deep_merge(DEFAULTS, raw)
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("settings load failed (using defaults): %s", e)
        return _deep_merge(DEFAULTS, {})


def save(patch: dict) -> dict:
    """Merge `patch` onto the current settings, persist atomically, return the
    full new settings. Coerces booleans in known bool sections."""
    with _lock:
        cur = load()
        merged = _deep_merge(cur, patch or {})
        # coerce known booleans (notifications + tray) so the UI can't persist junk
        for section in ("notifications", "tray"):
            for k, v in list(merged.get(section, {}).items()):
                if isinstance(DEFAULTS[section].get(k), bool):
                    merged[section][k] = bool(v)
        # coerce top-level booleans (e.g. restore_rules) likewise
        for k in ("restore_rules",):
            if k in merged and isinstance(DEFAULTS.get(k), bool):
                merged[k] = bool(merged[k])
        try:
            tmp = _path().with_suffix(".json.tmp")
            tmp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
            os.replace(tmp, _path())       # atomic on Windows
        except Exception as e:
            log.warning("settings save failed: %s", e)
        return merged


# ---------------- installer "initial application language" seed ----------------
def _seed_path() -> Path:
    return _data_dir() / "initial-language.txt"


def seed_initial_language() -> str | None:
    """Consume the installer's one-time application-language seed.

    The Setup wizard (installer.iss) writes the chosen INITIAL language code to
    %LOCALAPPDATA%\\SharkNet\\initial-language.txt. This is applied to settings
    ONLY on a genuinely fresh profile (no settings.json yet), so an UPGRADE never
    overwrites the user's saved language (and the theme is untouched — the seed
    only carries a locale). The seed is ALWAYS removed after (consume once), and
    once consumed the runtime source of truth is the normal settings/locale +
    frontend model — no second language state is introduced.

    Returns the locale applied, or None. Never raises: a language-seed failure
    must never affect startup (engine, adapters, notifications are untouched)."""
    with _lock:
        seed = _seed_path()
        try:
            if not seed.exists():
                return None
            try:
                code = seed.read_text(encoding="utf-8").strip()
            except Exception:
                code = ""
            applied = None
            # fresh install only: no settings.json means the user has never run or
            # saved a preference, so the installer choice defines the first launch.
            if not _path().exists() and code in VALID_LOCALES:
                save({"locale": code})
                applied = code
                log.info("applied installer initial language: %s", code)
            return applied
        except Exception as e:
            log.warning("initial-language seed failed (using defaults): %s", e)
            return None
        finally:
            try:
                seed.unlink()
            except Exception:
                pass


# ---------------- "Start SharkNet with Windows" (HKCU Run key) ----------------
def apply_autostart(enable: bool, exe_path: str | None = None) -> bool:
    """Add/remove the per-user (HKCU) Run entry so SharkNet starts with Windows.
    Per-user (not HKLM) needs no extra privilege. Best-effort: returns True on
    success, False on any failure (never raises). No-op / False off Windows."""
    if os.name != "nt":
        return False
    try:
        import winreg
        import sys
        target = exe_path or (sys.executable if getattr(sys, "frozen", False) else None)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            if enable:
                if not target:
                    return False          # dev (python) — nothing sensible to register
                winreg.SetValueEx(key, _APP_NAME, 0, winreg.REG_SZ, f'"{target}"')
            else:
                try:
                    winreg.DeleteValue(key, _APP_NAME)
                except FileNotFoundError:
                    pass                  # already absent -> success
        return True
    except Exception as e:
        log.warning("autostart %s failed: %s", "enable" if enable else "disable", e)
        return False
