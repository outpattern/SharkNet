"""
SQLite persistence. Keyed by MAC (stable across IP changes). Stored under
%LOCALAPPDATA%\\SharkNet.

Tables:
  * devices        — LIVE: device names/vendor/hostname round-trip (save/load) so a
                     device keeps its name across restarts.
  * rules,         — RESERVED: written on each mutation but intentionally NEVER
    domain_blocks    loaded. A fresh session always starts `allow` (no surprise-cut
                     on startup — see scanner.py); these persist the user's rules only
                     to reserve a future opt-in "remember rules across restart".
The old per-second `traffic` table was removed in V3.0: its reader (get_history) was
never wired to any UI — the live History chart is served from the in-memory ring
(engine/history.py), so the table was pure dead write pressure.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = Path(base) / "SharkNet"
    d.mkdir(parents=True, exist_ok=True)
    return d


DB_PATH = _data_dir() / "sharknet.db"

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def _c() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _init(_conn)
    return _conn


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            name TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            dtype TEXT DEFAULT 'unknown',
            hostname TEXT DEFAULT '',
            first_seen REAL,
            last_seen REAL
        );
        CREATE TABLE IF NOT EXISTS rules (
            mac TEXT PRIMARY KEY,
            mode TEXT DEFAULT 'allow',
            down_kbps INTEGER DEFAULT 0,
            up_kbps INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS domain_blocks (
            mac TEXT PRIMARY KEY, domains TEXT
        );
        """
    )
    conn.commit()


# ---------- devices ----------
def save_device(mac, name, vendor, dtype, hostname, first_seen, last_seen) -> None:
    if not mac:
        return
    with _lock:
        _c().execute(
            """INSERT INTO devices(mac,name,vendor,dtype,hostname,first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET
                 name=excluded.name, vendor=excluded.vendor, dtype=excluded.dtype,
                 hostname=excluded.hostname, last_seen=excluded.last_seen""",
            (mac, name, vendor, dtype, hostname, first_seen, last_seen),
        )
        _c().commit()


def load_devices() -> dict[str, dict]:
    with _lock:
        rows = _c().execute(
            "SELECT mac,name,vendor,dtype,hostname,first_seen,last_seen FROM devices"
        ).fetchall()
    out = {}
    for r in rows:
        out[r[0]] = dict(mac=r[0], name=r[1], vendor=r[2], dtype=r[3],
                         hostname=r[4], first_seen=r[5], last_seen=r[6])
    return out


def set_name(mac: str, name: str) -> None:
    with _lock:
        _c().execute("UPDATE devices SET name=? WHERE mac=?", (name, mac))
        _c().commit()


# ---------- rules ----------
def save_rule(mac: str, mode: str, down_kbps: int, up_kbps: int) -> None:
    if not mac:
        return
    with _lock:
        _c().execute(
            """INSERT INTO rules(mac,mode,down_kbps,up_kbps) VALUES(?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET
                 mode=excluded.mode, down_kbps=excluded.down_kbps, up_kbps=excluded.up_kbps""",
            (mac, mode, down_kbps, up_kbps),
        )
        _c().commit()


def load_rules() -> dict[str, dict]:
    with _lock:
        rows = _c().execute("SELECT mac,mode,down_kbps,up_kbps FROM rules").fetchall()
    return {r[0]: dict(mode=r[1], down_kbps=r[2], up_kbps=r[3]) for r in rows}


# ---------- domain blocks (reserved: written, intentionally not loaded — see header) ----------
def save_blocked(mac: str, domains: list) -> None:
    import json
    if not mac:
        return
    with _lock:
        _c().execute(
            """INSERT INTO domain_blocks(mac,domains) VALUES(?,?)
               ON CONFLICT(mac) DO UPDATE SET domains=excluded.domains""",
            (mac, json.dumps(domains)))
        _c().commit()


def load_blocked() -> dict[str, list]:
    import json
    with _lock:
        rows = _c().execute("SELECT mac,domains FROM domain_blocks").fetchall()
    out = {}
    for r in rows:
        try:
            out[r[0]] = json.loads(r[1]) or []
        except Exception:
            out[r[0]] = []
    return out
