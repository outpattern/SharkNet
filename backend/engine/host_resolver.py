"""
Device identity: resolve a friendly hostname for an IP via reverse DNS and,
on Windows, NetBIOS (nbtstat). Then build a friendly display name.

    MAC -> Vendor  +  IP -> Hostname  ->  friendly name
"""
from __future__ import annotations

import re
import socket
import subprocess


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        # strip local suffixes
        name = name.split(".")[0]
        return name
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


_NB_RE = re.compile(r"^\s*(\S+)\s+<00>\s+UNIQUE", re.MULTILINE)


def netbios_name(ip: str) -> str:
    try:
        out = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True, text=True, timeout=3,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        ).stdout
    except Exception:
        return ""
    m = _NB_RE.search(out)
    if m:
        nm = m.group(1).strip()
        if nm and nm != "*":
            return nm
    return ""


def resolve_hostname(ip: str) -> str:
    return reverse_dns(ip) or netbios_name(ip)


def friendly_name(vendor: str, hostname: str, dtype: str) -> str:
    """Build a human label when the user hasn't set one."""
    if hostname:
        return hostname
    v = (vendor or "").strip()
    if v and v.lower() not in ("unknown", ""):
        # shorten long vendor strings like "Samsung Electronics Co.,Ltd"
        short = re.split(r"[ ,]", v)[0]
        label = {
            "phone": "Phone", "computer": "PC", "console": "Console",
            "router": "Router", "iot": "Device",
        }.get(dtype, "Device")
        return f"{short} {label}"
    return ""
