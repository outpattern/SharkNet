"""
Device fingerprinting: quick TCP port scan + OS/type guess from open ports
and the IP TTL. On-demand (called from an API endpoint).
"""
from __future__ import annotations

import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

# port -> (label, os/device hint)
COMMON_PORTS = {
    22: ("SSH", "linux"),
    23: ("Telnet", "iot"),
    53: ("DNS", "router"),
    80: ("HTTP", ""),
    139: ("NetBIOS", "windows"),
    443: ("HTTPS", ""),
    445: ("SMB", "windows"),
    515: ("Printer", "printer"),
    548: ("AFP", "apple"),
    631: ("IPP/Print", "printer"),
    3389: ("RDP", "windows"),
    5000: ("UPnP", "iot"),
    5555: ("ADB", "android"),
    7000: ("AirPlay", "apple"),
    8009: ("Chromecast", "iot"),
    8080: ("HTTP-alt", ""),
    9100: ("JetDirect/Print", "printer"),
    62078: ("iPhone-sync", "apple"),
}


def _check_port(ip: str, port: int, timeout: float = 0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        s.close()
    return None


def _ttl(ip: str):
    try:
        out = subprocess.run(["ping", "-n", "1", "-w", "800", ip],
                             capture_output=True, text=True, timeout=3,
                             creationflags=0x08000000).stdout
        m = re.search(r"TTL[=:](\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


def _os_from_ttl(ttl):
    if ttl is None:
        return None
    if ttl > 128:
        return "network device"
    if ttl > 64:
        return "windows"
    return "linux/android/apple"


def fingerprint(ip: str) -> dict:
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(lambda p: _check_port(ip, p), COMMON_PORTS.keys()):
            if r:
                open_ports.append(r)
    open_ports.sort()
    services = [{"port": p, "name": COMMON_PORTS[p][0]} for p in open_ports]

    ttl = _ttl(ip)
    ttl_os = _os_from_ttl(ttl)

    # weigh OS hints from open ports
    hints = [COMMON_PORTS[p][1] for p in open_ports if COMMON_PORTS[p][1]]
    guess = None
    for key in ("windows", "apple", "android", "printer", "router", "linux", "iot"):
        if key in hints:
            guess = key
            break
    os_guess = guess or ttl_os or "unknown"

    return {
        "ip": ip,
        "ttl": ttl,
        "os_guess": os_guess,
        "open_ports": services,
    }
