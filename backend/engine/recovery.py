"""
Crash-safe ARP restore.

While enforcing, the active spoof set (interface + gateway + targets) is written
to a small state file. On a clean stop it's cleared. If SharkNet starts and finds
that file still present, it means a previous run crashed while spoofing -- so we
re-send the correct ARP mappings to heal every target, then clear the file.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

STATE_FILE = Path(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")) / "SharkNet" / "active_spoof.json"


def save_active(iface, gateway_mac: str, targets: list[dict]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({
            "iface": {"name": iface.name, "mac": iface.mac,
                      "ip": iface.ip, "gateway": iface.gateway},
            "gateway_mac": gateway_mac,
            "targets": targets,   # [{"ip","mac"}]
        }))
    except Exception:
        pass


def clear_active() -> None:
    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
    except Exception:
        pass


def recover() -> int:
    """If a crash left targets spoofed, restore their ARP. Returns count healed."""
    if not STATE_FILE.exists():
        return 0
    try:
        data = json.loads(STATE_FILE.read_text())
    except Exception:
        clear_active()
        return 0
    iface = data.get("iface") or {}
    gw_ip = iface.get("gateway")
    gw_mac = data.get("gateway_mac")
    targets = data.get("targets") or []
    if not (iface.get("name") and gw_ip and gw_mac and targets):
        clear_active()
        return 0

    healed = 0
    try:
        from . import rawpkt
        from .iobackend import make_injector
        sock = make_injector(iface["name"])
        for _ in range(5):
            for t in targets:
                tip, tmac = t.get("ip"), t.get("mac")
                if not (tip and tmac):
                    continue
                # tell target: gateway is really at gw_mac
                sock.send(rawpkt.build_arp(tmac, gw_mac, 2, gw_mac, gw_ip, tmac, tip))
                # tell gateway: target is really at tmac
                sock.send(rawpkt.build_arp(gw_mac, tmac, 2, tmac, tip, gw_mac, gw_ip))
            time.sleep(0.2)
        sock.close()
        healed = len(targets)
    except Exception:
        pass
    clear_active()
    return healed
