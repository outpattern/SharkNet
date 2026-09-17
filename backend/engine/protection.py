"""
Anti-spoofing protection:
  - Static ARP Lock: pin the gateway's real MAC as a permanent ARP neighbor so
    this PC cannot be ARP-spoofed off the gateway.
  - Auto-Heal: re-apply the correct mapping if tampering is detected.

Uses `netsh interface ipv4 add/delete neighbors` (requires Administrator).
"""
from __future__ import annotations

import subprocess

_NOWINDOW = 0x08000000


def _netsh(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                           timeout=8, creationflags=_NOWINDOW)
        ok = r.returncode == 0
        return ok, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


def _dash(mac: str) -> str:
    return mac.replace(":", "-").lower()


class Protection:
    def __init__(self):
        self.locked = False
        self.iface_name = None
        self.gw_ip = None
        self.gw_mac = None

    def lock(self, iface_name: str, gw_ip: str, gw_mac: str) -> tuple[bool, str]:
        """Pin gateway MAC as a permanent (static) ARP entry."""
        if not (iface_name and gw_ip and gw_mac):
            return False, "missing gateway info"
        # remove any existing entry first, then add the static one
        _netsh(["interface", "ipv4", "delete", "neighbors", iface_name, gw_ip])
        ok, msg = _netsh(["interface", "ipv4", "add", "neighbors",
                          iface_name, gw_ip, _dash(gw_mac)])
        if ok:
            self.locked = True
            self.iface_name = iface_name
            self.gw_ip = gw_ip
            self.gw_mac = gw_mac.lower()
        return ok, msg

    def unlock(self) -> tuple[bool, str]:
        if not self.iface_name or not self.gw_ip:
            self.locked = False
            return True, "nothing to unlock"
        ok, msg = _netsh(["interface", "ipv4", "delete", "neighbors",
                          self.iface_name, self.gw_ip])
        self.locked = False
        return ok, msg

    def heal(self) -> bool:
        """Re-assert the correct static mapping (used on tamper detection)."""
        if not self.locked:
            return False
        ok, _ = self.lock(self.iface_name, self.gw_ip, self.gw_mac)
        return ok

    def status(self) -> dict:
        return {
            "locked": self.locked,
            "gateway_ip": self.gw_ip or "",
            "gateway_mac": self.gw_mac or "",
        }


PROTECTION = Protection()
