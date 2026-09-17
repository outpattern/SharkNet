"""
Network information: enumerate interfaces, detect gateway + subnet.
Windows-focused (native GetAdaptersAddresses enumeration + `route print`).
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, asdict
from typing import Optional

import psutil
from . import winifaces


@dataclass
class Interface:
    name: str          # adapter friendly name
    description: str
    ip: str
    mac: str
    netmask: str
    gateway: str
    cidr: str          # e.g. 192.168.1.0/24
    is_wireless: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _looks_wireless(name: str, desc: str) -> bool:
    text = f"{name} {desc}".lower()
    return any(k in text for k in ("wi-fi", "wifi", "wireless", "802.11", "wlan"))


def pcap_driver() -> str:
    """Which capture driver is installed: 'npcap', 'winpcap', or 'none'."""
    import os
    sysdir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
    if os.path.isdir(os.path.join(sysdir, "Npcap")):
        return "npcap"
    if os.path.isfile(os.path.join(sysdir, "wpcap.dll")):
        return "winpcap"
    return "none"


def _default_gateways() -> dict[str, str]:
    """Map interface-IP -> gateway-IP by parsing `route print -4`."""
    gws: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True, text=True, timeout=8,
            creationflags=0x08000000,   # CREATE_NO_WINDOW (no CMD flash)
        ).stdout
    except Exception:
        return gws
    # Rows under "Active Routes": Dest Netmask Gateway Interface Metric
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway, iface_ip = parts[2], parts[3]
            if gateway not in ("On-link", "0.0.0.0"):
                gws[iface_ip] = gateway
    return gws


def _netmasks() -> dict[str, str]:
    """Map IPv4 -> netmask via psutil."""
    masks: dict[str, str] = {}
    for _name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            # AF_INET == 2
            if getattr(a, "family", None) == 2 and a.address and a.netmask:
                masks[a.address] = a.netmask
    return masks


def list_interfaces() -> list[Interface]:
    """Return active IPv4 interfaces that have an IP and a gateway."""
    gateways = _default_gateways()
    masks = _netmasks()
    result: list[Interface] = []

    for entry in winifaces.list_adapters():
        ips = entry.get("ips", []) or []
        ipv4 = next((i for i in ips if _is_ipv4(i)), None)
        if not ipv4:
            continue
        mac = (entry.get("mac") or "").lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        netmask = masks.get(ipv4, "255.255.255.0")
        gateway = gateways.get(ipv4, "")
        try:
            net = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
            cidr = str(net)
        except Exception:
            cidr = f"{ipv4}/24"
        name = entry.get("name", "")
        desc = entry.get("description", "")
        result.append(Interface(
            name=name, description=desc,
            ip=ipv4, mac=mac, netmask=netmask,
            gateway=gateway, cidr=cidr,
            is_wireless=_looks_wireless(name, desc),
        ))

    # Prefer interfaces with a gateway, and wired over wireless (ARP works on wired)
    result.sort(key=lambda i: (i.gateway == "", i.is_wireless, i.ip))
    return result


def _is_ipv4(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv4Address)
    except ValueError:
        return False
