"""
MAC -> vendor lookup. Uses a small built-in OUI table plus SharkNet's curated
OUI database (backend/data/oui_vendors.json); offline, covers common consumer
brands. (Gate 6.3 replaced the former scapy MANUFDB lookup with the bundled JSON
— fewer entries than scapy's full IEEE DB, but no scapy dependency.)
"""
from __future__ import annotations

# Compact OUI prefix (first 3 octets, upper, no separators) -> vendor.
_BUILTIN = {
    # Apple
    "F0DBF8": "Apple", "3C0754": "Apple", "A85C2C": "Apple", "DC2B2A": "Apple",
    "8866A5": "Apple", "F02475": "Apple", "A4B197": "Apple", "AC1F74": "Apple",
    # Samsung
    "F8042E": "Samsung", "D0176A": "Samsung", "5CF6DC": "Samsung", "8425DB": "Samsung",
    "E8508B": "Samsung", "C81479": "Samsung",
    # Xiaomi
    "F8A45F": "Xiaomi", "64B473": "Xiaomi", "286C07": "Xiaomi", "7451BA": "Xiaomi",
    # Huawei
    "48435A": "Huawei", "00E0FC": "Huawei", "F4C714": "Huawei", "D0374B": "Huawei",
    # Intel (laptops/NICs)
    "001B21": "Intel", "3C970E": "Intel", "A0A8CD": "Intel", "8C1645": "Intel",
    "E4B318": "Intel",
    # Dell
    "F8BC12": "Dell", "18DBF2": "Dell", "D067E5": "Dell",
    # TP-Link / routers
    "50C7BF": "TP-Link", "A42BB0": "TP-Link", "EC086B": "TP-Link", "C46E1F": "TP-Link",
    # Realtek NICs
    "525400": "Realtek/QEMU", "00E04C": "Realtek",
    # Sony / consoles
    "FCF152": "Sony", "A8E3EE": "Sony (PlayStation)",
    # Microsoft / Xbox
    "000D3A": "Microsoft", "7C1E52": "Microsoft",
    # Amazon devices
    "44650D": "Amazon", "FCA183": "Amazon",
    # Google / Nest
    "F4F5D8": "Google", "1CF29A": "Google",
    # Espressif (IoT / ESP32)
    "246F28": "Espressif (IoT)", "3C71BF": "Espressif (IoT)",
}

_oui_map = None        # "XXYYZZ" (upper, no separators) -> vendor name


def _oui_db() -> dict:
    """prefix -> vendor, inverted from backend/data/oui_vendors.json (which is
    stored vendor -> [prefixes]). Loaded once; fails soft to an empty map."""
    global _oui_map
    if _oui_map is not None:
        return _oui_map
    _oui_map = {}
    try:
        import json
        import os
        import sys
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [os.path.join(here, "..", "data", "oui_vendors.json")]
        base = getattr(sys, "_MEIPASS", None)          # PyInstaller frozen root
        if base:
            candidates.append(os.path.join(base, "backend", "data", "oui_vendors.json"))
            candidates.append(os.path.join(base, "data", "oui_vendors.json"))
        for p in candidates:
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    data = json.load(fh)
                for vendor, prefixes in (data.get("vendors") or {}).items():
                    for pre in prefixes or []:
                        key = pre.upper().replace(":", "").replace("-", "")[:6]
                        if len(key) == 6:
                            _oui_map[key] = vendor
                break
    except Exception:
        pass
    return _oui_map


def is_randomized(mac: str) -> bool:
    """A locally-administered (privacy/randomized) MAC has bit 0x02 set in the
    first octet — modern phones use these, so no real vendor exists."""
    try:
        return bool(int(mac.replace(":", "").replace("-", "")[:2], 16) & 0x02)
    except Exception:
        return False


def lookup(mac: str) -> str:
    if not mac:
        return "Unknown"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    if prefix in _BUILTIN:
        return _BUILTIN[prefix]
    db = _oui_db()
    if prefix in db:
        return db[prefix]
    if is_randomized(mac):
        return "Private (randomized MAC)"
    return "Unknown"


def guess_type(vendor: str) -> str:
    v = vendor.lower()
    if any(k in v for k in ("playstation", "xbox", "sony", "nintendo")):
        return "console"
    if any(k in v for k in ("apple", "samsung", "xiaomi", "huawei")):
        return "phone"
    if any(k in v for k in ("intel", "dell", "realtek")):
        return "computer"
    if any(k in v for k in ("tp-link", "router")):
        return "router"
    if any(k in v for k in ("espressif", "iot", "amazon", "google", "nest")):
        return "iot"
    return "unknown"
