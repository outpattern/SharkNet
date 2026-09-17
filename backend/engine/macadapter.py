"""
SHARKmac — OS-level adapter MAC control (Windows).

The native, TMAC-free mechanism Windows exposes for changing an adapter's MAC:

  1. Write the desired MAC (12 hex chars, no separators) to the adapter's
     `NetworkAddress` value under
     HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-...}\\<NNNN>,
     where <NNNN> is the class-index subkey whose `NetCfgInstanceId` == the
     adapter's GUID.
  2. Bounce the adapter (Disable-NetAdapter / Enable-NetAdapter) so the driver
     re-reads the address.
  3. Verify the effective MAC actually changed (drivers may silently ignore it).
  4. To restore the original, delete `NetworkAddress` and bounce again — the
     driver falls back to the burned-in PermanentAddress.

Read operations (enumerate / current / permanent / capability) are safe and are
what SharkNet uses to populate the SHARKmac UI. The write/cycle operations are
only ever invoked by an explicit user "Change MAC" action via the coordinator —
never automatically — because bouncing the adapter briefly drops the link.

All shell-outs use CREATE_NO_WINDOW (no console flash), matching the rest of the
engine. Everything fails soft with a (ok, message) result; nothing raises.
"""
from __future__ import annotations

import json
import subprocess
import time
from typing import Optional

from . import sharkmac

CREATE_NO_WINDOW = 0x08000000
_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

try:
    import winreg  # Windows only
    _HAVE_WINREG = True
except Exception:  # pragma: no cover - non-Windows
    _HAVE_WINREG = False


# ---------------------------------------------------------------- powershell
def _ps(script: str, timeout: float = 15.0) -> str:
    """Run a PowerShell snippet, return stdout ('' on any failure)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return out.stdout or ""
    except Exception:
        return ""


def _load_json(text: str):
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    return data if isinstance(data, list) else [data]


# ---------------------------------------------------------------- enumerate
# Get-NetAdapter costs ~0.5-1s (PowerShell start-up), so cache the result for a
# few seconds — the SHARKmac modal reads adapters + generates in quick
# succession. Any write (set/clear/cycle) invalidates the cache immediately.
_cache: dict = {"t": 0.0, "data": None}
_CACHE_TTL = 4.0


def invalidate_cache() -> None:
    _cache["data"] = None


# ---- adapter kind classification (SHARKmac presentation only) --------------
# SHARKmac offers MAC control for real Ethernet and Wi-Fi interfaces only.
# Bluetooth PAN must never be offered: changing its address is meaningless and
# the adapter is not a LAN interface the user is administering.
#
# Name matching alone is NOT reliable (it is localized, and a Bluetooth PAN
# adapter deliberately impersonates Ethernet). On Windows it reports:
#     InterfaceType = 6 (Ethernet)   MediaType = 802.3
# so those two fields WOULD wrongly accept it. The authoritative signal is NDIS:
#     NdisPhysicalMedium = 10 (NdisPhysicalMediumBluetooth)
# backed by the driver's ComponentID ("BTH\MS_BTHPAN"). We check those first,
# then fall back to the media strings, and only then to names.
#
# NDIS_PHYSICAL_MEDIUM values we care about:
_NDIS_WIRELESS_LAN = 1
_NDIS_NATIVE_802_11 = 9
_NDIS_BLUETOOTH = 10
_NDIS_802_3 = 14
# IANA ifType values used by Get-NetAdapter:
_IFTYPE_ETHERNET = 6
_IFTYPE_WIFI = 71

ETHERNET = "ethernet"
WIFI = "wifi"


def _is_bluetooth(medium, media_str: str, component_id: str, name: str, desc: str) -> bool:
    """True for a Bluetooth networking interface, by the most reliable signal
    available. Ordered strongest -> weakest so a localized name is only ever a
    last resort."""
    if medium == _NDIS_BLUETOOTH:
        return True
    cid = (component_id or "").strip().lower()
    if cid.startswith("bth\\") or cid.startswith("bth/") or "bthpan" in cid:
        return True
    if "bluetooth" in (media_str or "").lower():
        return True
    return "bluetooth" in f"{name} {desc}".lower()


def adapter_kind(medium, if_type, media_str: str, component_id: str,
                 name: str, desc: str) -> str | None:
    """Classify an adapter as ETHERNET, WIFI, or None (not offered by SHARKmac).

    Bluetooth is rejected BEFORE the Ethernet test, because a Bluetooth PAN
    adapter reports itself as Ethernet/802.3."""
    if _is_bluetooth(medium, media_str, component_id, name, desc):
        return None
    m = (media_str or "").lower()
    if (medium in (_NDIS_WIRELESS_LAN, _NDIS_NATIVE_802_11)
            or if_type == _IFTYPE_WIFI
            or "802.11" in m or "wireless" in m or "wi-fi" in m
            or _looks_wireless(name, desc)):
        return WIFI
    if medium == _NDIS_802_3 or if_type == _IFTYPE_ETHERNET or "802.3" in m:
        return ETHERNET
    return None


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def list_adapters(force: bool = False) -> list[dict]:
    """Return the machine's Ethernet and Wi-Fi adapters with identity + MAC state.

    Each: {name, description, guid, index(ifIndex), current, permanent,
           status, wireless, kind, changeable, capability, reason}.

    Only interfaces SHARKmac actually supports are returned — Bluetooth PAN and
    other non-LAN media are filtered out (see adapter_kind). This is a SHARKmac
    presentation concern only; SharkNet's enforcement interface list comes from
    netinfo.list_interfaces() and is untouched.
    """
    now = time.time()
    if not force and _cache["data"] is not None and (now - _cache["t"]) < _CACHE_TTL:
        return _cache["data"]
    raw = _load_json(_ps(
        "Get-NetAdapter | Select-Object "
        "Name,InterfaceDescription,ifIndex,DeviceID,MacAddress,"
        "PermanentAddress,Status,PhysicalMediaType,NdisPhysicalMedium,"
        "InterfaceType,ComponentID | ConvertTo-Json -Compress"
    ))
    adapters = []
    for a in raw:
        guid = str(a.get("DeviceID") or "")
        cur = sharkmac.normalize_mac(str(a.get("MacAddress") or "")) or ""
        perm = sharkmac.normalize_mac(str(a.get("PermanentAddress") or "")) or ""
        media = str(a.get("PhysicalMediaType") or "")
        name = str(a.get("Name") or "")
        desc = str(a.get("InterfaceDescription") or "")
        kind = adapter_kind(_as_int(a.get("NdisPhysicalMedium")),
                            _as_int(a.get("InterfaceType")), media,
                            str(a.get("ComponentID") or ""), name, desc)
        if kind is None:
            continue                      # Bluetooth / unsupported medium
        wireless = kind == WIFI
        cap = _capability(guid, wireless, bool(perm))
        adapters.append({
            "name": name,
            "description": desc,
            "guid": guid,
            "index": a.get("ifIndex"),
            "current": cur,
            "permanent": perm,
            "status": str(a.get("Status") or ""),
            "wireless": wireless,
            "kind": kind,
            "changeable": cap["level"] != "unsupported",
            "capability": cap["level"],
            "reason": cap["reason"],
        })
    _cache["t"] = now
    _cache["data"] = adapters
    return adapters


def _looks_wireless(name: str, desc: str) -> bool:
    t = f"{name} {desc}".lower()
    return any(k in t for k in ("wi-fi", "wifi", "wireless", "802.11", "wlan"))


def find_adapter(key: str, force: bool = False) -> Optional[dict]:
    """Find an adapter by GUID (preferred), name, or description."""
    if not key:
        return None
    k = key.lower()
    ads = list_adapters(force)
    for a in ads:
        if a["guid"].lower() == k:
            return a
    for a in ads:
        if a["name"].lower() == k or a["description"].lower() == k:
            return a
    return None


# ---------------------------------------------------------------- registry
def _class_index_for_guid(guid: str) -> Optional[str]:
    """Return the class-key subkey ('0007') whose NetCfgInstanceId == guid."""
    if not (_HAVE_WINREG and guid):
        return None
    guid = guid.lower()
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CLASS_KEY)
    except Exception:
        return None
    try:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            if not sub.isdigit():
                continue
            try:
                sk = winreg.OpenKey(root, sub)
                inst, _ = winreg.QueryValueEx(sk, "NetCfgInstanceId")
                if str(inst).lower() == guid:
                    return sub
            except Exception:
                continue
    finally:
        winreg.CloseKey(root)
    return None


def _capability(guid: str, wireless: bool, has_permanent: bool) -> dict:
    """Best-effort read-only guess at whether this adapter can change its MAC."""
    if not _HAVE_WINREG:
        return {"level": "unsupported", "reason": "Registry access unavailable."}
    idx = _class_index_for_guid(guid)
    if not idx:
        return {"level": "unsupported",
                "reason": "No driver registry entry — MAC change not supported."}
    if wireless:
        return {"level": "maybe",
                "reason": "Wi-Fi adapters often reject a changed MAC (driver-dependent)."}
    return {"level": "supported", "reason": "Wired adapter — MAC change supported."}


def has_override(guid: str) -> bool:
    """True if a NetworkAddress override is currently set (a spoofed MAC)."""
    if not _HAVE_WINREG:
        return False
    idx = _class_index_for_guid(guid)
    if not idx:
        return False
    try:
        sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CLASS_KEY + "\\" + idx)
        val, _ = winreg.QueryValueEx(sk, "NetworkAddress")
        return bool(str(val).strip())
    except Exception:
        return False


# ---------------------------------------------------------------- write ops
# (only ever called from MacChangeCoordinator on an explicit user action)
def _write_network_address(guid: str, twelve_hex: Optional[str]) -> tuple[bool, str]:
    idx = _class_index_for_guid(guid)
    if not idx:
        return False, "Adapter driver registry entry not found."
    path = _CLASS_KEY + "\\" + idx
    try:
        sk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_SET_VALUE)
    except Exception as e:
        return False, f"Cannot open adapter registry key (admin needed): {e}"
    try:
        if twelve_hex is None:
            try:
                winreg.DeleteValue(sk, "NetworkAddress")
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(sk, "NetworkAddress", 0, winreg.REG_SZ, twelve_hex)
        return True, ""
    except Exception as e:
        return False, f"Registry write failed: {e}"
    finally:
        winreg.CloseKey(sk)


def set_mac(guid: str, mac: str) -> tuple[bool, str]:
    """Write the NetworkAddress override (no adapter bounce here)."""
    m = sharkmac.normalize_mac(mac)
    if not m:
        return False, "Invalid MAC."
    r = _write_network_address(guid, m.replace(":", "").upper())
    invalidate_cache()
    return r


def clear_mac(guid: str) -> tuple[bool, str]:
    """Remove the override so the adapter reverts to its permanent MAC."""
    r = _write_network_address(guid, None)
    invalidate_cache()
    return r


def cycle_adapter(name: str, settle: float = 6.0) -> tuple[bool, str]:
    """Disable then re-enable the adapter so the driver re-reads the MAC."""
    if not name:
        return False, "No adapter name."
    safe = name.replace("'", "''")
    out = _ps(
        f"try {{ Disable-NetAdapter -Name '{safe}' -Confirm:$false -ErrorAction Stop; "
        f"Start-Sleep -Milliseconds 1500; "
        f"Enable-NetAdapter -Name '{safe}' -Confirm:$false -ErrorAction Stop; "
        f"'OK' }} catch {{ 'ERR:' + $_.Exception.Message }}",
        timeout=max(20.0, settle + 12.0),
    )
    invalidate_cache()
    if "OK" in out:
        return True, ""
    return False, (out.strip() or "Adapter bounce failed.")


def effective_mac(guid: str) -> str:
    a = find_adapter(guid, force=True)   # must be a fresh read after a bounce
    return a["current"] if a else ""


def verify_effective(guid: str, expected: str) -> bool:
    exp = sharkmac.normalize_mac(expected)
    return bool(exp) and effective_mac(guid) == exp
