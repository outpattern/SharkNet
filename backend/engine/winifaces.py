"""
Native Windows adapter enumeration (v3.0 Gate 6.2).

Replaces scapy's `get_windows_if_list` for SharkNet's adapter friendly-name /
GUID / MAC / IPv4 lookup — the last Scapy dependency shared by BOTH
`netinfo.list_interfaces()` and the native backend's `_wpcap.resolve_npf_name()`.

Pure ctypes over iphlpapi!GetAdaptersAddresses. `list_adapters()` returns dicts
shaped exactly like scapy's get_windows_if_list entries
({name, description, guid, mac, ips}) so both callers work with no other change.

Native GetAdaptersAddresses is authoritative (Gate 6.4 removed the transitional
scapy fallback); list_adapters() surfaces an OS-enumeration failure rather than
silently falling back.
"""
from __future__ import annotations

import ctypes
from ctypes import POINTER, Structure, byref, c_char_p, c_int, c_ubyte, c_ushort, c_void_p, c_wchar_p, wintypes

AF_INET = 2
_GAA_SKIP = 0x0002 | 0x0004 | 0x0008          # skip anycast / multicast / dns-server
_ERROR_BUFFER_OVERFLOW = 111


class _SOCKADDR(Structure):
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_ubyte * 14)]


class _SOCKET_ADDRESS(Structure):
    _fields_ = [("lpSockaddr", POINTER(_SOCKADDR)), ("iSockaddrLength", c_int)]


class _UNICAST(Structure):
    pass


_UNICAST._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", POINTER(_UNICAST)),
    ("Address", _SOCKET_ADDRESS),
    # trailing fields (prefix origin, valid/preferred lifetimes...) not read
]


class _ADAPTER(Structure):
    pass


_ADAPTER._fields_ = [
    ("Length", wintypes.ULONG),               # union head: ULONG Length + DWORD IfIndex (8 bytes)
    ("IfIndex", wintypes.DWORD),
    ("Next", POINTER(_ADAPTER)),
    ("AdapterName", c_char_p),                 # ANSI "{GUID}"
    ("FirstUnicastAddress", POINTER(_UNICAST)),
    ("FirstAnycastAddress", c_void_p),
    ("FirstMulticastAddress", c_void_p),
    ("FirstDnsServerAddress", c_void_p),
    ("DnsSuffix", c_wchar_p),
    ("Description", c_wchar_p),
    ("FriendlyName", c_wchar_p),
    ("PhysicalAddress", c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.DWORD),
    # struct continues (Flags, Mtu, IfType, OperStatus, ...) — we don't read past here
]


def _native_adapters() -> list[dict]:
    iphlp = ctypes.WinDLL("iphlpapi")
    fn = iphlp.GetAdaptersAddresses
    fn.argtypes = [wintypes.ULONG, wintypes.ULONG, c_void_p, c_void_p, POINTER(wintypes.ULONG)]
    fn.restype = wintypes.ULONG

    size = wintypes.ULONG(0)
    rc = fn(AF_INET, _GAA_SKIP, None, None, byref(size))   # first call: learn the size
    if rc not in (0, _ERROR_BUFFER_OVERFLOW) or size.value == 0:
        raise OSError(f"GetAdaptersAddresses(size) rc={rc}")
    buf = ctypes.create_string_buffer(size.value)
    rc = fn(AF_INET, _GAA_SKIP, None, buf, byref(size))
    if rc != 0:
        raise OSError(f"GetAdaptersAddresses rc={rc}")

    out: list[dict] = []
    p = ctypes.cast(buf, POINTER(_ADAPTER))
    while p:
        a = p.contents
        n = min(a.PhysicalAddressLength, 6)
        mac = ":".join(f"{a.PhysicalAddress[i]:02x}" for i in range(n)) if n == 6 else ""
        guid = a.AdapterName.decode(errors="ignore") if a.AdapterName else ""
        ips: list[str] = []
        ua = a.FirstUnicastAddress
        while ua:
            sa = ua.contents.Address.lpSockaddr
            if sa and sa.contents.sa_family == AF_INET:
                d = bytes(sa.contents.sa_data)          # sockaddr_in: [port:2][addr:4]
                ips.append(".".join(str(b) for b in d[2:6]))
            ua = ua.contents.Next
        out.append({
            "name": a.FriendlyName or "",
            "description": a.Description or "",
            "guid": guid,
            "mac": mac.lower(),
            "ips": ips,
        })
        p = a.Next
    return out


def list_adapters() -> list[dict]:
    """[{name, description, guid, mac, ips}] via native GetAdaptersAddresses."""
    return _native_adapters()
