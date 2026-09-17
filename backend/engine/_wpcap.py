"""
Minimal ctypes binding to Npcap's wpcap.dll (libpcap API) — v3.0 Stage 2.

Loads wpcap.dll directly (no scapy) and exposes ONLY the libpcap functions the
native Capture/Injector backends need, each with explicit argtypes/restype for a
safe x64 ABI. This module does packet I/O plumbing only — no SharkNet policy or
enforcement logic lives here.

Adapter friendly-name -> GUID resolution uses the native winifaces enumeration
(GetAdaptersAddresses); this module imports no scapy. (Gate 6.2 replaced the
former scapy get_windows_if_list lookup here.)

Every I/O primitive is a thin module-level function so tests can monkeypatch the
layer and exercise the backends WITHOUT a real device or Administrator. Offline
helpers (savefile round-trip, compile_nopcap/offline_filter) let the pkthdr ABI
and BPF behaviour be proven with no admin and no live traffic.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import (Structure, POINTER, byref, create_string_buffer,
                    c_char_p, c_int, c_uint, c_ushort, c_ubyte, c_long, c_void_p)

PCAP_ERRBUF_SIZE = 256
DLT_EN10MB = 1


# ---------------------------------------------------------------- load
def _load():
    sys32 = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
    npcap = os.path.join(sys32, "Npcap")
    if os.path.isdir(npcap):
        try:
            os.add_dll_directory(npcap)   # resolve the Packet.dll dependency
        except Exception:
            pass
    for p in (os.path.join(npcap, "wpcap.dll"), os.path.join(sys32, "wpcap.dll")):
        if os.path.exists(p):
            try:
                return ctypes.CDLL(p), p
            except Exception:
                pass
    return None, ""


_dll, WPCAP_PATH = _load()
HAVE_WPCAP = _dll is not None


# ---------------------------------------------------------------- structs (x64-safe)
class timeval(Structure):
    # Windows' winsock `struct timeval` is two 32-bit longs (8 bytes total),
    # which is what Npcap's pcap_pkthdr uses regardless of the CRT's time_t width
    # (the version string's "64-bit time_t" refers to the CRT, not this struct).
    # -> caplen follows at offset 8. VERIFIED EMPIRICALLY by the savefile
    # round-trip test (the 16-byte variant read caplen as 0).
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class pcap_pkthdr(Structure):
    _fields_ = [("ts", timeval), ("caplen", c_uint), ("len", c_uint)]


class bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_ubyte * 14)]


class pcap_addr(Structure):
    pass


pcap_addr._fields_ = [("next", POINTER(pcap_addr)), ("addr", POINTER(sockaddr)),
                      ("netmask", POINTER(sockaddr)), ("broadaddr", POINTER(sockaddr)),
                      ("dstaddr", POINTER(sockaddr))]


class pcap_if(Structure):
    pass


pcap_if._fields_ = [("next", POINTER(pcap_if)), ("name", c_char_p),
                    ("description", c_char_p), ("addresses", POINTER(pcap_addr)),
                    ("flags", c_uint)]


# ---------------------------------------------------------------- prototypes
if HAVE_WPCAP:
    _dll.pcap_lib_version.restype = c_char_p
    _dll.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
    _dll.pcap_findalldevs.restype = c_int
    _dll.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
    _dll.pcap_freealldevs.restype = None
    _dll.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    _dll.pcap_open_live.restype = c_void_p
    _dll.pcap_close.argtypes = [c_void_p]
    _dll.pcap_close.restype = None
    _dll.pcap_datalink.argtypes = [c_void_p]
    _dll.pcap_datalink.restype = c_int
    _dll.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint]
    _dll.pcap_compile.restype = c_int
    _dll.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]
    _dll.pcap_setfilter.restype = c_int
    _dll.pcap_freecode.argtypes = [POINTER(bpf_program)]
    _dll.pcap_freecode.restype = None
    _dll.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]
    _dll.pcap_next_ex.restype = c_int
    _dll.pcap_sendpacket.argtypes = [c_void_p, c_char_p, c_int]
    _dll.pcap_sendpacket.restype = c_int
    _dll.pcap_breakloop.argtypes = [c_void_p]
    _dll.pcap_breakloop.restype = None
    _dll.pcap_geterr.argtypes = [c_void_p]
    _dll.pcap_geterr.restype = c_char_p
    # offline / savefile — for the ABI + BPF tests (no device, no admin)
    _dll.pcap_open_dead.argtypes = [c_int, c_int]
    _dll.pcap_open_dead.restype = c_void_p
    _dll.pcap_open_offline.argtypes = [c_char_p, c_char_p]
    _dll.pcap_open_offline.restype = c_void_p
    _dll.pcap_dump_open.argtypes = [c_void_p, c_char_p]
    _dll.pcap_dump_open.restype = c_void_p
    _dll.pcap_dump.argtypes = [c_void_p, POINTER(pcap_pkthdr), c_char_p]
    _dll.pcap_dump.restype = None
    _dll.pcap_dump_close.argtypes = [c_void_p]
    _dll.pcap_dump_close.restype = None
    _dll.pcap_compile_nopcap.argtypes = [c_int, c_int, POINTER(bpf_program), c_char_p, c_int, c_uint]
    _dll.pcap_compile_nopcap.restype = c_int
    _dll.pcap_offline_filter.argtypes = [POINTER(bpf_program), POINTER(pcap_pkthdr), c_char_p]
    _dll.pcap_offline_filter.restype = c_int


def _need():
    if not HAVE_WPCAP:
        raise OSError("wpcap.dll not available")


# ---------------------------------------------------------------- live I/O
def lib_version() -> str:
    return _dll.pcap_lib_version().decode(errors="ignore") if HAVE_WPCAP else ""


def list_devices() -> list:
    """[{name, description, ipv4:[...]}] via pcap_findalldevs (enumeration only)."""
    _need()
    eb = create_string_buffer(PCAP_ERRBUF_SIZE)
    head = POINTER(pcap_if)()
    # rc==0 is success even if eb carries a benign per-adapter note (e.g. WAN
    # Miniport PacketRequest) — we only fail on rc<0.
    if _dll.pcap_findalldevs(byref(head), eb) < 0:
        raise OSError("pcap_findalldevs failed: " + eb.value.decode(errors="ignore"))
    out = []
    d = head
    while d:
        x = d.contents
        ips = []
        a = x.addresses
        while a:
            sa = a.contents.addr
            if sa and sa.contents.sa_family == 2:   # AF_INET
                b = bytes(sa.contents.sa_data)
                ips.append("%d.%d.%d.%d" % (b[2], b[3], b[4], b[5]))
            a = a.contents.next
        out.append({"name": (x.name or b"").decode(errors="ignore"),
                    "description": (x.description or b"").decode(errors="ignore"),
                    "ipv4": ips})
        d = x.next
    _dll.pcap_freealldevs(head)
    return out


def resolve_npf_name(iface_name: str) -> str:
    """Map SharkNet's adapter friendly name (e.g. 'Ethernet') to the Npcap device
    name '\\Device\\NPF_{GUID}'. Uses the native winifaces enumeration for the
    name->GUID step, then verifies the device is capturable."""
    _need()
    guid = None
    try:
        from .winifaces import list_adapters
        entries = list_adapters()
        for e in entries:
            if e.get("name") == iface_name:
                guid = e.get("guid")
                break
        if not guid:      # secondary: match on hardware description
            for e in entries:
                if e.get("description") == iface_name:
                    guid = e.get("guid")
                    break
    except Exception as ex:
        raise OSError(f"adapter enumeration failed: {ex}")
    if not guid:
        raise OSError(f"could not resolve adapter {iface_name!r} to a GUID")
    dev = r"\Device\NPF_" + guid
    if dev not in {d["name"] for d in list_devices()}:
        raise OSError(f"NPF device not found for {iface_name!r}: {dev}")
    return dev


def open_live(device: str, snaplen: int = 65535, promisc: int = 1, to_ms: int = 100):
    _need()
    eb = create_string_buffer(PCAP_ERRBUF_SIZE)
    h = _dll.pcap_open_live(device.encode(), snaplen, promisc, to_ms, eb)
    if not h:
        raise OSError("pcap_open_live failed: " + eb.value.decode(errors="ignore"))
    return h


def datalink(handle) -> int:
    return _dll.pcap_datalink(handle)


def geterr(handle) -> str:
    try:
        return (_dll.pcap_geterr(handle) or b"").decode(errors="ignore")
    except Exception:
        return ""


def compile_and_set(handle, bpf: str, netmask: int = 0) -> None:
    prog = bpf_program()
    if _dll.pcap_compile(handle, byref(prog), bpf.encode(), 1, netmask) != 0:
        raise OSError("pcap_compile failed: " + geterr(handle))
    try:
        if _dll.pcap_setfilter(handle, byref(prog)) != 0:
            raise OSError("pcap_setfilter failed: " + geterr(handle))
    finally:
        _dll.pcap_freecode(byref(prog))


def next_ex(handle):
    """Return (rc, raw_bytes|None). rc: 1 ok, 0 timeout, -1 error, -2 eof."""
    hdr = POINTER(pcap_pkthdr)()
    data = POINTER(c_ubyte)()
    rc = _dll.pcap_next_ex(handle, byref(hdr), byref(data))
    if rc == 1:
        return 1, ctypes.string_at(data, hdr.contents.caplen)
    return rc, None


def sendpacket(handle, raw: bytes) -> None:
    if _dll.pcap_sendpacket(handle, raw, len(raw)) != 0:
        raise OSError("pcap_sendpacket failed: " + geterr(handle))


def breakloop(handle) -> None:
    _dll.pcap_breakloop(handle)


def close(handle) -> None:
    _dll.pcap_close(handle)


# ---------------------------------------------------------------- offline (tests)
def open_dead(linktype: int = DLT_EN10MB, snaplen: int = 65535):
    _need()
    return _dll.pcap_open_dead(linktype, snaplen)


def dump_open(handle, path: str):
    d = _dll.pcap_dump_open(handle, path.encode())
    if not d:
        raise OSError("pcap_dump_open failed")
    return d


def dump(dumper, raw: bytes) -> None:
    hdr = pcap_pkthdr()
    hdr.caplen = len(raw)
    hdr.len = len(raw)
    _dll.pcap_dump(dumper, byref(hdr), raw)


def dump_close(dumper) -> None:
    _dll.pcap_dump_close(dumper)


def open_offline(path: str):
    _need()
    eb = create_string_buffer(PCAP_ERRBUF_SIZE)
    h = _dll.pcap_open_offline(path.encode(), eb)
    if not h:
        raise OSError("pcap_open_offline failed: " + eb.value.decode(errors="ignore"))
    return h


def compile_nopcap(bpf: str, linktype: int = DLT_EN10MB, snaplen: int = 65535, netmask: int = 0):
    _need()
    prog = bpf_program()
    if _dll.pcap_compile_nopcap(snaplen, linktype, byref(prog), bpf.encode(), 1, netmask) != 0:
        raise OSError(f"pcap_compile_nopcap failed for {bpf!r}")
    return prog


def offline_filter(prog, raw: bytes) -> bool:
    hdr = pcap_pkthdr()
    hdr.caplen = len(raw)
    hdr.len = len(raw)
    return _dll.pcap_offline_filter(byref(prog), byref(hdr), raw) != 0


def free_prog(prog) -> None:
    _dll.pcap_freecode(byref(prog))
