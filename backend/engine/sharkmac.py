"""
SHARKmac — native MAC address generation + validation (v1).

Pure logic, no OS calls, no scapy: turns a preset choice into a valid MAC and
validates any candidate before it is ever applied. The OS-level get/set/verify
lives in `macadapter.py`; the two are deliberately separate so this half is
fully unit-testable without touching a real adapter.

MAC byte 0, bit layout (the two low bits of the first octet):
    bit 0 (0x01) = I/G : 0 unicast, 1 multicast
    bit 1 (0x02) = U/L : 0 globally-unique (vendor OUI), 1 locally-administered
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path

_HEX = "0123456789abcdef"
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-]?)(?:[0-9a-fA-F]{2}\1){4}[0-9a-fA-F]{2}$")

BROADCAST = "ff:ff:ff:ff:ff:ff"
ALL_ZERO = "00:00:00:00:00:00"


# ---------------------------------------------------------------- parsing
def normalize_mac(s: str) -> str | None:
    """Accept aa:bb.., aa-bb.., aabb.. (any/again no separators) -> canonical
    lower-case colon form, or None if it isn't 6 valid octets."""
    if not s:
        return None
    s = s.strip()
    if not _MAC_RE.match(s):
        # also accept a bare 12-hex string with no separators
        raw = s.replace(":", "").replace("-", "").replace(".", "")
        if len(raw) != 12 or any(c not in _HEX for c in raw.lower()):
            return None
        octets = [raw[i:i + 2] for i in range(0, 12, 2)]
        return ":".join(octets).lower()
    raw = s.replace(":", "").replace("-", "")
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).lower()


def _bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _fmt(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


# ---------------------------------------------------------------- predicates
def is_valid(mac: str) -> bool:
    return normalize_mac(mac) is not None


def is_multicast(mac: str) -> bool:
    m = normalize_mac(mac)
    return m is not None and (_bytes(m)[0] & 0x01) == 1


def is_locally_administered(mac: str) -> bool:
    m = normalize_mac(mac)
    return m is not None and (_bytes(m)[0] & 0x02) == 2


def is_unicast(mac: str) -> bool:
    return is_valid(mac) and not is_multicast(mac)


def is_broadcast(mac: str) -> bool:
    m = normalize_mac(mac)
    return m == BROADCAST


def is_all_zero(mac: str) -> bool:
    m = normalize_mac(mac)
    return m == ALL_ZERO


def validate_for_apply(mac: str, current: str | None = None,
                       avoid: set[str] | None = None) -> tuple[bool, str]:
    """Gate a candidate MAC before it is applied to an adapter.
    Returns (ok, reason). reason is '' on success, else a user-facing message."""
    m = normalize_mac(mac)
    if m is None:
        return False, "Not a valid MAC address (need 6 hex octets)."
    if is_broadcast(m):
        return False, "Broadcast address is not allowed."
    if is_all_zero(m):
        return False, "All-zero address is not allowed."
    if is_multicast(m):
        return False, "Multicast address is not allowed (first octet must be even)."
    if current and normalize_mac(current) == m:
        return False, "That is already the current MAC — nothing to change."
    if avoid and m in {normalize_mac(a) for a in avoid if a}:
        return False, "That MAC is already used by one of your saved profiles."
    return True, ""


# ---------------------------------------------------------------- generation
def _finalize_local(b: bytearray) -> str:
    """Force a locally-administered unicast first octet."""
    b[0] = (b[0] | 0x02) & 0xFE      # set U/L (local), clear I/G (unicast)
    return _fmt(bytes(b))


def random_mac(avoid: set[str] | None = None, tries: int = 64) -> str:
    """Fully random, valid, locally-administered unicast MAC. Never returns the
    broadcast/all-zero/multicast address, the current MAC, or a saved duplicate."""
    avoid_n = {normalize_mac(a) for a in (avoid or set()) if a}
    for _ in range(tries):
        mac = _finalize_local(bytearray(secrets.token_bytes(6)))
        if mac in (BROADCAST, ALL_ZERO) or mac in avoid_n:
            continue
        return mac
    # astronomically unlikely fallback
    return _finalize_local(bytearray(secrets.token_bytes(6)))


def stable_mac(seed: str, profile: str) -> str:
    """Deterministic locally-administered MAC derived from a stored seed +
    profile name — the same (seed, profile) always reproduces the same MAC.
    (Phase-2 preset; included now because it is pure and free.)"""
    digest = hmac.new(seed.encode("utf-8"), profile.encode("utf-8"),
                      hashlib.sha256).digest()
    return _finalize_local(bytearray(digest[:6]))


# ---------------------------------------------------------------- vendor OUI DB
def _oui_db_path() -> Path | None:
    """Locate backend/data/oui_vendors.json in both source and frozen builds."""
    candidates = []
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        candidates.append(base / "backend" / "data" / "oui_vendors.json")
        candidates.append(base / "data" / "oui_vendors.json")
    candidates.append(Path(__file__).resolve().parent.parent / "data" / "oui_vendors.json")
    for c in candidates:
        if c.is_file():
            return c
    return None


class VendorOUI:
    """Curated vendor -> [OUI prefixes] repository. Loads once, fails soft to an
    empty set (SHARKmac just hides the Vendor preset if the DB is missing)."""

    def __init__(self) -> None:
        self._vendors: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        p = _oui_db_path()
        if not p:
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            raw = data.get("vendors", {})
        except Exception:
            return
        clean: dict[str, list[str]] = {}
        for vendor, ouis in raw.items():
            good = []
            for o in ouis or []:
                n = normalize_mac(str(o) + ":00:00:00") if len(str(o).replace(":", "").replace("-", "")) == 6 else None
                if n and (_bytes(n)[0] & 0x01) == 0:      # must be unicast
                    good.append(n[:8])                    # store "aa:bb:cc"
            if good:
                clean[vendor] = sorted(set(good))
        self._vendors = clean

    def vendors(self) -> list[str]:
        return sorted(self._vendors)

    def ouis_for(self, vendor: str) -> list[str]:
        return list(self._vendors.get(vendor, []))

    def search(self, query: str) -> list[str]:
        q = (query or "").strip().lower()
        if not q:
            return self.vendors()
        return [v for v in self.vendors() if q in v.lower()]

    def random_oui(self, vendor: str) -> str | None:
        ouis = self._vendors.get(vendor)
        return secrets.choice(ouis) if ouis else None

    def generate(self, vendor: str, avoid: set[str] | None = None) -> str | None:
        oui = self.random_oui(vendor)
        return vendor_mac(oui, avoid) if oui else None


VENDORS = VendorOUI()


def vendor_mac(oui: str, avoid: set[str] | None = None, tries: int = 64) -> str | None:
    """A MAC that begins with a real vendor OUI (first 3 bytes) + random tail.
    The vendor's globally-unique first octet is preserved (the point is to look
    like that vendor), so we do NOT force the locally-administered bit here."""
    o = normalize_mac(oui + ":00:00:00") if len(oui.replace(":", "").replace("-", "")) == 6 else None
    if o is None:
        return None
    prefix = _bytes(o)[:3]
    avoid_n = {normalize_mac(a) for a in (avoid or set()) if a}
    for _ in range(tries):
        mac = _fmt(prefix + secrets.token_bytes(3))
        if mac in (BROADCAST, ALL_ZERO) or mac in avoid_n:
            continue
        # a real OUI is unicast+global already; sanity-guard anyway
        if _bytes(mac)[0] & 0x01:
            continue
        return mac
    return None
