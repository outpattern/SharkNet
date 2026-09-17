"""
Device name intelligence (v2.9).

Several passive/active sources learn a device's name (DHCP option 12, mDNS,
NetBIOS, reverse DNS, a previously-saved name). Before v2.9 whichever source
fired *last* overwrote `Device.hostname`, so a weak reverse-DNS PTR could clobber
a strong DHCP hostname and the label would flap.

This module keeps, per device (keyed by MAC — stable across IP changes), the best
candidate seen from each source, and returns the highest-PRIORITY one. A lower-
priority source can therefore never override a higher-priority one, which makes
the displayed name deterministic and stable. The user-set name lives on
`Device.name` and always wins the label; this resolver only governs `hostname`.

Pure logic: no network, no scapy, no imports from the rest of the engine.
"""
from __future__ import annotations

import threading
import time

# lower number = higher priority (wins). `user` is here for completeness but the
# user-set name is applied on Device.name directly and always beats hostname.
PRIORITY = {
    "user": 0,
    "dhcp": 1,     # DHCP option-12 hostname (authoritative, device chose it)
    "mdns": 2,     # mDNS .local / service-instance / model name
    "saved": 3,    # persisted best from a previous run
    "netbios": 4,  # NetBIOS (Windows only)
    "rdns": 5,     # reverse DNS PTR (often generic / router-assigned)
}
# informational confidence per source (0..1) — surfaced in the details modal,
# never used to override PRIORITY ordering.
CONFIDENCE = {
    "user": 1.0, "dhcp": 0.9, "mdns": 0.85, "saved": 0.6, "netbios": 0.7, "rdns": 0.5,
}

_MAX_MACS = 512     # soft cap so a long-running session can't grow unbounded


def _clean(name: str) -> str:
    name = (name or "").strip().strip(".")
    for suf in (".local", ".lan", ".home"):
        if name.lower().endswith(suf):
            name = name[: -len(suf)]
    return name[:40].strip()


class NameResolver:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # mac(lower) -> {source: (value, ts)}
        self._cand: dict[str, dict[str, tuple[str, float]]] = {}

    def submit(self, mac: str | None, source: str, value: str) -> bool:
        """Record a name candidate from `source`. Returns True if the winning
        name for this device changed as a result (so the caller can persist)."""
        if not mac or source not in PRIORITY:
            return False
        value = _clean(value)
        if len(value) < 2:
            return False
        key = mac.lower()
        with self._lock:
            before = self._best_locked(key)
            slots = self._cand.get(key)
            if slots is None:
                if len(self._cand) >= _MAX_MACS:
                    # drop the least-recently-updated device to stay bounded
                    oldest = min(self._cand, key=lambda k: self._recency(k))
                    self._cand.pop(oldest, None)
                slots = self._cand[key] = {}
            slots[source] = (value, time.time())
            after = self._best_locked(key)
            return after != before

    def best(self, mac: str | None) -> str:
        if not mac:
            return ""
        with self._lock:
            return self._best_locked(mac.lower())

    def source_of(self, mac: str | None) -> str:
        if not mac:
            return ""
        with self._lock:
            slots = self._cand.get(mac.lower())
            if not slots:
                return ""
            src = min(slots, key=lambda s: PRIORITY[s])
            return src

    def confidence(self, mac: str | None) -> float:
        return CONFIDENCE.get(self.source_of(mac), 0.0)

    def forget(self, mac: str | None) -> None:
        if not mac:
            return
        with self._lock:
            self._cand.pop(mac.lower(), None)

    # ---- internals (call with the lock held) ----
    def _best_locked(self, key: str) -> str:
        slots = self._cand.get(key)
        if not slots:
            return ""
        # highest priority (min PRIORITY); tie-break on the fresher timestamp
        src = min(slots, key=lambda s: (PRIORITY[s], -slots[s][1]))
        return slots[src][0]

    def _recency(self, key: str) -> float:
        slots = self._cand.get(key) or {}
        return max((ts for _v, ts in slots.values()), default=0.0)


NAME_RESOLVER = NameResolver()
