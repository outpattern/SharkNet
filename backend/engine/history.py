"""
Per-device traffic history (v2.9).

An in-memory ring buffer holding the last ~10 minutes of 1-second samples per
device, keyed by MAC (stable across IP changes). This powers the live 10-minute
chart in the device details modal WITHOUT growing SQLite write pressure and
WITHOUT streaming history arrays over the WebSocket — the modal fetches the
backlog once on open, then extends it live from the per-tick speeds the UI
already receives.

Only devices we actually intercept (enforcement OR observation/monitor) produce
real samples — an ALLOW-and-not-monitored device is not MITM'd, so we have no
visibility into its traffic and record nothing for it (we never fabricate samples).

This ring is the ONLY source for the History chart (the old per-second SQLite
`traffic` table was removed in V3.0 — its reader was never wired to any UI).
"""
from __future__ import annotations

import threading
import time
from collections import deque

WINDOW_SECONDS = 600          # 10 minutes
_MAX_SAMPLES = WINDOW_SECONDS + 20   # ~1 Hz + a little slack
_MAX_DEVICES = 256            # soft cap on tracked MACs


class TrafficHistory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # mac(lower) -> deque[(ts, down_bps, up_bps)]
        self._rings: dict[str, deque] = {}

    def add(self, mac: str | None, down_bps: float, up_bps: float,
            ts: float | None = None) -> None:
        if not mac:
            return
        key = mac.lower()
        ts = time.time() if ts is None else ts
        with self._lock:
            ring = self._rings.get(key)
            if ring is None:
                if len(self._rings) >= _MAX_DEVICES:
                    self._evict_oldest_locked()
                ring = self._rings[key] = deque(maxlen=_MAX_SAMPLES)
            ring.append((ts, float(down_bps), float(up_bps)))

    def get(self, mac: str | None, seconds: int = WINDOW_SECONDS) -> list[dict]:
        """Return samples within the last `seconds` as [{ts,down,up}, ...]."""
        if not mac:
            return []
        seconds = max(1, min(int(seconds), WINDOW_SECONDS))
        cutoff = time.time() - seconds
        key = mac.lower()
        with self._lock:
            ring = self._rings.get(key)
            if not ring:
                return []
            return [{"ts": t, "down": d, "up": u} for (t, d, u) in ring if t >= cutoff]

    def forget(self, mac: str | None) -> None:
        if not mac:
            return
        with self._lock:
            self._rings.pop(mac.lower(), None)

    def clear(self) -> None:
        with self._lock:
            self._rings.clear()

    # ---- internals (lock held) ----
    def _evict_oldest_locked(self) -> None:
        def last_ts(k: str) -> float:
            r = self._rings.get(k)
            return r[-1][0] if r else 0.0
        oldest = min(self._rings, key=last_ts)
        self._rings.pop(oldest, None)


HISTORY = TrafficHistory()
