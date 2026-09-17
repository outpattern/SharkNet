"""
Traffic monitor: every second, turn the forwarder's byte counters into
per-device speeds (bytes/sec) and invoke a push callback for the UI.
"""
from __future__ import annotations

import threading
import time

from ..state import STATE, is_intercepted
from .forwarder import FORWARDER
from .history import HISTORY


class Monitor:
    def __init__(self, on_tick=None, interval: float = 1.0):
        self.on_tick = on_tick
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        last = time.time()
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            now = time.time()
            dt = max(now - last, 1e-6)
            last = now
            # swap-and-read counters
            counters = FORWARDER.counters
            FORWARDER.counters = {}
            with STATE.lock:
                for dev in STATE.devices.values():
                    c = counters.get(dev.ip)
                    if c:
                        dev.down_bps = c.get("down", 0) / dt
                        dev.up_bps = c.get("up", 0) / dt
                    else:
                        dev.down_bps = 0.0
                        dev.up_bps = 0.0
                    # live 10-min ring for every INTERCEPTED device — enforcement
                    # (cut/limit/block) OR observation (monitor). These are exactly
                    # the devices whose traffic routes through us, so the samples are
                    # real; a monitored ALLOW device gets real history too (P0/P1).
                    # In-memory only: no SQLite write pressure. (The old per-second
                    # `traffic` table was removed in V3.0 — this ring is the History
                    # chart's only source; see db.py header.)
                    if is_intercepted(dev):
                        HISTORY.add(dev.mac, dev.down_bps, dev.up_bps, ts=now)
            if self.on_tick:
                try:
                    self.on_tick()
                except Exception:
                    pass


_monitor: Monitor | None = None


def get_monitor(on_tick=None) -> Monitor:
    global _monitor
    if _monitor is None:
        _monitor = Monitor(on_tick=on_tick)
    elif on_tick is not None:
        _monitor.on_tick = on_tick
    return _monitor
