"""
Asynchronous domain observation (v2.9).

Before v2.9 the forwarder parsed every outbound packet's SNI/Host/DNS *inline*
on the enforcement hot path, even when the device had no domain blocks and the
result was used only to populate the UI's visited-domains list.

v2.9 keeps ACTIVE domain blocking inline and deterministic (the drop decision
must happen before the packet is forwarded), but moves passive observation-only
parsing onto this bounded background queue. The hot path just hands off a packet
reference (O(1)); a worker thread parses it and records the visit. The queue is
bounded and never blocks the sniffer callback — under a flood it drops the
overflow (we lose some *observations*, never any *forwarding* or *blocking*).
"""
from __future__ import annotations

import logging
import queue
import threading

from . import domains as domains_engine

log = logging.getLogger("sharknet.engine")

_MAX_QUEUE = 4096


class DomainObserver:
    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUE)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stop = object()          # sentinel
        self.dropped = 0               # observations lost to a full queue (diag)

    # ---- lifecycle ----
    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="sharknet-domain-observer")
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            t = self._thread
            self._thread = None
        if t and t.is_alive():
            try:
                self._q.put_nowait(self._stop)
            except queue.Full:
                # drain one slot so the sentinel fits, then signal
                try:
                    self._q.get_nowait()
                    self._q.put_nowait(self._stop)
                except Exception:
                    pass
            t.join(timeout=2)

    # ---- producer (called from the forwarder hot path) ----
    def observe(self, dev, pkt) -> None:
        """Enqueue a packet for off-hot-path domain parsing. Never blocks."""
        try:
            self._q.put_nowait((dev, pkt))
        except queue.Full:
            self.dropped += 1          # overflow -> drop the observation, not traffic

    # ---- consumer ----
    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is self._stop:
                return
            dev, pkt = item
            try:
                hit = domains_engine.parse_domain(pkt)
                if hit:
                    domains_engine.record_visit(dev, hit[0])
            except Exception:
                pass                   # a bad packet must never kill the worker


DOMAIN_OBSERVER = DomainObserver()
