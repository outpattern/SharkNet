"""
Runtime diagnostics (V3.1) — READ-ONLY observation of SharkNet's own resource use
and current workload.

HARD ARCHITECTURAL RULE: this module only READS existing state/counters and the
host process metrics. It NEVER writes device.mode, monitor state, enforcement
rules, ARP/forwarding/protection state, or notification policy. It adds no packet
capture, no sniffer, no monitoring loop, and nothing to the packet hot path. A
diagnostics failure can never destabilize SharkNet — every metric fails
independently to the string "Unavailable".

Data sources (all pre-existing, read cheaply):
  * CPU / RAM / child-process (WebView) usage : psutil on THIS process only
  * engine status            : STATE.controlling / STATE.scanning (authoritative)
  * monitored / enforced counts : STATE + is_managed/is_intercepted (the SAME
                                  predicates enforcement uses — no re-derivation)
  * packet rate              : FORWARDER.packets_total delta over wall time
  * intercepted throughput   : sum of dev.down_bps + dev.up_bps for intercepted
                               devices — already computed by the 1 Hz monitor
Sampling is caller-driven (the UI polls ~1 Hz); nothing here runs on its own
unless a Performance Check is explicitly requested.
"""
from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger("sharknet.engine")

UNAVAILABLE = "Unavailable"

# --- LOW/NORMAL/HIGH thresholds -------------------------------------------------
# Centralized + easy to adjust. These are an APPLICATION-HEALTH indicator, not a
# hardware requirement, and they NEVER trigger any automatic behaviour. A status
# is HIGH if ANY pressure signal is high; LOW only if ALL are clearly low.
THRESHOLDS = {
    "cpu_high": 25.0,      # % of one core, SharkNet's own process
    "cpu_low": 5.0,
    "ram_high_mb": 400.0,  # SharkNet main process RSS
    "ram_low_mb": 200.0,
    "pkts_high": 20000.0,  # intercepted frames/sec
    "pkts_low": 2000.0,
    "mbps_high": 150.0,    # intercepted throughput
    "mbps_low": 20.0,
}

_lock = threading.Lock()
_proc = None                       # cached psutil.Process for THIS process
_last_pkt = {"ts": 0.0, "count": 0}


def _process():
    global _proc
    if _proc is not None:
        return _proc
    try:
        import psutil
        _proc = psutil.Process()
        # prime cpu_percent so the first real read is meaningful, not a spurious 0
        try:
            _proc.cpu_percent(None)
        except Exception:
            pass
    except Exception as e:
        log.info("diagnostics: psutil unavailable (%s)", e)
        _proc = None
    return _proc


# ---------------------------------------------------------------- individual metrics
def _cpu_percent():
    p = _process()
    if p is None:
        return None
    try:
        # non-blocking: % since the previous call (the UI polls ~1 Hz, so this is
        # a ~1 s window). Never sleeps, so it can't stall the request loop.
        return round(float(p.cpu_percent(None)), 1)
    except Exception:
        return None


def _ram_mb():
    p = _process()
    if p is None:
        return None
    try:
        return round(p.memory_info().rss / (1024 * 1024), 1)
    except Exception:
        return None


def _webview_mb():
    """Sum RSS of THIS process's own WebView2 children only. If children cannot be
    reliably attributed, return None (-> 'Unavailable') rather than a fake number.
    Never sums every msedgewebview2.exe on the machine."""
    p = _process()
    if p is None:
        return None
    try:
        total = 0.0
        found = False
        for child in p.children(recursive=True):
            try:
                name = (child.name() or "").lower()
            except Exception:
                continue
            if "webview" in name or "msedgewebview2" in name:
                try:
                    total += child.memory_info().rss / (1024 * 1024)
                    found = True
                except Exception:
                    continue
        return round(total, 1) if found else None
    except Exception:
        return None


def _engine_status():
    """Authoritative runtime status — reuses STATE, no second health system."""
    try:
        from .state import STATE
        if STATE.controlling:
            return "Starting" if STATE.scanning and not STATE.enforcing else "Running"
        return "Stopped"
    except Exception:
        return UNAVAILABLE


def _device_counts():
    """(monitored, enforced) from the SAME predicates enforcement uses. Read-only."""
    try:
        from .state import STATE, is_managed
        with STATE.lock:
            devs = list(STATE.devices.values())
        monitored = sum(1 for d in devs if getattr(d, "monitor", False))
        enforced = sum(1 for d in devs if is_managed(d))
        return monitored, enforced
    except Exception:
        return None, None


def _packet_rate():
    """Frames/sec from FORWARDER.packets_total delta since the last call. First
    call (or after a counter reset) returns None until a second sample exists."""
    try:
        from .engine.forwarder import FORWARDER
        now = time.time()
        count = int(FORWARDER.packets_total)
        with _lock:
            last_ts = _last_pkt["ts"]
            last_count = _last_pkt["count"]
            _last_pkt["ts"] = now
            _last_pkt["count"] = count
        if last_ts <= 0:
            return None                      # need a baseline first
        dt = now - last_ts
        if dt <= 0:
            return None
        delta = count - last_count
        if delta < 0:                        # counter reset (engine restart)
            return None
        return round(delta / dt)
    except Exception:
        return None


def _throughput_mbps():
    """Intercepted throughput = live per-device bps the 1 Hz monitor already
    computed, summed over intercepted devices, in Mbps. Read-only."""
    try:
        from .state import STATE, is_intercepted
        with STATE.lock:
            bps = sum((d.down_bps + d.up_bps) for d in STATE.devices.values()
                      if is_intercepted(d))
        return round((bps * 8) / 1e6, 1)     # bytes/s -> Mbps
    except Exception:
        return None


# ---------------------------------------------------------------- classification
def _num(v):
    return v if isinstance(v, (int, float)) else None


def classify(cpu, ram_mb, pkts, mbps) -> str:
    """LOW / Normal / HIGH — informational only, never triggers any action.
    HIGH if any signal is high; LOW only when every available signal is clearly
    low; otherwise Normal. Missing signals are ignored (never force a grade)."""
    T = THRESHOLDS
    highs, lows, seen = [], [], 0
    for val, hi, lo in ((_num(cpu), T["cpu_high"], T["cpu_low"]),
                        (_num(ram_mb), T["ram_high_mb"], T["ram_low_mb"]),
                        (_num(pkts), T["pkts_high"], T["pkts_low"]),
                        (_num(mbps), T["mbps_high"], T["mbps_low"])):
        if val is None:
            continue
        seen += 1
        highs.append(val >= hi)
        lows.append(val <= lo)
    if seen == 0:
        return UNAVAILABLE
    if any(highs):
        return "High"
    if all(lows):
        return "Low"
    return "Normal"


# ---------------------------------------------------------------- public API
def snapshot() -> dict:
    """One cheap read-only sample. Every field is a value or the string
    'Unavailable'; this function never raises."""
    cpu = _cpu_percent()
    ram = _ram_mb()
    web = _webview_mb()
    monitored, enforced = _device_counts()
    pkts = _packet_rate()
    mbps = _throughput_mbps()
    status = classify(cpu, ram, pkts, mbps)

    def show(v):
        return UNAVAILABLE if v is None else v

    return {
        "cpu_percent": show(cpu),
        "ram_mb": show(ram),
        "webview_mb": show(web),
        "engine": _engine_status(),
        "monitored_devices": show(monitored),
        "enforced_devices": show(enforced),
        "packet_rate": show(pkts),
        "throughput_mbps": show(mbps),
        "performance_status": status,
    }


def _agg(values):
    nums = [v for v in values if isinstance(v, (int, float))]
    if not nums:
        return None, None
    return round(sum(nums) / len(nums), 1), round(max(nums), 1)


def performance_check(duration: float = 12.0, interval: float = 1.0,
                      sampler=None, sleep=time.sleep) -> dict:
    """Observe the REAL CURRENT workload for ~duration seconds and summarise it.

    This changes NOTHING: it does not generate traffic, inject packets, alter any
    device rule, enable Monitor, or touch interception — it only calls snapshot()
    on a timer and aggregates. `sampler`/`sleep` are injectable for tests.
    """
    sampler = sampler or snapshot
    duration = max(2.0, min(float(duration), 30.0))     # bounded window
    interval = max(0.2, float(interval))
    cpus, rams, pkts, mbpss, mons, enfs = [], [], [], [], [], []
    ram_first = ram_last = None
    deadline = time.time() + duration
    n = 0
    while time.time() < deadline:
        s = sampler()
        cpus.append(s.get("cpu_percent"))
        rams.append(s.get("ram_mb"))
        pkts.append(s.get("packet_rate"))
        mbpss.append(s.get("throughput_mbps"))
        mons.append(s.get("monitored_devices"))
        enfs.append(s.get("enforced_devices"))
        if isinstance(s.get("ram_mb"), (int, float)):
            if ram_first is None:
                ram_first = s["ram_mb"]
            ram_last = s["ram_mb"]
        n += 1
        sleep(interval)

    cpu_avg, cpu_peak = _agg(cpus)
    _, ram_peak = _agg(rams)
    pkt_avg, pkt_peak = _agg(pkts)
    mbps_avg, mbps_peak = _agg(mbpss)
    _, mon_peak = _agg(mons)
    _, enf_peak = _agg(enfs)
    ram_delta = (round(ram_last - ram_first, 1)
                 if isinstance(ram_first, (int, float)) and isinstance(ram_last, (int, float))
                 else None)
    status = classify(cpu_peak, ram_peak, pkt_peak, mbps_peak)

    def show(v):
        return UNAVAILABLE if v is None else v

    return {
        "samples": n,
        "duration_s": round(duration, 1),
        "cpu_avg": show(cpu_avg),
        "cpu_peak": show(cpu_peak),
        "ram_mb": show(ram_last if ram_last is not None else None),
        "ram_delta_mb": show(ram_delta),
        "packet_rate_avg": show(pkt_avg),
        "packet_rate_peak": show(pkt_peak),
        "throughput_avg_mbps": show(mbps_avg),
        "throughput_peak_mbps": show(mbps_peak),
        "monitored_devices": show(mon_peak),
        "enforced_devices": show(enf_peak),
        "performance_status": status,
    }
