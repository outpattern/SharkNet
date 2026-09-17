"""
V3.1 Runtime Diagnostics — READ-ONLY observation.

Pins the hard rule: diagnostics READS existing counters/state and process metrics
and NEVER writes any enforcement/monitor/interception/notification state. A
diagnostics failure must never destabilize SharkNet. Includes a structural
assertion that the module imports no enforcement-mutation surface.
"""
from __future__ import annotations

import ast
import inspect

import pytest

from backend import diagnostics
from backend.engine.forwarder import FORWARDER


# --------------------------------------------------- snapshot is read-only + safe
def _reset_pkt_baseline():
    with diagnostics._lock:
        diagnostics._last_pkt["ts"] = 0.0
        diagnostics._last_pkt["count"] = 0


def test_snapshot_has_all_fields_and_never_raises():
    snap = diagnostics.snapshot()
    for k in ("cpu_percent", "ram_mb", "webview_mb", "engine", "monitored_devices",
              "enforced_devices", "packet_rate", "throughput_mbps", "performance_status"):
        assert k in snap


def test_snapshot_does_not_change_device_rules_or_monitor_or_interception():
    from backend.state import STATE, Device, is_managed, is_intercepted
    STATE.devices.clear()
    d1 = Device(ip="10.0.0.1", mac="a", mode="cut")
    d2 = Device(ip="10.0.0.2", mac="b", mode="limit", down_kbps=500)
    d3 = Device(ip="10.0.0.3", mac="c"); d3.monitor = True
    for d in (d1, d2, d3):
        STATE.devices[d.ip] = d
    before = {d.ip: (d.mode, d.down_kbps, d.up_kbps, d.monitor, is_managed(d),
                     is_intercepted(d)) for d in (d1, d2, d3)}
    for _ in range(5):
        diagnostics.snapshot()
    after = {d.ip: (d.mode, d.down_kbps, d.up_kbps, d.monitor, is_managed(d),
                    is_intercepted(d)) for d in (d1, d2, d3)}
    assert before == after, "diagnostics must not mutate any device/enforcement state"
    STATE.devices.clear()


def test_device_counts_use_the_real_predicates():
    from backend.state import STATE, Device
    STATE.devices.clear()
    STATE.devices["10.0.0.1"] = Device(ip="10.0.0.1", mac="a", mode="cut")      # enforced
    STATE.devices["10.0.0.2"] = Device(ip="10.0.0.2", mac="b", mode="hardcut")  # enforced
    m = Device(ip="10.0.0.3", mac="c"); m.monitor = True                        # monitored only
    STATE.devices["10.0.0.3"] = m
    STATE.devices["10.0.0.9"] = Device(ip="10.0.0.9", mac="d")                  # neutral
    snap = diagnostics.snapshot()
    assert snap["enforced_devices"] == 2
    assert snap["monitored_devices"] == 1
    STATE.devices.clear()


# --------------------------------------------------- packet-rate from counter delta
def test_packet_rate_is_a_delta_of_the_existing_counter(monkeypatch):
    _reset_pkt_baseline()
    times = iter([100.0, 101.0])                      # 1 s apart
    monkeypatch.setattr(diagnostics.time, "time", lambda: next(times))
    FORWARDER.packets_total = 1000
    assert diagnostics._packet_rate() is None         # first call: baseline only
    FORWARDER.packets_total = 2200                     # +1200 over 1 s
    assert diagnostics._packet_rate() == 1200


def test_packet_rate_handles_counter_reset(monkeypatch):
    _reset_pkt_baseline()
    times = iter([200.0, 201.0])
    monkeypatch.setattr(diagnostics.time, "time", lambda: next(times))
    FORWARDER.packets_total = 5000
    diagnostics._packet_rate()                         # baseline
    FORWARDER.packets_total = 10                        # engine restarted -> smaller
    assert diagnostics._packet_rate() is None          # negative delta -> Unavailable


def test_forwarder_counter_increments_once_per_counted_frame():
    start = FORWARDER.packets_total
    FORWARDER._count("10.0.0.5", "up", 100)
    FORWARDER._count("10.0.0.5", "down", 100)
    assert FORWARDER.packets_total == start + 2


# --------------------------------------------------- throughput from byte deltas
def test_throughput_sums_intercepted_device_bps():
    from backend.state import STATE, Device
    STATE.devices.clear()
    a = Device(ip="10.0.0.1", mac="a", mode="cut"); a.down_bps = 1_000_000; a.up_bps = 250_000
    b = Device(ip="10.0.0.2", mac="b"); b.down_bps = 9_999_999  # neutral, NOT intercepted
    STATE.devices["10.0.0.1"] = a
    STATE.devices["10.0.0.2"] = b
    mbps = diagnostics._throughput_mbps()
    assert mbps == pytest.approx((1_250_000 * 8) / 1e6, abs=0.05)  # only the cut device
    STATE.devices.clear()


# --------------------------------------------------- per-metric fail-safe
def test_cpu_failure_returns_unavailable(monkeypatch):
    monkeypatch.setattr(diagnostics, "_cpu_percent", lambda: None)
    assert diagnostics.snapshot()["cpu_percent"] == diagnostics.UNAVAILABLE


def test_memory_failure_returns_unavailable(monkeypatch):
    monkeypatch.setattr(diagnostics, "_ram_mb", lambda: None)
    assert diagnostics.snapshot()["ram_mb"] == diagnostics.UNAVAILABLE


def test_webview_attribution_failure_is_safe(monkeypatch):
    monkeypatch.setattr(diagnostics, "_webview_mb", lambda: None)
    assert diagnostics.snapshot()["webview_mb"] == diagnostics.UNAVAILABLE


def test_all_metrics_failing_never_raises(monkeypatch):
    for name in ("_cpu_percent", "_ram_mb", "_webview_mb", "_packet_rate", "_throughput_mbps"):
        monkeypatch.setattr(diagnostics, name, lambda: None)
    monkeypatch.setattr(diagnostics, "_device_counts", lambda: (None, None))
    snap = diagnostics.snapshot()          # must not raise
    assert snap["performance_status"] == diagnostics.UNAVAILABLE


# --------------------------------------------------- classification (info only)
@pytest.mark.parametrize("cpu,ram,pkts,mbps,expect", [
    (1.0, 150.0, 100, 5.0, "Low"),
    (10.0, 300.0, 5000, 50.0, "Normal"),
    (50.0, 150.0, 100, 5.0, "High"),        # any high signal -> High
    (1.0, 150.0, 100, 500.0, "High"),       # throughput high -> High
    (None, None, None, None, "Unavailable"),
])
def test_classify(cpu, ram, pkts, mbps, expect):
    assert diagnostics.classify(cpu, ram, pkts, mbps) == expect


def test_classification_has_no_side_effects():
    from backend.state import STATE, Device
    STATE.devices.clear()
    d = Device(ip="10.0.0.1", mac="a", mode="cut")
    STATE.devices["10.0.0.1"] = d
    diagnostics.classify(99.0, 999.0, 99999, 999.0)   # "High"
    assert d.mode == "cut" and d.monitor is False     # HIGH triggered nothing
    STATE.devices.clear()


# --------------------------------------------------- performance check (no traffic)
def _fake_sampler():
    return {"cpu_percent": 3.0, "ram_mb": 150.0, "packet_rate": 1000,
            "throughput_mbps": 20.0, "monitored_devices": 2, "enforced_devices": 1}


def test_perfcheck_observes_only_and_generates_no_traffic(monkeypatch):
    calls = {"n": 0}

    def sampler():
        calls["n"] += 1
        return _fake_sampler()

    # a fake clock so the bounded window ends deterministically without real waits
    ticks = iter([0.0, 0.0, 1.0, 2.0, 3.0, 4.0, 100.0])
    monkeypatch.setattr(diagnostics.time, "time", lambda: next(ticks))
    r = diagnostics.performance_check(duration=3, interval=1, sampler=sampler,
                                      sleep=lambda s: None)
    assert calls["n"] >= 1
    assert r["cpu_avg"] == 3.0 and r["cpu_peak"] == 3.0
    assert r["performance_status"] == "Low"
    assert r["enforced_devices"] == 1 and r["monitored_devices"] == 2


def test_perfcheck_does_not_touch_enforcement_or_monitoring(monkeypatch):
    from backend.state import STATE, Device
    STATE.devices.clear()
    d = Device(ip="10.0.0.1", mac="a", mode="cut")
    m = Device(ip="10.0.0.2", mac="b"); m.monitor = True
    STATE.devices["10.0.0.1"] = d
    STATE.devices["10.0.0.2"] = m
    ticks = iter([0.0, 0.0, 5.0, 100.0])
    monkeypatch.setattr(diagnostics.time, "time", lambda: next(ticks))
    diagnostics.performance_check(duration=2, interval=1, sleep=lambda s: None)
    assert d.mode == "cut" and m.monitor is True     # unchanged
    STATE.devices.clear()


def test_perfcheck_duration_is_bounded(monkeypatch):
    seen = {}

    def sampler():
        return _fake_sampler()

    ticks = iter([0.0] + [float(i) for i in range(1, 200)])
    monkeypatch.setattr(diagnostics.time, "time", lambda: next(ticks))
    # even asked for 9999s, it clamps to <=30
    r = diagnostics.performance_check(duration=9999, interval=1, sampler=sampler,
                                      sleep=lambda s: None)
    assert r["duration_s"] <= 30.0


# --------------------------------------------------- shutdown/collection bounded
def test_baseline_state_is_bounded_and_resettable():
    # the only retained state is a single last-sample dict — not an unbounded log
    keys = set(diagnostics._last_pkt)
    assert keys == {"ts", "count"}


# --------------------------------------------------- structural separation
def test_diagnostics_never_imports_enforcement_mutation_surface():
    """Diagnostics may READ state; it must not import forwarder/spoofer/policy or
    the server mutation endpoints, so there is structurally no
    Diagnostics -> enforcement path."""
    tree = ast.parse(inspect.getsource(diagnostics))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
        elif isinstance(node, ast.Import):
            modules.update(a.name for a in node.names)
    banned = {"backend.engine.forwarder", "backend.engine.spoofer",
              "backend.engine.policy", "backend.server", "backend.engine.protection"}
    assert not (modules & banned), f"diagnostics imports enforcement surface: {modules & banned}"


def test_diagnostics_source_has_no_enforcement_writes():
    src = inspect.getsource(diagnostics)
    # crude but effective: no assignment to a device mode / monitor / rule call
    for needle in (".mode =", ".mode=", ".monitor =", ".monitor=", "save_rule",
                   "recompute_effective", "SPOOFER", "reconcile("):
        assert needle not in src, f"diagnostics must not write enforcement ({needle!r})"


# --------------------------------------------------- copy-summary excludes secrets
def test_copy_summary_excludes_sensitive_data():
    """The Copy Diagnostics text is built in the frontend. It may include metric
    COUNTS (e.g. 'Monitored devices: 4') but must not pull in the capability
    token, a device/domain LIST, or browsing history."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "frontend" / "js" / "g-settings.js").read_text(encoding="utf-8")
    fn = js[js.index("function copyDiagnostics"):js.index("copyText(lines.join")]
    # sensitive SOURCES that must never be read into the summary
    for banned in ("TOKEN", "password", "lastDevices", "rows", ".domains",
                   ".blocked", ".forEach", "visited", "history"):
        assert banned not in fn, f"Copy Diagnostics must not read {banned!r}"
    # it only reads the read-only DIAG snapshot fields
    assert "DIAG" in fn


# --------------------------------------------------- server endpoints read-only
def test_api_diagnostics_endpoint_is_read_only(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from backend import server
    from backend.state import STATE, Device
    STATE.devices.clear()
    d = Device(ip="10.0.0.1", mac="a", mode="cut")
    STATE.devices["10.0.0.1"] = d
    r = server.api_diagnostics()
    assert r["ok"] is True and "diagnostics" in r
    assert r["diagnostics"]["version"] == server.SHARKNET_VERSION
    assert d.mode == "cut"           # endpoint changed nothing
    STATE.devices.clear()
