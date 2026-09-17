"""
Network Health honesty: a dropped ICMP ping (common under SharkNet's own MITM /
Npcap load) must NOT be reported as "Offline / 100% loss" when the internet is
actually reachable. A TCP handshake is the reachability source of truth; ICMP is
only for latency. A genuine outage (every signal fails) still grades offline.
"""
import pytest

from backend.state import STATE
from backend.engine import health as H
from backend.engine.health import Health
from backend.engine import netinfo


@pytest.fixture(autouse=True)
def _reset():
    STATE.enforcing = False
    STATE.interface = netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")
    yield
    STATE.enforcing = False
    STATE.interface = None


def test_tcp_reach_refused_counts_as_reachable(monkeypatch):
    # a RST (ConnectionRefused) proves the host answered -> reachable
    monkeypatch.setattr(H.socket, "create_connection",
                        lambda addr, timeout=0: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert H._tcp_reach("1.1.1.1", 443) is True
    # a timeout -> not reachable
    monkeypatch.setattr(H.socket, "create_connection",
                        lambda addr, timeout=0: (_ for _ in ()).throw(OSError("timed out")))
    assert H._tcp_reach("1.1.1.1", 443) is False


def test_dropped_icmp_but_tcp_reachable_is_not_offline(monkeypatch):
    """The exact bug: ICMP 100% lost while enforcing, but TCP reaches the net."""
    STATE.enforcing = True
    monkeypatch.setattr(H, "_ping", lambda host, count=1, timeout_ms=800: (None, 100.0))
    monkeypatch.setattr(H, "_tcp_reach", lambda host, port, timeout=1.2: True)
    monkeypatch.setattr(H, "_dns_ok", lambda: False)
    h = Health()
    h._check_connectivity()
    assert h.data["internet_online"] is True          # not offline
    assert h.data["gateway_online"] is True
    assert h.data["packet_loss"] == 0.0               # NOT a misleading 100%
    assert h.data["grade"] == "good"                  # healthy, policy-influenced
    assert h.data["policy_influenced"] is True


def test_genuine_outage_still_offline(monkeypatch):
    monkeypatch.setattr(H, "_ping", lambda host, count=1, timeout_ms=800: (None, 100.0))
    monkeypatch.setattr(H, "_tcp_reach", lambda host, port, timeout=1.2: False)
    monkeypatch.setattr(H, "_dns_ok", lambda: False)
    h = Health()
    h._check_connectivity()
    assert h.data["internet_online"] is False
    assert h.data["grade"] == "offline"               # real outage never masked
    assert h.data["packet_loss"] == 100.0


def test_normal_icmp_latency_grades_on_latency(monkeypatch):
    monkeypatch.setattr(H, "_ping", lambda host, count=1, timeout_ms=800: (12.0, 0.0))
    monkeypatch.setattr(H, "_tcp_reach", lambda host, port, timeout=1.2: True)
    monkeypatch.setattr(H, "_dns_ok", lambda: True)
    h = Health()
    h._check_connectivity()
    assert h.data["internet_online"] is True
    assert h.data["latency_ms"] == 12.0
    assert h.data["grade"] == "excellent"
    assert h.data["policy_influenced"] is False


def test_grade_offline_takes_priority():
    h = Health()
    h.data.update(internet_online=False, gateway_online=True, dns_online=True,
                  latency_ms=None, packet_loss=100.0)
    assert h._grade() == "offline"
