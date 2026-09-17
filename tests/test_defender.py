"""
SharkNet Defender — passive ARP anomaly detection.

Regression for the V3.0 audit: `_on_arp` referenced an undefined `a.op` on the
mac-conflict path, so the generic ARP-spoof detector NameError'd exactly when it
should have fired (silently swallowed by the capture loop). These tests exercise
the real handler with crafted ARP frames.
"""
from backend.state import STATE, Device
from backend.engine.defender import Defender
from backend.engine import netinfo, rawpkt


def _iface():
    return netinfo.Interface(name="t", description="t", ip="192.168.9.2",
        mac="02:00:00:00:00:aa", netmask="255.255.255.0", gateway="192.168.9.1",
        cidr="192.168.9.0/24")


def _arp(ip, mac, op=2):
    # ARP with sender_ip=ip, sender_mac=mac (op 2 = reply, 1 = request)
    return rawpkt.build_arp("ff:ff:ff:ff:ff:ff", mac, op, mac, ip,
                            "00:00:00:00:00:00", "0.0.0.0")


def _defender():
    d = Defender()
    d.iface = _iface()
    d.baseline_mac = "aa:bb:cc:dd:ee:ff"     # gateway's legit MAC
    return d


def test_mac_conflict_detected_and_no_nameerror():
    STATE.devices.clear()
    d = _defender()
    # first time we see this (non-gateway) IP -> learned, no alert
    d._on_arp(_arp("192.168.9.50", "11:11:11:11:11:11"))
    assert d.alert is None
    assert d._seen.get("192.168.9.50") == "11:11:11:11:11:11"
    # the same IP now claims a DIFFERENT MAC via ARP reply -> mac_conflict raised
    # (this path previously raised NameError on `a.op` and was swallowed)
    d._on_arp(_arp("192.168.9.50", "22:22:22:22:22:22"))
    assert d.alert is not None, "mac_conflict alert was not raised"
    assert d.alert.get("type") == "mac_conflict"
    assert d.anomalies >= 1
    STATE.devices.clear()


def test_arp_request_does_not_trigger_mac_conflict():
    # a MAC change seen via ARP REQUEST (op=1) must NOT be flagged (guard is op==2)
    STATE.devices.clear()
    d = _defender()
    d._on_arp(_arp("192.168.9.60", "11:11:11:11:11:11", op=2))
    d._on_arp(_arp("192.168.9.60", "22:22:22:22:22:22", op=1))
    assert d.alert is None
    STATE.devices.clear()


def test_our_own_arp_is_ignored():
    # ARP sourced from our own MAC (our scanning/spoofing) is never an anomaly
    STATE.devices.clear()
    d = _defender()
    d._on_arp(_arp("192.168.9.70", "02:00:00:00:00:aa"))   # == iface.mac
    assert d.alert is None
    assert "192.168.9.70" not in d._seen
    STATE.devices.clear()


# ---- passive same-IP identity re-key (release audit: wrong-device enforcement) ----
def _put(ip, mac, **kw):
    d = Device(ip=ip, mac=mac, **kw)
    STATE.devices[ip] = d
    return d


def test_same_ip_identity_change_resets_stale_enforcement():
    """DHCP reassigns a CUT device's IP to a NEW device before a full rescan.
    The new occupant must NOT inherit the previous device's cut/limit/blocks —
    otherwise the IP-keyed gateway poison would blackhole a device never cut."""
    STATE.devices.clear()
    d = _defender()
    _put("192.168.9.50", "11:11:11:11:11:11", mode="cut",
         blocked=["ads.example"], services=["netflix"], monitor=True,
         down_kbps=500, up_kbps=300)
    # a DIFFERENT device now answers for .50
    d._discover("192.168.9.50", "22:22:22:22:22:22")
    dev = STATE.devices["192.168.9.50"]
    assert dev.mac.lower() == "22:22:22:22:22:22", "IP must re-key to the new MAC"
    assert dev.mode == "allow", "new occupant must not inherit the cut"
    assert dev.down_kbps == 0 and dev.up_kbps == 0
    assert dev.blocked == [] and dev.services == [] and dev.monitor is False
    assert dev.eff_blocked == (), "effective block set must be cleared"


def test_same_ip_same_mac_is_not_reset():
    """A normal repeat ARP from the SAME device must NOT clear its enforcement."""
    STATE.devices.clear()
    d = _defender()
    _put("192.168.9.50", "11:11:11:11:11:11", mode="cut", blocked=["ads.example"])
    d._discover("192.168.9.50", "11:11:11:11:11:11")
    dev = STATE.devices["192.168.9.50"]
    assert dev.mode == "cut" and dev.blocked == ["ads.example"], "must stay enforced"


def test_gateway_ip_is_never_rekeyed_by_passive_arp():
    """The gateway's identity is guarded by gateway-spoof detection, never re-keyed
    from a passive ARP (an attacker claiming the gateway IP must not overwrite it)."""
    STATE.devices.clear()
    d = _defender()
    _put("192.168.9.1", "de:ad:be:ef:00:01", is_gateway=True)
    d._discover("192.168.9.1", "at:ta:ck:er:00:99")
    assert STATE.devices["192.168.9.1"].mac == "de:ad:be:ef:00:01", "gateway MAC unchanged"
