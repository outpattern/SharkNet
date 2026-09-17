"""
Gate 6.3 — scapy-free raw parsers proven field-equivalent to scapy, plus the
domain-blocking-through-the-forwarder proof that the native _Frame limitation is
fixed, and MAC->vendor lookup against the bundled OUI JSON.

Scapy is used ONLY as the golden oracle here (it remains installed until 6.4).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest                                                    # noqa: E402
from backend.engine import rawpkt, domains, vendors, npcap        # noqa: E402

from scapy.layers.l2 import Ether, ARP                            # noqa: E402
from scapy.layers.inet import IP, TCP, UDP, IPOption              # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR                    # noqa: E402
from scapy.layers.dhcp import DHCP, BOOTP                         # noqa: E402


# ---------------------------------------------------------------- helpers
def _client_hello(host: bytes) -> bytes:
    """Minimal TLS1.2 ClientHello record carrying an SNI extension for `host`."""
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host   # type host_name(0)
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    ext_block = len(sni_ext).to_bytes(2, "big") + sni_ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +                 # version, random, sid_len=0
            b"\x00\x02" + b"\x00\x2f" +                            # cipher suites
            b"\x01" + b"\x00" +                                    # compression
            ext_block)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body            # handshake ClientHello
    return b"\x16" + b"\x03\x03" + len(hs).to_bytes(2, "big") + hs  # TLS record


MY = "02:00:00:00:00:aa"
DEV = "de:ad:be:ef:00:01"


# ---------------------------------------------------------------- ARP
def test_build_arp_request_matches_scapy():
    mine = rawpkt.build_arp("ff:ff:ff:ff:ff:ff", MY, 1, MY, "192.168.1.5",
                            "00:00:00:00:00:00", "192.168.1.1")
    theirs = bytes(Ether(dst="ff:ff:ff:ff:ff:ff", src=MY) /
                   ARP(op=1, hwsrc=MY, psrc="192.168.1.5",
                       hwdst="00:00:00:00:00:00", pdst="192.168.1.1"))
    assert mine == theirs


@pytest.mark.parametrize("op", [1, 2])
def test_parse_arp_fields_match_scapy(op):
    p = Ether(dst="ff:ff:ff:ff:ff:ff", src=DEV) / ARP(
        op=op, hwsrc=DEV, psrc="192.168.1.50", hwdst="11:22:33:44:55:66", pdst="192.168.1.1")
    frame = bytes(p)
    got = rawpkt.parse_arp(frame)
    a = p[ARP]
    assert got == (a.op, a.hwsrc, a.psrc, a.hwdst, a.pdst)


def test_parse_arp_rejects_non_arp_and_truncated():
    assert rawpkt.parse_arp(b"") is None
    assert rawpkt.parse_arp(b"\x00" * 20) is None
    ip = bytes(Ether(dst=MY, src=DEV) / IP() / TCP())
    assert rawpkt.parse_arp(ip) is None                            # IPv4, not ARP
    arp = bytes(Ether(dst="ff:ff:ff:ff:ff:ff", src=DEV) / ARP())
    assert rawpkt.parse_arp(arp[:30]) is None                      # truncated


# ---------------------------------------------------------------- L4 offsets
def test_l4_payload_tcp_udp_match_scapy():
    body = b"HELLO-PAYLOAD"
    tp = Ether(dst=MY, src=DEV) / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(dport=443) / body
    proto, _s, dport, pay = rawpkt.l4_payload(bytes(tp))
    assert (proto, dport, pay) == (6, 443, bytes(tp[TCP].payload))
    up = Ether(dst=MY, src=DEV) / IP() / UDP(dport=53) / body
    proto, _s, dport, pay = rawpkt.l4_payload(bytes(up))
    assert (proto, dport, pay) == (17, 53, bytes(up[UDP].payload))


def test_l4_payload_handles_ip_options_and_tcp_options():
    body = b"OPTS-BODY"
    # IPv4 options -> IHL > 5 ; TCP options -> data offset > 5
    pkt = (Ether(dst=MY, src=DEV) /
           IP(src="10.0.0.2", dst="10.0.0.1", options=[IPOption(b"\x94\x04\x00\x00")]) /
           TCP(dport=443, options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]) / body)
    raw = bytes(pkt)
    assert (raw[14] & 0x0F) > 5                                    # IHL includes options
    proto, _s, dport, pay = rawpkt.l4_payload(raw)
    assert proto == 6 and dport == 443 and pay == bytes(pkt[TCP].payload) == body


def test_l4_payload_rejects_short():
    assert rawpkt.l4_payload(b"") is None
    assert rawpkt.l4_payload(b"\x00" * 20) is None


# ---------------------------------------------------------------- DNS
def test_dns_question_name_matches_scapy_query():
    q = Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    _p, _s, dport, payload = rawpkt.l4_payload(bytes(q))
    assert dport == 53
    got = rawpkt.dns_question_name(payload)
    assert got == q[DNS].qd.qname.decode().rstrip(".") == "example.com"


def test_dns_question_name_ignores_responses():
    r = DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="1.2.3.4"))
    assert rawpkt.dns_question_name(bytes(r)) is None               # qr=1 -> not a query
    assert rawpkt.dns_question_name(b"") is None


# ---------------------------------------------------------------- DHCP
def test_dhcp_hostname_matches_scapy():
    chaddr = bytes.fromhex(DEV.replace(":", ""))
    pkt = (Ether() / IP() / UDP(sport=68, dport=67) /
           BOOTP(chaddr=chaddr) / DHCP(options=[("hostname", b"my-laptop"), ("end")]))
    _p, _s, _d, payload = rawpkt.l4_payload(bytes(pkt))
    host, mac = rawpkt.dhcp_hostname(payload)
    assert host == "my-laptop"
    assert mac == DEV


def test_dhcp_hostname_rejects_non_dhcp():
    host, mac = rawpkt.dhcp_hostname(b"\x00" * 300)                 # no magic cookie
    assert host is None and mac is None
    assert rawpkt.dhcp_hostname(b"") == (None, None)


# ---------------------------------------------------------------- domains (raw == scapy oracle)
def _scapy_domain_oracle(pkt):
    """The former scapy getlayer() logic, kept here as the equivalence oracle."""
    from backend.engine.domains import _norm, _tls_sni, _HOST_RE
    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        dport = tcp.dport
        if dport != 443 and dport not in (80, 8080, 8000, 8888):
            return None
        raw = getattr(tcp.payload, "load", None) or bytes(tcp.payload)
        if not raw:
            return None
        if dport == 443:
            d = _norm(_tls_sni(raw))
            return (d, "tls") if d else None
        m = _HOST_RE.search(raw[:400])
        d = _norm(m.group(1)) if m else None
        return (d, "http") if d else None
    udp = pkt.getlayer(UDP)
    if udp is not None and udp.dport == 53:
        dns = pkt.getlayer(DNS)
        if dns is not None and dns.qr == 0 and dns.qd is not None:
            d = _norm(dns.qd.qname)
            return (d, "dns") if d else None
    return None


def _wrap(scapy_pkt):
    """A native _Frame carrying the scapy packet's bytes (what capture delivers)."""
    return npcap._Frame(bytes(scapy_pkt))


def test_parse_domain_sni_http_dns_equivalent_to_scapy():
    sni = Ether(dst=MY, src=DEV) / IP() / TCP(dport=443) / _client_hello(b"example.com")
    http = Ether(dst=MY, src=DEV) / IP() / TCP(dport=80) / (b"GET / HTTP/1.1\r\nHost: test.org\r\n\r\n")
    dns = Ether(dst=MY, src=DEV) / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="site.net"))
    for p, expect in [(sni, ("example.com", "tls")),
                      (http, ("test.org", "http")),
                      (dns, ("site.net", "dns"))]:
        assert domains.parse_domain(_wrap(p)) == expect            # raw path on a native _Frame
        assert domains.parse_domain(_wrap(p)) == _scapy_domain_oracle(p)   # == scapy oracle


def test_parse_domain_with_ip_and_tcp_options():
    p = (Ether(dst=MY, src=DEV) /
         IP(options=[IPOption(b"\x94\x04\x00\x00")]) /
         TCP(dport=443, options=[("MSS", 1460), ("NOP", None)]) / _client_hello(b"opt.example"))
    assert domains.parse_domain(_wrap(p)) == ("opt.example", "tls")


def test_parse_domain_malformed_returns_none():
    assert domains.parse_domain(npcap._Frame(b"")) is None
    assert domains.parse_domain(npcap._Frame(b"\x00" * 10)) is None
    # a non-request TCP port yields nothing
    p = Ether(dst=MY, src=DEV) / IP() / TCP(dport=22) / b"ssh"
    assert domains.parse_domain(_wrap(p)) is None


# ------------------------------------------- domain BLOCKING through the real forwarder
def test_domain_blocking_fires_on_native_frame_through_forwarder():
    """The Gate 5b limitation is fixed: a blocked-domain request delivered as a
    native _Frame is now DROPPED by the real forwarder (was forwarded in 5b)."""
    from backend.engine.forwarder import Forwarder
    from backend.engine.spoofer import SPOOFER
    from backend.engine import netinfo
    from backend.state import STATE, Device

    prev_iface, prev_gw = STATE.interface, SPOOFER._gateway_mac
    try:
        STATE.interface = netinfo.Interface(name="t", description="t", ip="192.168.9.2",
                                            mac=MY, netmask="255.255.255.0",
                                            gateway="192.168.9.1", cidr="192.168.9.0/24")
        STATE.devices.clear()
        dev = Device(ip="192.168.9.50", mac=DEV, mode="allow", blocked=["example.com"])
        STATE.devices[dev.ip] = dev                                # managed via domain block
        SPOOFER._gateway_mac = "aa:bb:cc:dd:ee:ff"

        fw = Forwarder()
        fw._my_mac_b = fw._mac_to_bytes(MY)
        sent = []
        fw._inj = type("S", (), {"send": lambda self, b: sent.append(b)})()

        def frame_for(host):
            p = (Ether(dst=MY, src=DEV) / IP(src="192.168.9.50", dst="93.1.2.3") /
                 TCP(dport=443) / _client_hello(host))
            return npcap._Frame(bytes(p))

        fw._handle(frame_for(b"example.com"))                      # blocked -> dropped
        assert sent == [], "blocked domain must be dropped (native-frame limitation fixed)"
        fw._handle(frame_for(b"allowed.org"))                      # not blocked -> forwarded
        assert len(sent) == 1, "non-blocked request must be forwarded"
    finally:
        STATE.interface, SPOOFER._gateway_mac = prev_iface, prev_gw
        STATE.devices.clear()


# ---------------------------------------------------------------- vendors (OUI JSON)
def test_vendor_lookup_uses_oui_json():
    # 04:D9:F5 is ASUS in oui_vendors.json (and is this host's NIC prefix)
    assert vendors.lookup("04:d9:f5:08:0c:32") == "ASUS"
    assert vendors.lookup("00:03:93:11:22:33") == "Apple"          # Apple prefix in JSON
    assert vendors.lookup("B8:27:EB:00:00:01") == "Raspberry Pi"


def test_vendor_builtin_precedence_and_fallbacks():
    # a prefix in the built-in table resolves without the JSON
    assert vendors.lookup("F0:DB:F8:00:00:01") == "Apple"
    # locally-administered / randomized MAC (bit 0x02 set), not in any DB
    assert vendors.lookup("02:11:22:33:44:55") == "Private (randomized MAC)"
    # globally-unique but unlisted -> Unknown
    assert vendors.lookup("0C:AB:CD:00:00:01") == "Unknown"
    assert vendors.lookup("") == "Unknown"
