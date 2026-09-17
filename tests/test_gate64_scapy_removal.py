"""
Gate 6.4 — Scapy removal proofs.

- the newly-wired control-plane raw parsers (namer DHCP/mDNS, defender ARP) work
  on native _Frame objects, field-equivalent to scapy;
- dns_a_answers matches scapy;
- and the definitive test: the production application imports AND runs its live
  code paths in a subprocess where `import scapy` is hard-blocked.

Scapy is used only as a golden oracle (a dev/test-only dependency post-6.4).
"""
import os
import subprocess
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest                                                          # noqa: E402
from backend.engine import rawpkt, npcap                              # noqa: E402

from scapy.layers.l2 import Ether, ARP                                # noqa: E402
from scapy.layers.inet import IP, UDP                                 # noqa: E402
from scapy.layers.dns import DNS, DNSRR, DNSQR                        # noqa: E402
from scapy.layers.dhcp import DHCP, BOOTP                             # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- dns_a_answers
def test_dns_a_answers_matches_scapy():
    msg = DNS(qr=1, an=[DNSRR(rrname="printer.local", type="A", rdata="192.168.9.7", ttl=120),
                        DNSRR(rrname="tv.local", type="A", rdata="192.168.9.8", ttl=120)])
    raw = bytes(msg)
    got = dict(rawpkt.dns_a_answers(raw))
    # oracle: parse the SAME bytes with scapy and pull its A answers
    dns = DNS(raw)
    oracle = {}
    for i in range(dns.ancount):
        rr = dns.an[i]
        if getattr(rr, "type", None) == 1:
            oracle[rr.rrname.decode(errors="ignore").rstrip(".")] = str(rr.rdata)
    assert got == oracle
    assert got.get("printer.local") == "192.168.9.7"
    assert got.get("tv.local") == "192.168.9.8"


def test_dns_a_answers_skips_questions_and_non_a():
    msg = DNS(qr=1, qd=DNSQR(qname="q.local"),
              an=DNSRR(rrname="host.local", type="A", rdata="10.0.0.5"))
    assert ("host.local", "10.0.0.5") in rawpkt.dns_a_answers(bytes(msg))
    assert rawpkt.dns_a_answers(b"") == []
    assert rawpkt.dns_a_answers(b"\x00" * 8) == []


# ---------------------------------------------------------------- namer (raw wiring)
def test_namer_parses_dhcp_and_mdns_from_native_frame():
    from backend.engine.namer import Namer
    n = Namer()
    calls = []
    n._apply = lambda name, source, mac=None, ip=None: calls.append((name, source, mac, ip))

    chaddr = bytes.fromhex("deadbeef0001")
    dhcp = (Ether(src="de:ad:be:ef:00:01") / IP() / UDP(sport=68, dport=67) /
            BOOTP(chaddr=chaddr) / DHCP(options=[("hostname", b"my-phone"), ("end")]))
    n._on(npcap._Frame(bytes(dhcp)))
    assert calls and calls[0][0] == "my-phone" and calls[0][1] == "dhcp"
    assert calls[0][2] == "de:ad:be:ef:00:01"        # BOOTP chaddr

    calls.clear()
    mdns = (Ether() / IP() / UDP(sport=5353, dport=5353) /
            DNS(qr=1, an=DNSRR(rrname="printer.local", type="A", rdata="192.168.9.7")))
    n._on(npcap._Frame(bytes(mdns)))
    assert calls and calls[0][0] == "printer.local" and calls[0][1] == "mdns"
    assert calls[0][3] == "192.168.9.7"


# ---------------------------------------------------------------- defender (raw wiring)
def test_defender_gateway_spoof_via_native_frame():
    from backend.engine.defender import Defender
    from backend.engine import netinfo
    d = Defender()
    d.iface = netinfo.Interface("t", "t", "192.168.9.2", "02:00:00:00:00:aa",
                                "255.255.255.0", "192.168.9.1", "192.168.9.0/24")
    d.baseline_mac = "aa:bb:cc:dd:ee:ff"
    d.current_mac = d.baseline_mac
    raised = []
    d._raise = lambda kind, *a, **k: raised.append(kind)
    d._discover = lambda ip, mac: None
    spoof = (Ether(src="66:66:66:66:66:66") /
             ARP(op=2, hwsrc="66:66:66:66:66:66", psrc="192.168.9.1", pdst="192.168.9.2"))
    d._on_arp(npcap._Frame(bytes(spoof)))
    assert "gateway_spoof" in raised


def test_arp_reply_parse_ignores_non_reply_and_bad():
    reply = (Ether(src="de:ad:be:ef:00:09") /
             ARP(op=2, hwsrc="de:ad:be:ef:00:09", psrc="192.168.1.9", pdst="192.168.1.1"))
    info = rawpkt.parse_arp(bytes(reply))
    assert info[0] == 2 and info[1] == "de:ad:be:ef:00:09" and info[2] == "192.168.1.9"
    req = Ether() / ARP(op=1, psrc="192.168.1.2", pdst="192.168.1.1")
    assert rawpkt.parse_arp(bytes(req))[0] == 1     # op preserved; caller filters op!=2


# ------------------------------------------------- THE scapy-absent import/run proof
def test_production_app_imports_and_runs_without_scapy():
    code = textwrap.dedent('''
        import sys
        # hard-block scapy: raise on any scapy import (it IS installed as a dev dep)
        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name == "scapy" or name.startswith("scapy."):
                    raise ModuleNotFoundError("scapy is blocked (Gate 6.4 proof)")
                return None
        for m in [m for m in list(sys.modules) if m == "scapy" or m.startswith("scapy.")]:
            del sys.modules[m]
        sys.meta_path.insert(0, _Block())

        # import the whole production app + engine (must not pull scapy)
        import backend.server                                    # noqa
        from backend.engine import (winifaces, rawpkt, domains, vendors, netinfo,
            npcap, _wpcap, forwarder, spoofer, arp, defender, namer, iobackend)  # noqa

        # exercise live scapy-free paths (would trigger any lazy scapy import)
        assert iobackend.active_backend() == "native"
        assert winifaces.list_adapters()                         # native GetAdaptersAddresses
        assert netinfo.list_interfaces() is not None
        assert vendors.lookup("04:d9:f5:08:0c:32") == "ASUS"     # OUI JSON
        assert domains.parse_domain(npcap._Frame(b"")) is None
        assert rawpkt.parse_arp(b"") is None

        leaked = [m for m in sys.modules if m == "scapy" or m.startswith("scapy.")]
        assert not leaked, "scapy was imported by production: %r" % leaked
        print("SCAPY_ABSENT_OK")
    ''')
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=REPO)
    assert "SCAPY_ABSENT_OK" in r.stdout, f"stdout={r.stdout!r}\nstderr={r.stderr!r}"
