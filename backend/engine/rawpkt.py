"""
Lightweight raw packet build/parse — the single scapy-free packet-utility home.

  * build_arp()  - construct a 42-byte ARP-over-Ethernet frame as raw bytes.
                   Used by the 0.25 s poison loop and ARP restore (sent over the
                   native injector, which accepts a bytes object).
  * parse_ipv4() - pull (src, dst, proto) straight out of a captured Ethernet
                   frame's bytes on the forwarding hot path (the frame is
                   guaranteed IPv4-over-Ethernet by the capture BPF
                   `ip and ether dst <mac>`).
  * parse_arp / l4_payload / dns_question_name / dns_a_answers / dhcp_hostname -
                   raw control-plane / observation parsers.

Every parser is proven field-equivalent to scapy by tests/test_gate63_parsers.py
and tests/test_gate64_scapy_removal.py (scapy is a test-only oracle). Packet
capture/inject backends live in npcap.py. Pure standard library: no scapy here.
"""
from __future__ import annotations

import socket
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806

# ARP header up to the operation field: htype=Ethernet, ptype=IPv4, hlen=6,
# plen=4. Matches scapy's ARP() defaults.
_ARP_FIXED = struct.pack("!HHBB", 0x0001, ETHERTYPE_IPV4, 6, 4)


def _mac_bytes(mac: str) -> bytes:
    b = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(b) != 6:
        raise ValueError(f"bad MAC: {mac!r}")
    return b


def build_arp(eth_dst: str, eth_src: str, op: int,
              sender_mac: str, sender_ip: str,
              target_mac: str, target_ip: str) -> bytes:
    """Build a raw ARP-over-Ethernet frame (42 bytes).

    Equivalent to:
        bytes(Ether(dst=eth_dst, src=eth_src) /
              ARP(op=op, hwsrc=sender_mac, psrc=sender_ip,
                  hwdst=target_mac, pdst=target_ip))
    """
    eth = _mac_bytes(eth_dst) + _mac_bytes(eth_src) + struct.pack("!H", ETHERTYPE_ARP)
    arp = (_ARP_FIXED + struct.pack("!H", op)
           + _mac_bytes(sender_mac) + socket.inet_aton(sender_ip)
           + _mac_bytes(target_mac) + socket.inet_aton(target_ip))
    return eth + arp


def parse_ipv4(frame: bytes):
    """Return (src_ip, dst_ip, protocol) from a raw Ethernet frame, or None.

    Assumes untagged IPv4-over-Ethernet (guaranteed by the forwarder's capture
    filter). src/dst/proto sit at fixed offsets in the IPv4 header regardless of
    IHL/options, so this is O(1) and never dissects the payload.
    """
    if len(frame) < 34:
        return None
    # EtherType at bytes 12-13 must be IPv4 (0x0800); no VLAN handling needed
    # because the capture BPF only delivers `ip` frames.
    if frame[12] != 0x08 or frame[13] != 0x00:
        return None
    if (frame[14] >> 4) != 4:            # IP version nibble
        return None
    proto = frame[23]                    # 14 (eth) + 9 (proto offset in IP hdr)
    src = socket.inet_ntoa(frame[26:30])  # 14 + 12
    dst = socket.inet_ntoa(frame[30:34])  # 14 + 16
    return src, dst, proto


# ============================================================================
# v3.0 Gate 6.3 — raw control-plane / observation parsers (scapy-free).
# Each mirrors the exact field a scapy layer produced; proven byte/field-
# equivalent to scapy in tests/test_gate63_parsers.py. All are defensive:
# malformed / truncated input returns None (never raises) so a bad packet can
# never kill a capture callback.
# ============================================================================

def _mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_arp(frame: bytes):
    """(op, sender_mac, sender_ip, target_mac, target_ip) from an ARP-over-
    Ethernet frame, or None. Mirrors scapy's ARP op / hwsrc / psrc / hwdst / pdst
    (IPv4-over-Ethernet ARP: htype=1, ptype=0x0800, hlen=6, plen=4)."""
    if len(frame) < 42:
        return None
    if frame[12] != 0x08 or frame[13] != 0x06:        # EtherType ARP
        return None
    # ARP header starts at offset 14: htype(2) ptype(2) hlen(1) plen(1) op(2)
    #   sha(6) spa(4) tha(6) tpa(4)
    if frame[18] != 6 or frame[19] != 4:              # hlen=6, plen=4 (Ethernet/IPv4)
        return None
    op = (frame[20] << 8) | frame[21]
    sender_mac = _mac_str(frame[22:28])
    sender_ip = socket.inet_ntoa(frame[28:32])
    target_mac = _mac_str(frame[32:38])
    target_ip = socket.inet_ntoa(frame[38:42])
    return op, sender_mac, sender_ip, target_mac, target_ip


def l4_payload(frame: bytes):
    """(proto, sport, dport, payload_bytes) for a TCP(6)/UDP(17) IPv4 packet, or
    None. Handles IPv4 options (variable IHL) and the TCP data-offset so the
    returned payload is the true L4 body — the offsets scapy computes via
    getlayer(TCP/UDP).payload.

    Locates the IPv4 header for BOTH an Ethernet-framed packet (the production
    case: EtherType 0x0800 at 12-13, IP at 14) and a bare IPv4 packet (IP at 0).
    Ethernet is checked first and is specific (ethertype), so a real captured
    frame always takes that path; the bare-IP branch only serves L2-less input.
    """
    n = len(frame)
    if n >= 34 and frame[12] == 0x08 and frame[13] == 0x00 and (frame[14] >> 4) == 4:
        ipo = 14                                       # Ethernet-framed IPv4
    elif n >= 20 and (frame[0] >> 4) == 4:
        ipo = 0                                        # bare IPv4 (no L2)
    else:
        return None
    if n < ipo + 20:
        return None
    ihl = (frame[ipo] & 0x0F) * 4                      # IP header length (>=20)
    if ihl < 20:
        return None
    proto = frame[ipo + 9]
    l4 = ipo + ihl                                     # transport header offset
    if proto == 6:                                     # TCP
        if n < l4 + 20:
            return None
        sport = (frame[l4] << 8) | frame[l4 + 1]
        dport = (frame[l4 + 2] << 8) | frame[l4 + 3]
        data_off = (frame[l4 + 12] >> 4) * 4           # TCP header length
        if data_off < 20:
            return None
        return proto, sport, dport, frame[l4 + data_off:]
    if proto == 17:                                    # UDP
        if n < l4 + 8:
            return None
        sport = (frame[l4] << 8) | frame[l4 + 1]
        dport = (frame[l4 + 2] << 8) | frame[l4 + 3]
        return proto, sport, dport, frame[l4 + 8:]
    return None


def _dns_name(msg: bytes, off: int):
    """Read a DNS name at `off`, following 0xC0 compression pointers. Returns
    (name_str, next_offset_after_the_name) or (None, off) on malformed input."""
    labels = []
    jumped = False
    next_off = off
    guard = 0
    n = len(msg)
    while True:
        guard += 1
        if off >= n or guard > 128:
            return None, next_off
        ln = msg[off]
        if ln == 0:                                    # root -> end of name
            if not jumped:
                next_off = off + 1
            break
        if (ln & 0xC0) == 0xC0:                         # compression pointer
            if off + 1 >= n:
                return None, next_off
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                next_off = off + 2
            jumped = True
            off = ptr
            continue
        off += 1
        if off + ln > n:
            return None, next_off
        labels.append(msg[off:off + ln])
        off += ln
    try:
        return ".".join(l.decode(errors="ignore") for l in labels), next_off
    except Exception:
        return None, next_off


def dns_question_name(msg: bytes):
    """First question QNAME from a DNS message that is a QUERY (qr=0), else None.
    Equivalent to scapy `dns.qd.qname` guarded by `dns.qr == 0`."""
    if len(msg) < 12:
        return None
    flags = (msg[2] << 8) | msg[3]
    if (flags >> 15) & 1:                              # qr==1 -> response, skip
        return None
    qd = (msg[4] << 8) | msg[5]                         # qdcount
    if qd < 1:
        return None
    name, _ = _dns_name(msg, 12)
    return name or None


def dns_a_answers(msg: bytes):
    """[(name, ipv4)] for A-record answers in a DNS/mDNS message (any qr). Skips
    the question section, then reads answers; type-A(1) rdata is the 4-byte IPv4.
    Equivalent to scapy iterating dns.an[i] where rr.type==1 -> (rrname, rdata)."""
    out = []
    try:
        if len(msg) < 12:
            return out
        qd = (msg[4] << 8) | msg[5]
        an = (msg[6] << 8) | msg[7]
        off = 12
        for _ in range(qd):                            # skip questions: name + type(2) + class(2)
            _nm, off = _dns_name(msg, off)
            if _nm is None:
                return out
            off += 4
        for _ in range(an):
            name, off = _dns_name(msg, off)
            if name is None or off + 10 > len(msg):
                return out
            rtype = (msg[off] << 8) | msg[off + 1]
            rdlen = (msg[off + 8] << 8) | msg[off + 9]
            rdata_off = off + 10
            if rdata_off + rdlen > len(msg):
                return out
            if rtype == 1 and rdlen == 4:              # A record
                out.append((name, socket.inet_ntoa(msg[rdata_off:rdata_off + 4])))
            off = rdata_off + rdlen
    except Exception:
        return out
    return out


def dhcp_hostname(bootp: bytes):
    """(hostname, client_mac) from a BOOTP/DHCP payload (the UDP body), or
    (None, None). hostname = DHCP option 12; client_mac = BOOTP chaddr[:6].
    Mirrors scapy DHCP option ('hostname', ...) + BOOTP.chaddr."""
    # BOOTP fixed section is 236 bytes, then 4-byte magic cookie, then options.
    if len(bootp) < 240:
        return None, None
    if bootp[236:240] != b"\x63\x82\x53\x63":          # DHCP magic cookie
        return None, None
    client_mac = _mac_str(bootp[28:34]) if len(bootp) >= 34 else None
    host = None
    i = 240
    n = len(bootp)
    while i < n:
        code = bootp[i]
        if code == 0:                                  # pad
            i += 1
            continue
        if code == 255:                                # end
            break
        if i + 1 >= n:
            break
        ln = bootp[i + 1]
        val = bootp[i + 2:i + 2 + ln]
        if code == 12:                                 # host name
            host = val.decode(errors="ignore")
        i += 2 + ln
    return (host or None), client_mac
