"""
Domain observation + blocking (metadata only, no HTTPS decryption).

We read the domain a device is reaching from:
  - DNS queries (UDP/TCP 53)
  - TLS SNI (the server name in a TLS ClientHello, port 443)
  - HTTP Host header (port 80)

Blocking a domain drops those request packets for a managed device, so the
connection to that domain fails while everything else keeps working.
"""
from __future__ import annotations

import re
import time

from . import rawpkt

# preset groups -> domain keywords
PRESETS = {
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "youtu.be"],
    "TikTok": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ibytedtos.com"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "Facebook": ["facebook.com", "fbcdn.net", "fbsbx.com", "fb.com"],
    "Snapchat": ["snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com"],
    "WhatsApp": ["whatsapp.com", "whatsapp.net"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
    "Twitter/X": ["twitter.com", "x.com", "twimg.com", "t.co"],
    "PUBG/Games": ["pubgmobile.com", "igamecj.com", "steampowered.com", "epicgames.com"],
    "Shahid": ["shahid.net", "shahid.mbc.net", "mbc.net"],
    "Watch iT": ["watchit.com", "watchit-mena.com", "watchitapp.net"],
    "OSN+": ["osn.com", "osnplus.com", "stream.osnplus.com"],
    "TOD": ["tod.tv", "todtv.com"],
    "Disney+": ["disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com"],
    "VIU": ["viu.com", "viu.tv", "viuapi.io"],
    "Yango Play": ["yangoplay.com", "plus.yango.com", "yandex.net"],
}

_HOST_RE = re.compile(rb"[Hh]ost:\s*([A-Za-z0-9.\-]+)")


def normalize_domain(name) -> str | None:
    """THE single canonical domain-normalization path (F3 item 6).

    Every layer that compares domains — the DNS/SNI/HTTP observer, the block
    matcher, the effective-policy build (state.recompute_effective), the service
    catalog, and the API write path — funnels through this so a domain has exactly
    ONE identity. Idempotent. Returns None for anything that isn't a usable host.

      - decode bytes, trim whitespace
      - reduce a pasted URL to its host ("https://x.com/a?b" -> "x.com"), because
        people paste addresses out of the browser bar. Without this the entry is
        stored verbatim and can NEVER match observed traffic — the UI would show an
        active rule that silently blocks nothing.
      - lower-case (case-insensitive)
      - strip a trailing root dot ("example.com." -> "example.com") and any stray
        leading dot
      - drop a leading "www." (canonical apex; matches how sites are observed)
      - reject empty / dotless / over-long / whitespace-bearing names
    """
    if isinstance(name, (bytes, bytearray)):
        name = name.decode(errors="ignore")
    name = (name or "").strip()
    # URL -> host: drop scheme, then path/query/fragment, then userinfo and port.
    if "//" in name:
        name = name.split("//", 1)[1]
    for sep in ("/", "?", "#"):
        name = name.split(sep, 1)[0]
    if "@" in name:
        name = name.rsplit("@", 1)[1]
    if ":" in name:
        name = name.split(":", 1)[0]
    name = name.strip().strip(".").lower()
    if name.startswith("www."):
        name = name[4:]
    # a host never contains whitespace; reject rather than store a dead rule
    if not name or "." not in name or len(name) > 100 or any(c.isspace() for c in name):
        return None
    return name


# backwards-compatible alias (was the internal name before F3 item 6)
_norm = normalize_domain


def _tls_sni(raw: bytes) -> str | None:
    try:
        if len(raw) < 45 or raw[0] != 0x16:      # TLS handshake
            return None
        if raw[5] != 0x01:                        # ClientHello
            return None
        p = 43                                    # skip to session id
        sid = raw[p]; p += 1 + sid
        clen = int.from_bytes(raw[p:p+2], "big"); p += 2 + clen   # cipher suites
        cmp = raw[p]; p += 1 + cmp                # compression
        p += 2                                    # extensions length
        end = len(raw)
        while p + 4 <= end:
            etype = int.from_bytes(raw[p:p+2], "big")
            elen = int.from_bytes(raw[p+2:p+4], "big")
            p += 4
            if etype == 0x00:                     # server_name
                # list len(2) + type(1) + name len(2) + name
                nlen = int.from_bytes(raw[p+3:p+5], "big")
                return raw[p+5:p+5+nlen].decode(errors="ignore")
            p += elen
    except Exception:
        return None
    return None


def parse_domain(pkt):
    """Return (domain, source) for an outbound request packet, or None.

    Backend-agnostic (Gate 6.3): reads the raw frame bytes — `pkt.original` for
    BOTH the scapy packet and the native _Frame — then parses transport+payload
    with the scapy-free rawpkt helpers. SNI (443) and HTTP Host (80) use the same
    raw matchers as before; DNS (53) uses rawpkt.dns_question_name. Result is
    field-equivalent to the former scapy getlayer() path, and now works under
    native capture (which previously returned None -> domain blocking no-op).
    """
    try:
        if isinstance(pkt, (bytes, bytearray)):
            raw = bytes(pkt)
        else:
            raw = getattr(pkt, "original", b"") or b""
            if not raw:                       # a freshly-built scapy packet has no .original
                try:
                    raw = bytes(pkt)
                except Exception:
                    return None
        if not raw:
            return None
        info = rawpkt.l4_payload(raw)
        if info is None:
            return None
        proto, _sport, dport, payload = info
        return domain_from_l4(proto, dport, payload)
    except Exception:
        return None


def domain_from_l4(proto: int, dport: int, payload: bytes):
    """(domain, source) from ALREADY-parsed L4 fields, or None. This is the core
    of parse_domain, exposed so the enforcement hot path can reuse ONE
    rawpkt.l4_payload() parse for both the block decision AND the scoped-QUIC
    check (see forwarder) instead of parsing the frame twice.

      TCP/443 -> TLS SNI ("tls") · TCP/80,8080,8000,8888 -> HTTP Host ("http")
      UDP/53  -> DNS query name ("dns")
    QUIC (UDP/443) has no cleartext name here and is intentionally NOT parsed —
    it is handled best-effort by IP pinning, not by name."""
    if proto == 6:                                   # TCP (the bulk case)
        if dport != 443 and dport not in (80, 8080, 8000, 8888):
            return None                              # not a request port
        if not payload:
            return None
        if dport == 443:
            d = _norm(_tls_sni(payload))
            if d:
                return d, "tls"
        else:
            m = _HOST_RE.search(payload[:400])
            if m:
                d = _norm(m.group(1))
                if d:
                    return d, "http"
        return None
    if proto == 17 and dport == 53:                  # DNS query
        d = _norm(rawpkt.dns_question_name(payload))
        if d:
            return d, "dns"
    return None


def is_blocked(domain: str, blocked: list) -> bool:
    """domain is blocked if it equals or is a subdomain of any blocked entry.

    Both sides go through the SAME canonical normalization (F3 item 6) so a rule
    entered as `www.Example.com.` or `EXAMPLE.COM` matches an observed
    `example.com` / `api.example.com`, while `notexample.com` never does.
    """
    d = normalize_domain(domain)
    if not d:
        return False
    for b in blocked:
        nb = normalize_domain(b)
        if nb and (d == nb or d.endswith("." + nb)):
            return True
    return False


VISITED_CAP = 400


def record_visit(dev, domain: str, cap: int = VISITED_CAP) -> None:
    """Record a visited domain on `dev` as an LRU-capped {domain: last_seen}.

    Replaces the old hard `.clear()` at the cap (which wiped ALL history at
    once): the most-recently-seen domain moves to the end and, when over the
    cap, only the single oldest entry is evicted. Takes STATE.lock because the
    device's `domains` dict is read by the /api/domains snapshot on another
    thread. Safe to call from the hot path or the async observer worker.
    """
    if not domain:
        return
    from ..state import STATE   # local import avoids any import-time cycle
    with STATE.lock:
        d = dev.domains
        if domain in d:
            del d[domain]                 # move-to-end: mark most-recently-seen
        d[domain] = time.time()
        if len(d) > cap:
            try:
                del d[next(iter(d))]      # evict the single oldest entry
            except StopIteration:
                pass
