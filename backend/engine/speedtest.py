"""
Internet speed & health test: ping/jitter, DNS lookup time, download and
upload throughput. Uses Cloudflare's speed endpoints.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import time
import urllib.request

_UP = "https://speed.cloudflare.com/__up"
_NOWINDOW = 0x08000000
_SSL = ssl.create_default_context()   # normal TLS verification
# fallback download hosts if the primary is slow/blocked on a given network
_DOWN_FALLBACKS = [
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://speedtest.selectel.ru/{mb}MB.bin",
    "https://proof.ovh.net/files/10Mb.dat",
]


def _geo() -> dict:
    """Public IP + ISP + city/country (like Ookla shows). Uses HTTPS (ip-api's free
    tier is HTTP-only; ipwho.is is free + HTTPS + no key) with verified TLS, so the
    user's public IP is never disclosed over plaintext. Fails soft to blanks."""
    try:
        req = urllib.request.Request("https://ipwho.is/", headers={"User-Agent": "SharkNet"})
        with urllib.request.urlopen(req, timeout=5, context=_SSL) as r:
            d = json.loads(r.read().decode(errors="ignore"))
        if not d.get("success", True):
            return {"ip": "", "isp": "", "city": "", "country": ""}
        conn = d.get("connection") or {}
        return {"ip": d.get("ip", ""),
                "isp": conn.get("isp") or conn.get("org") or d.get("org") or "",
                "city": d.get("city", ""), "country": d.get("country", "")}
    except Exception:
        return {"ip": "", "isp": "", "city": "", "country": ""}


def _ping_stats(host: str = "1.1.1.1", count: int = 5):
    try:
        out = subprocess.run(["ping", "-n", str(count), "-w", "1000", host],
                             capture_output=True, text=True, timeout=count + 6,
                             creationflags=_NOWINDOW).stdout
    except Exception:
        return None, None, 100.0
    times = [int(m) for m in re.findall(r"time[=<](\d+)ms", out)]
    loss_m = re.search(r"\((\d+)% loss\)", out)
    loss = float(loss_m.group(1)) if loss_m else 0.0
    if not times:
        return None, None, loss
    avg = sum(times) / len(times)
    jitter = (max(times) - min(times)) if len(times) > 1 else 0
    return round(avg, 1), round(jitter, 1), loss


def _dns_ms(host: str = "cloudflare.com"):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(3)
        t = time.time()
        socket.gethostbyname(host)
        return round((time.time() - t) * 1000, 1)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)   # don't leak the global default


def _download_once(url: str, max_seconds: float):
    got, start = 0, time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SharkNet"})
        with urllib.request.urlopen(req, timeout=max_seconds + 3, context=_SSL) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk or time.time() - start > max_seconds:
                    break
                got += len(chunk)
    except Exception:
        pass
    dur = max(time.time() - start, 1e-3)
    return (got * 8) / dur / 1e6, got


def _download(target_bytes: int, max_seconds: float):
    mb = max(5, target_bytes // 1_000_000)
    for tmpl in _DOWN_FALLBACKS:
        url = tmpl.format(n=target_bytes, mb=mb)
        mbps, got = _download_once(url, max_seconds)
        if got >= 500_000:                 # got a real download -> use it
            return mbps, got
    return 0.0, 0


def _upload(target_bytes: int, max_seconds: float):
    payload = b"0" * target_bytes
    start = time.time()
    try:
        req = urllib.request.Request(_UP, data=payload, method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "User-Agent": "SharkNet"})
        urllib.request.urlopen(req, timeout=max_seconds + 3, context=_SSL).read()
    except Exception:
        pass
    dur = max(time.time() - start, 1e-3)
    return (target_bytes * 8) / dur / 1e6


def run() -> dict:
    ping, jitter, loss = _ping_stats()
    dns = _dns_ms()
    down_mbps, down_bytes = _download(15_000_000, 6.0)
    up_mbps = _upload(5_000_000, 6.0)
    grade = "—"
    if down_mbps:
        grade = ("Excellent" if down_mbps > 100 else "Good" if down_mbps > 30
                 else "Fair" if down_mbps > 8 else "Slow")
    geo = _geo()
    return {
        "ok": True,
        "download_mbps": round(down_mbps, 1),
        "upload_mbps": round(up_mbps, 1),
        "ping_ms": ping,
        "jitter_ms": jitter,
        "packet_loss": loss,
        "dns_ms": dns,
        "grade": grade,
        "isp": geo["isp"],
        "public_ip": geo["ip"],
        "city": geo["city"],
        "country": geo["country"],
    }
