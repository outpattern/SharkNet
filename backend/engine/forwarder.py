"""
Packet forwarder + traffic shaper. This is the enforcement point.

While the spoofer holds the MITM position, every transit packet (Ethernet
dst = our MAC) is captured here. Per managed device we apply:
  - HARD CUT : blackhole — drop immediately, before any counting/observation (V3.1)
  - CUT      : drop the packet (no forwarding -> no internet); still byte-counted
  - LIMIT    : token-bucket per direction; forward if tokens available else drop
  - else     : forward normally (so allowed devices keep working)

We do the forwarding ourselves (OS IP-forwarding stays OFF) so throttling and
cutting are fully under our control. Byte counts feed the live monitor.
"""
from __future__ import annotations

import logging
import os
import threading
import time

from ..state import STATE
from .spoofer import SPOOFER
from . import domains as domains_engine
from .domain_observer import DOMAIN_OBSERVER
from . import policy
from . import rawpkt
from .iobackend import make_capture, make_injector

log = logging.getLogger("sharknet.engine")


def _sharknet_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "SharkNet")


def _limit_debug_marker() -> str:
    # presence of this file enables LIMIT diagnostics — works from the packaged
    # (UAC-elevated) EXE, which does NOT inherit env vars from the caller shell.
    return os.path.join(_sharknet_dir(), "limit-debug.on")


def _log_file_path() -> str:
    return os.path.join(_sharknet_dir(), "sharknet.log")


class _Bucket:
    __slots__ = ("rate", "tokens", "cap", "ts")

    def __init__(self, rate_bps: float):
        self.rate = rate_bps
        self.cap = max(rate_bps, 8192)   # ~burst
        self.tokens = self.cap
        self.ts = time.time()

    def allow(self, size: int) -> bool:
        if self.rate <= 0:            # unlimited
            return True
        now = time.time()
        self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= size:
            self.tokens -= size
            return True
        return False


class Forwarder:
    def __init__(self):
        self._cap = None        # Capture backend (Gate 6.2: iobackend, Native default)
        self._inj = None        # Injector backend (Gate 6.2: iobackend, Native default)
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._rates: dict[tuple[str, str], float] = {}
        # byte counters since last monitor tick
        self.counters: dict[str, dict[str, int]] = {}
        # DIAGNOSTICS (read-only): a single cumulative frame counter for the
        # intercepted/observed path. One lock-free int increment per frame (like
        # the byte dict update right beside it) — never read on the hot path,
        # never affects any drop/limit/forward decision. Read by backend.diagnostics
        # as a delta over time. Not incremented for HARD CUT frames (they return
        # before _count), which correctly excludes fully-isolated devices.
        self.packets_total: int = 0
        # perf: cache MAC string -> 6 raw bytes; our own MAC precomputed on start
        self._mac_cache: dict[str, bytes] = {}
        self._my_mac_b: bytes = b""
        # opt-in LIMIT diagnostics — OFF by default. Enabled by EITHER the env
        # var SHARKNET_LIMIT_DEBUG (source/dev, or --limit-debug flag) OR the
        # marker file %LOCALAPPDATA%\SharkNet\limit-debug.on (the reliable way
        # for the packaged EXE, whose elevated process gets no caller env vars).
        # Re-evaluated at runtime so it can be toggled without a restart.
        self._dbg: dict[tuple, list] = {}
        self._dbg_last = time.time()
        self._eval_pkts = 0
        self._dbg_check_ts = 0.0        # last time the debug marker was checked (throttle)
        self._log_handler = None
        self._debug = False
        # DOMAIN/SERVICE ENFORCEMENT diagnostic (Phase 7). LOGGING ONLY — it never
        # changes the drop/forward decision; it records, per blocked device, the
        # effective block set and every parsed request domain + match + decision,
        # so a real device (e.g. .74) reveals exactly where the block chain breaks.
        # Enabled by env SHARKNET_BLOCK_DEBUG or the marker %LOCALAPPDATA%\SharkNet\
        # block-debug.on (works under the elevated packaged EXE). OFF by default.
        self._blk_debug = False
        self._blk_seen: set = set()      # (ip, eff-signature) already logged, de-spam
        self.refresh_debug()

    def _eval_debug(self) -> bool:
        if os.environ.get("SHARKNET_LIMIT_DEBUG"):
            return True
        try:
            # match ANY file starting with "limit-debug" so a stray .txt that
            # Explorer appends (limit-debug.on.txt) still enables the mode
            import glob
            return bool(glob.glob(os.path.join(_sharknet_dir(), "limit-debug*")))
        except Exception:
            return False

    def _eval_block_debug(self) -> bool:
        if os.environ.get("SHARKNET_BLOCK_DEBUG"):
            return True
        try:
            import glob
            return bool(glob.glob(os.path.join(_sharknet_dir(), "block-debug*")))
        except Exception:
            return False

    def _blk_log(self, ip: str, msg: str) -> None:
        log.info("[BLOCK-DEBUG] %-15s %s", ip, msg)

    def _ensure_dbg_handler(self) -> None:
        # write [LIMIT-DEBUG]/[BLOCK-DEBUG] straight to sharknet.log regardless of how
        # the host process configured logging (packaged run.py vs engine_service).
        if self._log_handler is not None:
            return
        try:
            path = os.path.abspath(_log_file_path())
            # REUSE an existing FileHandler for this file if one is already attached
            # to the shared 'sharknet.engine' logger. Prevents duplicate log lines
            # when a second Forwarder instance (or a re-init) would otherwise add a
            # second handler to the same logger (item 19: duplicate BLOCK-DEBUG).
            for h in list(log.handlers):
                if isinstance(h, logging.FileHandler) and \
                        os.path.abspath(getattr(h, "baseFilename", "")) == path:
                    self._log_handler = h
                    log.setLevel(logging.INFO)
                    log.propagate = False
                    return
            os.makedirs(_sharknet_dir(), exist_ok=True)
            h = logging.FileHandler(_log_file_path(), encoding="utf-8", delay=True)
            h.setLevel(logging.INFO)
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            log.setLevel(logging.INFO)
            log.addHandler(h)
            log.propagate = False           # our handler owns it -> no duplicates
            self._log_handler = h
        except Exception:
            pass

    def refresh_debug(self) -> None:
        on = self._eval_debug()
        if on and not self._debug:
            self._ensure_dbg_handler()
            log.info("[LIMIT-DEBUG] diagnostic mode ENABLED (marker=%s)",
                     _limit_debug_marker())
        elif not on and self._debug:
            log.info("[LIMIT-DEBUG] diagnostic mode disabled")
        self._debug = on
        blk = self._eval_block_debug()
        if blk and not self._blk_debug:
            self._ensure_dbg_handler()
            self._blk_seen.clear()
            log.info("[BLOCK-DEBUG] enforcement diagnostic ENABLED (logging only)")
        elif not blk and self._blk_debug:
            log.info("[BLOCK-DEBUG] enforcement diagnostic disabled")
        self._blk_debug = blk

    def _dbg_note(self, ip: str, direction: str, size: int,
                  forwarded: bool, rate_kbps: int) -> None:
        s = self._dbg.get((ip, direction))
        if s is None:
            s = self._dbg[(ip, direction)] = [0, 0, 0, 0, rate_kbps]
        s[0] += 1; s[1] += size; s[4] = rate_kbps          # in pkts, in bytes, rate
        if forwarded:
            s[2] += 1; s[3] += size                          # fwd pkts, fwd bytes
        now = time.time()
        dt = now - self._dbg_last
        if dt >= 2.0:
            for (dip, ddir), v in list(self._dbg.items()):
                inp, inb, fwp, fwb, rt = v
                log.info("[LIMIT-DEBUG] %-15s %-4s rate=%dKB/s(%.1fMbps)  "
                         "in=%.0fpps/%.1fMbps  fwd=%.0fpps/%.1fMbps  drop=%.0fpps/%.1fMbps",
                         dip, ddir, rt, rt * 1024 * 8 / 1e6,
                         inp / dt, inb * 8 / dt / 1e6, fwp / dt, fwb * 8 / dt / 1e6,
                         (inp - fwp) / dt, (inb - fwb) * 8 / dt / 1e6)
            # limiter bucket inventory — proves the aggregation model (one bucket
            # per DEVICE per DIRECTION, never per-flow/per-connection)
            with self._lock:
                keys = sorted(self._buckets.keys())
                inv = "; ".join(
                    "%s/%s rate=%.0fKB/s tokens=%.0f" %
                    (k[0], k[1], self._rates.get(k, 0) / 1024.0, self._buckets[k].tokens)
                    for k in keys)
            log.info("[LIMIT-DEBUG] limiter buckets active=%d: %s", len(keys), inv or "(none)")
            self._dbg.clear()
            self._dbg_last = now

    @staticmethod
    def _mac_to_bytes(mac: str) -> bytes:
        return bytes.fromhex(mac.replace(":", "").replace("-", ""))

    def _mac_bytes(self, mac: str) -> bytes | None:
        b = self._mac_cache.get(mac)
        if b is None:
            try:
                b = self._mac_to_bytes(mac)
            except Exception:
                return None
            self._mac_cache[mac] = b
        return b

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._cap:
            return
        iface = STATE.interface
        self._inj = make_injector(iface.name)
        my_mac = iface.mac
        self._mac_cache.clear()
        self._my_mac_b = self._mac_to_bytes(my_mac)   # our L2 source, precomputed
        # capture only IPv4 frames addressed to us at L2 (transit traffic)
        bpf = f"ip and ether dst {my_mac}"
        DOMAIN_OBSERVER.start()        # async visited-domain worker (off hot path)
        # backend from iobackend (Native/Npcap); it delivers each frame to _handle,
        # which reads .original -> backend-agnostic.
        self._cap = make_capture(iface.name, bpf, self._handle)
        self._cap.start()

    def stop(self) -> None:
        if self._cap:
            self._cap.stop()
            self._cap = None
        try:
            DOMAIN_OBSERVER.stop()      # stop the async worker after the sniffer
        except Exception:
            pass
        try:
            if self._inj:
                self._inj.close()
        except Exception:
            pass
        self._inj = None
        self._buckets.clear()

    # ---------- bucket management ----------
    def _bucket(self, ip: str, direction: str, rate_bps: float) -> _Bucket:
        key = (ip, direction)
        with self._lock:
            b = self._buckets.get(key)
            if b is None or self._rates.get(key) != rate_bps:
                b = _Bucket(rate_bps)
                self._buckets[key] = b
                self._rates[key] = rate_bps
            return b

    def _count(self, ip: str, direction: str, n: int) -> None:
        c = self.counters.setdefault(ip, {"down": 0, "up": 0})
        c[direction] += n
        self.packets_total += 1          # diagnostics: lock-free cumulative frame count

    # ---------- scoped IP pinning + F3 retroactive enforcement ----------
    _PIN_TTL = 600.0    # seconds an observed blocked-domain IP stays pinned
    _PIN_CAP = 256      # max pinned IPs per device (bounded state)
    _DNS_TTL = 600.0    # recent domain->IP association window (retroactive pinning)
    _DNS_CAP = 128      # max remembered domains per device

    def _bound_pins(self, target) -> None:
        pins = target.blocked_ips
        if len(pins) > self._PIN_CAP:
            now = time.time()
            for k in [k for k, e in list(pins.items()) if e <= now]:
                pins.pop(k, None)                       # expired first
            while len(pins) > self._PIN_CAP:
                pins.pop(next(iter(pins)), None)        # then the oldest

    def _record_dns(self, target, raw: bytes) -> None:
        """Record recent domain->IP resolutions for a MANAGED device (F3) and pin
        the IPs of any CURRENTLY-blocked domain. `recent_dns` feeds retroactive
        pinning (pin_recent) when a block is applied later; `blocked_ips` feeds the
        scoped IP-drop. Both bounded + TTL'd — never broad IP blocking. Cheap inline
        UDP/53 gate so non-DNS UDP (e.g. QUIC downloads) costs almost nothing."""
        if len(raw) < 42 or raw[23] != 17:              # not Ethernet/IPv4/UDP
            return
        ihl = (raw[14] & 0x0F) * 4
        l4 = 14 + ihl
        if len(raw) < l4 + 8 or ((raw[l4] << 8) | raw[l4 + 1]) != 53:   # UDP sport != 53
            return
        answers = rawpkt.dns_a_answers(raw[l4 + 8:])
        if not answers:
            return
        now = time.time()
        rec = target.recent_dns
        keywords = target.eff_blocked or target.blocked
        pins = target.blocked_ips
        for name, ip in answers:
            nm = (name or "").strip(".").lower()
            if not nm:
                continue
            e = rec.get(nm)
            if e is None:
                e = rec[nm] = [set(), 0.0]
            e[0].add(ip)
            e[1] = now + self._DNS_TTL
            if keywords and domains_engine.is_blocked(nm, keywords):
                pins[ip] = now + self._PIN_TTL          # proactive pin (blocked now)
                if self._blk_debug:
                    self._blk_log(target.ip, "pin %s -> %s (DNS answer)" % (nm, ip))
        if len(rec) > self._DNS_CAP:
            for k in [k for k, v in list(rec.items()) if v[1] <= now]:
                rec.pop(k, None)
            while len(rec) > self._DNS_CAP:
                rec.pop(next(iter(rec)), None)
        self._bound_pins(target)

    def pin_recent(self, target) -> int:
        """F3: RECONCILE the scoped IP-pin set from this device's recent DNS
        observations against its CURRENT effective block set. Called on every
        block/unblock mutation. It BOTH:
          * pins IPs of now-blocked domains the device recently resolved
            (retroactive/immediate enforcement of existing connections + QUIC), AND
          * unpins IPs whose domain is no longer blocked (unblock cleanup — no stale
            pin survives an unblock, item 7/8).
        Scoped + TTL'd; only this device's own resolutions; never blanket blocking.
        Returns the number of IPs newly pinned. Safe when idle (recent_dns empty)."""
        now = time.time()
        rec = target.recent_dns
        for nm in [k for k, v in list(rec.items()) if v[1] <= now]:
            rec.pop(nm, None)                       # drop expired associations first
        keywords = target.eff_blocked or target.blocked
        want: dict = {}
        if keywords:
            for nm, (ips, exp) in rec.items():
                if exp > now and domains_engine.is_blocked(nm, keywords):
                    for ip in ips:
                        want[ip] = now + self._PIN_TTL
        pins = target.blocked_ips
        added = 0
        for ip, exp in want.items():                # add missing (retroactive)
            if ip not in pins:
                added += 1
                if self._blk_debug:
                    self._blk_log(target.ip, "RETRO pin %s" % ip)
            pins[ip] = exp
        for ip in [ip for ip in pins if ip not in want]:   # remove stale (unblock)
            pins.pop(ip, None)
            if self._blk_debug:
                self._blk_log(target.ip, "unpin %s (no longer blocked)" % ip)
        return added

    # ---------- packet handler ----------
    def _handle(self, pkt) -> None:
        # re-evaluate the diagnostic toggle occasionally (the marker file may be
        # created/removed at runtime). Gated by BOTH a packet counter AND a 3 s
        # time throttle so the filesystem glob never runs more than ~once/3 s even
        # at very high pps (item 5: keep syscalls off the hot path).
        self._eval_pkts += 1
        if self._eval_pkts >= 4096:
            self._eval_pkts = 0
            now = time.time()
            if now - self._dbg_check_ts >= 3.0:
                self._dbg_check_ts = now
                self.refresh_debug()
        # manual IPv4 parse straight from the captured frame bytes. The BPF
        # "ip and ether dst <mac>" already guarantees an untagged IPv4-over-
        # Ethernet frame, so this avoids per-packet layer dissection on the
        # forwarding hot path (rawpkt.parse_ipv4, proven equivalent in tests).
        raw = pkt.original
        if not raw:
            return
        parsed = rawpkt.parse_ipv4(raw)
        if parsed is None:
            return
        src, dst, proto = parsed
        iface = STATE.interface
        if iface is None:
            return
        my_ip = iface.ip
        if src == my_ip or dst == my_ip:
            return  # our own traffic

        # Which managed device does this packet belong to? (shared predicate:
        # cut/limit rule, device/network domain-or-service block. See policy.py.)
        # Lock-free lookup: STATE.devices.get is a GIL-atomic dict read; taking
        # STATE.lock per packet was needless contention on the hot path (item 5).
        target, direction = policy.select_target(src, dst, STATE.devices.get)
        if target is None:
            return

        # HARD CUT (V3.1): MAXIMUM isolation. Blackhole the frame here — the earliest
        # safe point after the device is identified — and return BEFORE byte counting,
        # DNS/IP pinning, domain parse/observe, policy, and re-injection. A hard-cut
        # device gets zero network access AND is intentionally NOT observed (no traffic
        # inspection). This is a SEPARATE branch: the CUT path below is unchanged, and a
        # device set to "cut" never reaches here as hard cut. self/gateway are never
        # managed, so hard cut can never isolate the host/gateway (see is_managed).
        if target.mode == "hardcut":
            return

        # frame size for accounting (raw bytes already in hand, O(1))
        size = len(raw)
        self._count(target.ip, direction, size)

        # EARLY CUT (item 5/6): a cut device drops EVERY packet in both directions
        # regardless of domain/QUIC, so decide here and skip all parse/observe/pin
        # work — the fastest safe drop. A cut device is intentionally unreachable, so
        # there is no traffic to observe (documented CUT limitation). To observe an
        # allowed device without enforcing, use Monitor (observation intent) — it is
        # intercepted here too but falls through to FORWARD, not this early return.
        if target.mode == "cut":
            if self._debug:
                self._dbg_note(target.ip, direction, size, False,
                               target.down_kbps if direction == "down" else target.up_kbps)
            return

        # F3 SCOPED IP ENFORCEMENT: immediately drop traffic to/from an IP a BLOCKED
        # domain resolved to for THIS device. This catches EXISTING connections and
        # QUIC (UDP/443) that carry no cleartext name. Scoped to pinned + TTL'd
        # blocked-domain IPs only (never blanket IP blocking); O(1) dict lookup and
        # only when the device actually has pins.
        if target.blocked_ips:
            peer = dst if direction == "up" else src
            exp = target.blocked_ips.get(peer)
            if exp is not None:
                if exp > time.time():
                    if self._blk_debug:
                        self._blk_log(target.ip, "IP-drop %s peer=%s (pinned) -> DROP" % (direction, peer))
                    return
                del target.blocked_ips[peer]            # expired -> forget

        # F3 record recent DNS answers for retroactive pinning (ANY managed device)
        # + proactively pin currently-blocked domains' IPs. Cheap inline UDP/53 gate.
        if direction == "down" and proto == 17:
            self._record_dns(target, raw)

        # name-based blocking on OUTBOUND requests (DNS query / TLS SNI / HTTP Host).
        # eff_blocked is precomputed at mutation time -> just a tuple read here. With
        # no blocks, parse is observation-only -> async observer (off the hot path).
        up_domain = None
        if target.eff_blocked or target.blocked:
            if self._blk_debug:
                sig = (target.ip, target.eff_blocked, tuple(target.services))
                if sig not in self._blk_seen:
                    self._blk_seen.add(sig)
                    self._blk_log(target.ip, "eff_blocked=%s services=%s adhoc=%s"
                                  % (list(target.eff_blocked)[:14], list(target.services), list(target.blocked)))
            if direction == "up":
                info = rawpkt.l4_payload(raw)
                if info is not None:
                    p2, _sp, dp2, payload = info
                    hit = domains_engine.domain_from_l4(p2, dp2, payload)
                    if hit:
                        up_domain = hit[0]
                        domains_engine.record_visit(target, up_domain)
                        if self._blk_debug:
                            kw = target.eff_blocked or target.blocked
                            m = domains_engine.is_blocked(up_domain, kw)
                            self._blk_log(target.ip, "%s %s match=%s -> %s"
                                          % (hit[1], up_domain, m, "DROP" if m else "forward"))
        elif direction == "up":
            DOMAIN_OBSERVER.observe(target, pkt)      # observation only (no blocks)

        # drop / limit / forward decision (single source of truth: policy.py)
        action = policy.action_for(target, direction, up_domain)
        if action == policy.DROP:
            if self._debug:
                self._dbg_note(target.ip, direction, size, False,
                               target.down_kbps if direction == "down" else target.up_kbps)
            return                          # cut, or blocked-domain request
        if action == policy.LIMIT:
            rate_kbps = target.down_kbps if direction == "down" else target.up_kbps
            if not self._bucket(target.ip, direction, rate_kbps * 1024.0).allow(size):
                if self._debug:
                    self._dbg_note(target.ip, direction, size, False, rate_kbps)
                return  # over budget -> drop (TCP backs off)
            if self._debug:
                self._dbg_note(target.ip, direction, size, True, rate_kbps)
        elif self._debug:
            self._dbg_note(target.ip, direction, size, True, 0)

        # forward: rewrite ONLY the L2 dst/src (first 12 bytes) on the ORIGINAL
        # captured frame and re-inject the raw bytes — no per-packet re-
        # serialization (the dominant cost). The IP payload — TTL, checksum,
        # everything above L2 — is forwarded byte-for-byte; the native injector
        # sends the bytes object unchanged.
        nh_mac = self._next_hop_mac(dst)
        if not nh_mac:
            return
        nh_b = self._mac_bytes(nh_mac)
        if nh_b is None or len(raw) < 14:
            return
        try:
            # _inj.send IS the raw socket's bound send (no wrapper on the hot path)
            self._inj.send(nh_b + self._my_mac_b + raw[12:])
        except Exception:
            pass

    def _next_hop_mac(self, dst_ip: str) -> str | None:
        iface = STATE.interface
        if dst_ip == iface.gateway:
            return SPOOFER.gateway_mac()
        d = STATE.devices.get(dst_ip)          # lock-free GIL-atomic read (item 5)
        if d and d.mac and not d.is_self:
            return d.mac
        # off-subnet / internet -> gateway
        return SPOOFER.gateway_mac()


FORWARDER = Forwarder()
