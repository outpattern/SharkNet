"""
Enforcement policy — the SINGLE source of truth for what each rule means and
how a transit packet is classified.

SharkNet has exactly ONE enforcement mechanism: native (Npcap) userspace packet
forwarding driven by ARP spoofing/MITM. The `Forwarder` calls these
helpers so the pure drop/limit/forward decision stays separate from the packet
I/O and can be unit-tested without sockets. (Keeping this as the single classifier
is also what fixed the old "block a domain -> whole device loses internet" bug.)

Rule semantics — a device's `mode` ("allow" | "limit" | "cut") plus its
`blocked` domain list together define enforcement:

  allow  + no blocks : NOT managed. Traffic is never routed through us.
  allow  + blocks    : managed. Everything is FORWARDED except requests to a
                       blocked domain (those are dropped). This must NEVER be
                       equivalent to a full CUT.
  limit  (+- blocks) : managed. Token-bucket per direction; blocked-domain
                       requests are dropped; everything else is rate-limited.
  cut    (+- blocks) : managed. Every packet is dropped (no internet). The device
                       is still observed (byte counters) so the UI shows it trying.
  hardcut (V3.1)     : managed. MAXIMUM isolation — every packet is dropped AND the
                       device is NOT observed (no byte counting, no domain parse).
                       The forwarder blackholes it before any observation work
                       (see forwarder._handle). action_for returns DROP for it too,
                       so any non-fast-path caller still enforces correctly. It is
                       an ADDITION: cut stays exactly cut, this never rewrites it.

"managed" == `is_managed(dev)` == this device's traffic must be MITM'd
(ARP-spoofed to us) so we can enforce. `STATE.managed()` uses the SAME
predicate, so the set we spoof and the set we forward are always identical.
When a device returns to `allow` with no blocks it leaves this set, the spoofer
stops poisoning it, and its ARP is restored (no stale enforcement).

Policy scope & precedence (Phase 7):
  - DOMAIN/SERVICE blocking has TWO scopes: DEVICE (dev.blocked / dev.services)
    and NETWORK (STATE.net_domains / STATE.net_services). The EFFECTIVE block set
    is their UNION (most-restrictive wins): a device-level ALLOW can never
    override a network-level BLOCK. It is precomputed into dev.eff_blocked.
  - Traffic MODE (allow < limit < cut) is a SEPARATE, device-only axis. Domain/
    service blocking is orthogonal to it: a blocked-domain request is dropped
    regardless of mode; non-blocked traffic then follows the device's mode.
    Within a packet, the block check runs first (DROP), then cut (DROP), then
    limit (LIMIT), else forward — i.e. the most-restrictive applicable action.
"""
from __future__ import annotations

from ..state import is_managed, is_intercepted
from .domains import is_blocked

# packet actions
PASS = "pass"        # not one of our intercepted devices -> route untouched
DROP = "drop"        # cut, or a request to a blocked domain -> drop
LIMIT = "limit"      # managed + limited -> caller applies its token bucket
FORWARD = "forward"  # intercepted but allowed right now (incl. monitor-only) -> forward as-is

__all__ = ["PASS", "DROP", "LIMIT", "FORWARD",
           "is_managed", "is_intercepted", "select_target", "blocks_domain", "action_for", "decide"]


def select_target(src: str, dst: str, lookup):
    """Pick the INTERCEPTED device a transit packet belongs to.

    Uses is_intercepted (enforcement ∪ observation), NOT is_managed — so a
    monitored ALLOW device is selected here and observed, while action_for()
    still returns FORWARD for it. This is the observation/enforcement split: being
    selected means "we see this device's traffic", not "we enforce on it".

    lookup(ip) -> Device | None  (e.g. STATE.get)
    Returns (device, direction) with direction "up" (device is the sender) or
    "down" (device is the receiver), or (None, None) if neither end is intercepted.
    """
    dev = lookup(src)
    if dev is not None and is_intercepted(dev):
        return dev, "up"
    dev2 = lookup(dst)
    if dev2 is not None and is_intercepted(dev2):
        return dev2, "down"
    return None, None


def blocks_domain(target, direction: str, domain) -> bool:
    """True if this outbound request is to a domain blocked for the target.

    Uses the precomputed EFFECTIVE keyword set (device ad-hoc ∪ device services ∪
    network ad-hoc ∪ network services — union, most-restrictive wins, so a device
    ALLOW cannot override a NETWORK block). Falls back to the raw device list when
    eff_blocked has not been computed (e.g. a unit test that sets only .blocked).
    The set is precomputed at mutation time, so this stays O(keywords) with no
    catalog/JSON work on the hot path."""
    if not (direction == "up" and domain):
        return False
    keywords = target.eff_blocked or target.blocked
    return bool(keywords and is_blocked(domain, keywords))


def action_for(target, direction: str, domain) -> str:
    """Final drop/limit/forward decision for a packet already matched to a
    managed target. `domain` is the outbound request's domain, or None."""
    if blocks_domain(target, direction, domain):
        return DROP          # blocked domain -> drop the request only
    if target.mode in ("cut", "hardcut"):
        return DROP          # cut / hard cut -> drop everything (hard cut also
                             # blackholes earlier in the forwarder; see _handle)
    if target.mode == "limit":
        return LIMIT         # limited -> caller applies the token bucket
    return FORWARD           # allowed (incl. allow+blocks non-blocked traffic)


def decide(src: str, dst: str, up_domain, lookup):
    """Pure, fully-composed classification (used by tests and both engines'
    fast paths). Returns (action, target|None, direction|None)."""
    target, direction = select_target(src, dst, lookup)
    if target is None:
        return PASS, None, None
    return action_for(target, direction, up_domain), target, direction
