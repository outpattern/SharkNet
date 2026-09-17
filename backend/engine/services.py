"""
Service catalog — the data-driven "block a whole app/service" abstraction (Phase 7).

A Service groups the real domains an app/streaming platform uses (web + app + CDN
+ API) under ONE identity, so "block YouTube" blocks the service rather than a
single domain. Blocking reuses the SAME mechanism as ad-hoc domain blocking:
`policy` drops an outbound request (DNS query name / TLS SNI / HTTP Host) whose
domain matches — exact-or-subdomain — any keyword in the service's domain list.

There is NO per-service engine code: a service is a data entry in
backend/data/services.json. Adding a future service is a catalog edit, never new
enforcement logic. The catalog is loaded ONCE and cached; nothing here runs per
packet (the forwarder reads a per-device precomputed keyword tuple — see
state.recompute_effective).

Signals & honesty (Phase 7 / decision D1-A): a block is deterministic on the
cleartext request signals we can read — DNS(53), TLS-SNI(tcp/443), HTTP-Host(80).
QUIC/UDP-443 carries no cleartext SNI here (we do NOT decrypt QUIC Initial in this
phase), so QUIC is handled best-effort by pinning the IPs a blocked domain
resolved to for a device (forwarder._note_dns_answer / QUIC drop). We therefore
never claim a service is universally/100% blocked; the coverage a block gives is
described by `block_signals()`.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Service:
    id: str
    name: str
    category: str = "streaming"          # streaming | social | gaming | messaging | music
    regions: tuple = ()                  # ("mena","us","eu","global")
    domains: tuple = ()                  # base-domain keywords (suffix-matched)
    quic: bool = False                   # heavily uses QUIC/HTTP3 (UDP 443)
    notes: str = ""
    confidence: str = "LIKELY"           # CONFIRMED | LIKELY | BEST_EFFORT | UNKNOWN

    def meta(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "regions": list(self.regions), "domain_count": len(self.domains),
            "quic": self.quic, "confidence": self.confidence, "notes": self.notes,
        }


def _data_candidates(filename: str) -> list:
    here = os.path.dirname(os.path.abspath(__file__))
    out = [os.path.join(here, "..", "data", filename)]
    base = getattr(sys, "_MEIPASS", None)                # PyInstaller frozen root
    if base:
        out.append(os.path.join(base, "backend", "data", filename))
        out.append(os.path.join(base, "data", filename))
    return out


def _norm_domain(d) -> str:
    # F3 item 6: the service catalog canonicalizes domains through the SAME path as
    # the observer / block matcher / policy engine — one identity everywhere.
    # Returns "" (not None) for anything unusable, to keep the catalog-load filter
    # and suffix checks working on plain strings.
    from .domains import normalize_domain
    return normalize_domain(d) or ""


class ServiceCatalog:
    """Loads services.json once; provides id/domain lookups. Fails soft to an
    empty catalog so a missing/corrupt file can never crash the engine."""

    def __init__(self) -> None:
        self._by_id: dict[str, Service] = {}
        self._kw_to_id: dict[str, str] = {}   # domain keyword -> service id (for identify)
        self._loaded = False

    # ---- loading ----
    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        for p in _data_candidates("services.json"):
            try:
                if not os.path.exists(p):
                    continue
                with open(p, encoding="utf-8") as fh:
                    data = json.load(fh)
                items = data.get("services") if isinstance(data, dict) else data
                for it in items or []:
                    sid = str(it.get("id") or "").strip().lower()
                    name = str(it.get("name") or sid).strip()
                    if not sid or not name:
                        continue
                    domains = tuple(sorted({_norm_domain(d) for d in (it.get("domains") or []) if _norm_domain(d)}))
                    svc = Service(
                        id=sid, name=name,
                        category=str(it.get("category") or "streaming").strip().lower(),
                        regions=tuple(str(r).strip().lower() for r in (it.get("regions") or [])),
                        domains=domains,
                        quic=bool(it.get("quic", False)),
                        notes=str(it.get("notes") or ""),
                        confidence=str(it.get("confidence") or "LIKELY").strip().upper().replace("-", "_"),
                    )
                    self._by_id[sid] = svc
                    for kw in domains:
                        # first service to claim a keyword owns it for identify()
                        self._kw_to_id.setdefault(kw, sid)
                break
            except Exception:
                # leave whatever loaded; never raise from catalog load
                continue

    # ---- queries ----
    def all(self) -> list:
        self._load()
        return sorted(self._by_id.values(), key=lambda s: (s.category, s.name.lower()))

    def meta(self) -> list:
        return [s.meta() for s in self.all()]

    def get(self, sid: str):
        self._load()
        return self._by_id.get((sid or "").strip().lower())

    def exists(self, sid: str) -> bool:
        return self.get(sid) is not None

    def domains_for(self, ids) -> tuple:
        """Union of domain keywords for the given service ids (unknown ids
        ignored). Returned sorted+deduped so callers can cache it cheaply."""
        self._load()
        out: set[str] = set()
        for sid in ids or []:
            svc = self._by_id.get((sid or "").strip().lower())
            if svc:
                out.update(svc.domains)
        return tuple(sorted(out))

    def uses_quic(self, ids) -> bool:
        self._load()
        for sid in ids or []:
            svc = self._by_id.get((sid or "").strip().lower())
            if svc and svc.quic:
                return True
        return False

    def identify(self, domain: str):
        """Which service a domain belongs to (exact-or-parent-suffix), or None.
        Used to CLASSIFY observed traffic (identified vs unknown), not to block.
        O(number of labels) — checks the domain and each parent suffix."""
        self._load()
        d = _norm_domain(domain)
        if not d:
            return None
        parts = d.split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            sid = self._kw_to_id.get(suffix)
            if sid:
                return sid
        return None


CATALOG = ServiceCatalog()


def block_signals(service_id: str) -> dict:
    """Coverage a block gives for a service, so the UI/tests never over-claim.
    'identified' = we know this service's domains; DNS/TLS/HTTP are deterministic
    request signals; QUIC is best-effort (scoped IP-pinning, no decryption)."""
    svc = CATALOG.get(service_id)
    if svc is None:
        return {"identified": False, "dns": False, "tls": False, "http": False,
                "quic": "unknown"}
    return {
        "identified": True,
        "dns": True, "tls": True, "http": True,
        # QUIC coverage is best-effort even for services that lean on it heavily
        "quic": "best_effort" if svc.quic else "not_applicable",
    }
