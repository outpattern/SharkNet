"""
SharkNet Service Intelligence Update (SSIU) — DESIGN + VALIDATION SCAFFOLD.

Phase 7 decision: the service catalog stays STATIC (the bundled
backend/data/services.json is the known-good baseline). There is currently NO
trusted update source, and SharkNet does NOT fetch anything at runtime. This
module is the *prepared architecture* for a FUTURE signed update feed — the
safety/validation pipeline is implemented and unit-tested now, but no network
code is wired. `check_for_updates()` is intentionally a no-op.

Why no live scraping (per the spec): the app must never block startup on a
network call, must never trust arbitrary URLs, and must never silently apply
uncontrolled domains that could over-block. So the runtime only ever loads the
bundled/known-good catalog; any future feed must pass EVERY check below before
it could be applied.

------------------------------------------------------------------------------
FUTURE UPDATE ARCHITECTURE (design, not yet active)
------------------------------------------------------------------------------
1. Trusted source        A single SharkNet-controlled HTTPS endpoint (pinned),
                         e.g. https://updates.sharknet.app/services/v1.json .
                         NEVER a URL discovered online.
2. Update format         {"schema_version": 1, "version": <int>, "generated_at":
                         <iso8601>, "services": [ <Service> ... ]} — same Service
                         shape as services.json.
3. Versioning            Monotonic integer `version`; apply only if feed.version
                         > local.version AND feed.schema_version is understood.
4. Integrity/signature   Ed25519 detached signature over canonical JSON, verified
                         against a PUBLIC KEY pinned in the app. Unsigned/invalid
                         => rejected. (Verifier stubbed here until a key exists.)
5. Validation            validate_catalog(): schema -> ids -> hostnames -> SAFETY
                         (reject shared/broad infra) -> dedupe. See below.
6. Diff/report           diff_catalog(): new / changed / removed candidates, for
                         review before anything is applied.
7. Apply                 Only a signature-verified, fully-validated feed is written
                         to the cache; the bundled baseline is never overwritten.
8. Rollback              Previous known-good kept as <cache>.bak; revert on any
                         post-apply problem. Bundled services.json is the ultimate
                         fallback and is immutable.
9. Cache/offline         Last known-good validated catalog cached at
                         %LOCALAPPDATA%/SharkNet/services_cache.json; loaded only
                         if present, valid, and newer than bundled. Offline or any
                         failure => bundled/cached catalog keeps working normally.
10. Frequency/failure    At most once per start (+ optional 24h), async, best
                         effort. ANY failure => ignore, keep last known-good. The
                         app is NEVER unusable because the update server is down.
"""
from __future__ import annotations

import json
import re

# The single source of truth for "no trusted feed yet -> stay static".
UPDATE_SOURCE = None          # set to the pinned HTTPS endpoint when a signed feed exists
SCHEMA_VERSION = 1

# Generic shared infrastructure that must NEVER become a blocking keyword. Two
# tiers, because a suffix-matched KEYWORD only ever blocks that host and below:
#   _DENY_CDN  — pure CDN/edge infra whose SUBDOMAINS are random/shared/reassigned
#                (d123.cloudfront.net). Reject the root AND any subdomain.
#   _DENY_ROOT — shared API/product roots. Reject ONLY the bare root; a
#                service-DEDICATED named host under one (youtubei.googleapis.com,
#                atv-ps.amazon.com, hls-svod.itunes.apple.com) is safe — the
#                keyword scopes to that host, not the whole shared root.
_DENY_CDN = (
    "akamai.net", "akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net",
    "cloudfront.net", "fastly.net", "fastlylb.net", "azureedge.net", "llnwd.net",
    "footprint.net", "cdn77.org", "incapdns.net", "amazonaws.com", "media-amazon.com",
    "aws-cbc.cloud", "appspot.com",
)
_DENY_ROOT = (
    "googleapis.com", "gstatic.com", "google.com", "1e100.net", "amazon.com",
    "apple.com", "itunes.apple.com", "mzstatic.com", "cloudflare.net", "cloudflare.com",
    "microsoft.com", "windows.net", "windowsupdate.com", "azure.com",
    "onetrust.com", "conviva.com", "demdex.net", "tiqcdn.com", "omtrdc.net",
)

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def is_unsafe_domain(domain: str) -> bool:
    """True if `domain` is generic shared infrastructure that would cause
    collateral over-blocking. Pure-CDN infra is rejected root+subdomains; shared
    API/product roots are rejected only as the BARE root (a service-dedicated host
    under them — e.g. youtubei.googleapis.com — is scoped and allowed)."""
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return True
    for bad in _DENY_CDN:
        if d == bad or d.endswith("." + bad):
            return True
    return d in _DENY_ROOT              # bare root only; a specific host under it is fine


def valid_hostname(domain: str) -> bool:
    d = (domain or "").strip().lower().strip(".")
    return bool(d) and "/" not in d and "*" not in d and bool(_HOST_RE.match(d))


def validate_service(svc: dict) -> tuple:
    """(ok, cleaned|None, problems[]). Validates one service entry: id syntax,
    required fields, and hostname syntax + SAFETY on every domain (unsafe/invalid
    domains are dropped, not silently kept)."""
    problems = []
    sid = str(svc.get("id", "")).strip().lower()
    name = str(svc.get("name", "")).strip()
    if not _ID_RE.match(sid):
        return False, None, [f"bad service id: {sid!r}"]
    if not name:
        return False, None, [f"{sid}: missing name"]
    clean_domains = []
    for d in (svc.get("domains") or []):
        dd = str(d).strip().lower().strip(".")
        if dd.startswith("www."):
            dd = dd[4:]
        if not valid_hostname(dd):
            problems.append(f"{sid}: dropped invalid hostname {d!r}")
            continue
        if is_unsafe_domain(dd):
            problems.append(f"{sid}: REJECTED shared/broad domain {dd!r}")
            continue
        if dd not in clean_domains:
            clean_domains.append(dd)
    if not clean_domains:
        return False, None, problems + [f"{sid}: no safe domains left"]
    cleaned = {
        "id": sid, "name": name,
        "category": str(svc.get("category", "streaming")).strip().lower(),
        "regions": [str(r).strip().lower() for r in (svc.get("regions") or [])],
        "domains": sorted(clean_domains),
        "quic": bool(svc.get("quic", False)),
        "notes": str(svc.get("notes", "")),
    }
    return True, cleaned, problems


def validate_catalog(data) -> tuple:
    """(ok, cleaned_services[], report). Full pipeline for a candidate feed:
    schema-version gate, per-service validation, id de-duplication, safety filter.
    A future signed feed would run THIS before anything could be applied."""
    report = {"accepted": [], "rejected": [], "problems": [], "dropped_domains": 0}
    if isinstance(data, dict):
        if data.get("schema_version") not in (None, SCHEMA_VERSION):
            return False, [], {"problems": [f"unknown schema_version {data.get('schema_version')}"]}
        items = data.get("services")
    else:
        items = data
    if not isinstance(items, list):
        return False, [], {"problems": ["catalog is not a list of services"]}
    cleaned, seen = [], set()
    for svc in items:
        if not isinstance(svc, dict):
            report["rejected"].append(str(svc)[:40])
            continue
        ok, c, probs = validate_service(svc)
        report["problems"].extend(probs)
        report["dropped_domains"] += sum(1 for p in probs if "REJECTED" in p or "invalid hostname" in p)
        if not ok:
            report["rejected"].append(svc.get("id", "?"))
            continue
        if c["id"] in seen:
            report["problems"].append(f"duplicate id dropped: {c['id']}")
            report["rejected"].append(c["id"])
            continue
        seen.add(c["id"])
        cleaned.append(c)
        report["accepted"].append(c["id"])
    return (len(cleaned) > 0), cleaned, report


def diff_catalog(local: list, feed: list) -> dict:
    """New / changed / removed service ids between the local catalog and a
    (already-validated) feed — for review before applying. Read-only."""
    lb = {s["id"]: s for s in local}
    fb = {s["id"]: s for s in feed}
    changed = [i for i in lb.keys() & fb.keys()
               if set(lb[i].get("domains", [])) != set(fb[i].get("domains", []))]
    return {"new": sorted(fb.keys() - lb.keys()),
            "removed": sorted(lb.keys() - fb.keys()),
            "changed": sorted(changed)}


def check_for_updates() -> dict:
    """No-op by design (Phase 7): there is no trusted feed and the app must never
    fetch/scrape at runtime. Returns a status dict so a future implementation can
    slot in behind the same interface without changing callers."""
    return {"enabled": UPDATE_SOURCE is not None, "checked": False,
            "reason": "static catalog — no trusted signed feed configured"}


# The Ed25519 public key that a future signed feed is verified against, pinned in
# the app. None => no feed is trusted yet, so verify_signature always fails closed.
PUBLIC_KEY = None


def verify_signature(payload: bytes, signature) -> bool:
    """Verify an Ed25519 detached signature over the canonical feed bytes against
    the pinned PUBLIC_KEY. FAILS CLOSED: with no pinned key (the current state) or
    any error, returns False — an unsigned/forged feed can never be applied.
    (The cryptography verify is deferred until a key + feed exist; the contract is
    fixed now so callers and tests are stable.)"""
    if not PUBLIC_KEY or not signature:
        return False
    try:  # pragma: no cover - exercised only once a real key/feed exists
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(
            base64.b64decode(signature), payload)
        return True
    except Exception:
        return False


def _atomic_write_json(path: str, obj) -> None:
    """Write JSON to `path` atomically (temp file + os.replace) so a crash mid-write
    never leaves a truncated/corrupt catalog on disk."""
    import os
    import tempfile
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False)
        os.replace(tmp, path)                 # atomic on Windows + POSIX
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def apply_update(feed: dict, *, cache_path: str, local_version: int = 0,
                 require_signature: bool = True) -> dict:
    """Guarded apply of a candidate feed to the on-disk cache. Never raises, never
    partially applies, and can NEVER make the app unusable — on ANY failure it
    leaves the existing cache untouched and reports why. Steps:
      1. version gate   (feed.version must be > local_version)
      2. signature      (verify_signature; skippable only for offline tests)
      3. validation     (validate_catalog: schema/id/hostname/SAFETY/dedupe)
      4. backup         (copy current cache -> <cache>.bak for rollback)
      5. atomic write   (temp + os.replace)
    Returns {applied, reason, version, accepted}."""
    import os
    try:
        version = int(feed.get("version", 0)) if isinstance(feed, dict) else 0
    except Exception:
        version = 0
    if version <= int(local_version or 0):
        return {"applied": False, "reason": "not newer", "version": version}
    if require_signature and not verify_signature(
            json.dumps(feed.get("services", []), sort_keys=True, separators=(",", ":")).encode(),
            (feed or {}).get("signature")):
        return {"applied": False, "reason": "signature invalid/missing", "version": version}
    ok, cleaned, report = validate_catalog(feed)
    if not ok:
        return {"applied": False, "reason": "validation failed", "version": version,
                "problems": report.get("problems", [])}
    try:
        if os.path.exists(cache_path):        # rollback backup
            import shutil
            shutil.copyfile(cache_path, cache_path + ".bak")
        _atomic_write_json(cache_path, {"schema_version": SCHEMA_VERSION,
                                        "version": version, "services": cleaned})
    except Exception as e:
        return {"applied": False, "reason": f"write failed: {e}", "version": version}
    return {"applied": True, "reason": "ok", "version": version, "accepted": len(cleaned)}
