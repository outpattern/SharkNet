"""
Service catalog research-refresh tests + online-update safety scaffold + the
"provider click != server block" regression (Phase 7 pass).

- the bundled catalog loads, is unique, and contains ZERO unsafe/shared-infra domains
- services_update safety validator: pure-CDN infra rejected root+subdomains; shared
  API roots rejected only as the bare root (a dedicated host under one is allowed)
- validate_catalog rejects unsafe domains / bad ids / duplicates
- the online-update mechanism is inert (no live fetch) by design
- viewing a device/service (a GET) never blocks anything; only an explicit
  POST /api/services|domains/block does — proving a provider CLICK is not a block
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine.services import ServiceCatalog, CATALOG            # noqa: E402
from backend.engine import services_update as su                       # noqa: E402
from backend.state import STATE, Device, is_managed                    # noqa: E402
from backend import server                                             # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    def clean():
        STATE.devices.clear(); STATE.net_services = []; STATE.net_domains = []
        STATE.enforcing = False; STATE.controlling = False; STATE.interface = None
    clean(); yield; clean()


# ---------------- catalog integrity ----------------
def test_catalog_loads_unique_and_nonempty():
    cat = ServiceCatalog()
    svc = cat.all()
    assert len(svc) >= 45                       # 47 after the refresh (adtv removed)
    ids = [s.id for s in svc]
    assert len(ids) == len(set(ids)), "duplicate service ids"
    for s in svc:
        assert s.domains, f"{s.id} has no domains"
        assert s.confidence in ("CONFIRMED", "LIKELY", "BEST_EFFORT", "UNKNOWN"), s.confidence
        for d in s.domains:
            assert d == d.lower() and " " not in d and "/" not in d and not d.startswith("www.")


def test_catalog_has_zero_unsafe_domains():
    """The whole bundled catalog must pass the safety validator with NOTHING
    rejected — no shared/broad infra crept in."""
    import json
    data = json.load(open(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                        "backend", "data", "services.json"), encoding="utf-8"))
    ok, cleaned, report = su.validate_catalog(data)
    assert ok and not report["rejected"], report["rejected"]
    bad = [p for p in report["problems"] if "REJECTED" in p or "invalid hostname" in p]
    assert not bad, bad
    assert len(cleaned) == len(data["services"])


def test_research_refresh_specifics():
    cat = ServiceCatalog()
    ids = {s.id for s in cat.all()}
    assert "adtv" not in ids                                    # discontinued -> removed
    assert "vrv.co" not in cat.domains_for(["crunchyroll"])     # dead
    assert "crunchyrollcdn.com" in cat.domains_for(["crunchyroll"])
    assert "now.com" not in cat.domains_for(["now-sky"])        # wrong-service collision removed
    assert "amazonvideo.com" in cat.domains_for(["amazon-prime-video"])
    assert "pscdn.co" in cat.domains_for(["spotify"])
    assert "facebook.net" in cat.domains_for(["facebook"])
    # scoped, never bare
    assert "yango.com" not in cat.domains_for(["yango-play"])
    assert "play.yango.com" in cat.domains_for(["yango-play"])


# ---------------- safety validator ----------------
def test_is_unsafe_domain_two_tier():
    # pure CDN: root AND subdomains unsafe
    assert su.is_unsafe_domain("cloudfront.net")
    assert su.is_unsafe_domain("d123.cloudfront.net")
    assert su.is_unsafe_domain("x.akamaized.net")
    assert su.is_unsafe_domain("s3.amazonaws.com")
    # shared API root: bare root unsafe, dedicated host under it SAFE
    assert su.is_unsafe_domain("googleapis.com")
    assert not su.is_unsafe_domain("youtubei.googleapis.com")
    assert not su.is_unsafe_domain("atv-ps.amazon.com")
    assert su.is_unsafe_domain("amazon.com")
    # legit service domains safe
    assert not su.is_unsafe_domain("nflxvideo.net")
    assert not su.is_unsafe_domain("ggpht.com")


def test_validate_catalog_rejects_bad_feed():
    feed = {"schema_version": 1, "services": [
        {"id": "evil", "name": "Evil", "domains": ["cloudfront.net", "akamaized.net", "real-svc.com"]},
        {"id": "BAD ID", "name": "x", "domains": ["ok.com"]},
        {"id": "empty", "name": "Empty", "domains": ["googleapis.com"]},   # only unsafe -> dropped
        {"id": "good", "name": "Good", "domains": ["good-svc.com", "cdn.good-svc.com"]},
        {"id": "good", "name": "Dup", "domains": ["dup.com"]},              # duplicate id
    ]}
    ok, cleaned, report = su.validate_catalog(feed)
    got = {c["id"]: c["domains"] for c in cleaned}
    assert got.get("evil") == ["real-svc.com"]        # shared infra stripped
    assert "good" in got and got["good"] == ["cdn.good-svc.com", "good-svc.com"]
    assert "BAD ID" in report["rejected"] and "empty" in report["rejected"]
    assert "duplicate id dropped: good" in report["problems"]


def test_validate_catalog_rejects_unknown_schema():
    ok, cleaned, report = su.validate_catalog({"schema_version": 999, "services": []})
    assert not ok


def test_diff_catalog():
    local = [{"id": "a", "domains": ["a.com"]}, {"id": "b", "domains": ["b.com"]}]
    feed = [{"id": "a", "domains": ["a.com", "a2.com"]}, {"id": "c", "domains": ["c.com"]}]
    d = su.diff_catalog(local, feed)
    assert d["new"] == ["c"] and d["removed"] == ["b"] and d["changed"] == ["a"]


def test_online_update_is_inert_by_design():
    assert su.UPDATE_SOURCE is None
    status = su.check_for_updates()
    assert status["enabled"] is False and status["checked"] is False


# ---------------- provider CLICK != server block (mid-turn bug regression) ----------------
def test_viewing_a_service_or_device_does_not_block(monkeypatch):
    """Clicking a provider/device to VIEW it (a GET) must never change block
    state; only an explicit POST block does. Proves 'provider click != block'."""
    monkeypatch.setenv("SHARKNET_DEMO", "1")
    d = Device(ip="10.0.0.5", mac="aa", mode="allow")
    STATE.devices["10.0.0.5"] = d

    # viewing the catalog + the device (what a click that opens info does) = GET, no mutation
    server.api_services()
    server.api_domains_get("10.0.0.5")
    assert d.services == [] and d.blocked == [] and not is_managed(d), "a view/click must not block"

    # only an EXPLICIT block call mutates state
    server.api_services_block(server.ServiceBlockReq(ip="10.0.0.5", services=["netflix"]))
    assert d.services == ["netflix"] and is_managed(d), "explicit block must block"

    # and an explicit unblock clears it
    server.api_services_block(server.ServiceBlockReq(ip="10.0.0.5", services=[]))
    assert d.services == [] and not is_managed(d)
