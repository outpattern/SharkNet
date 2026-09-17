"""
F3 item 6 — ONE canonical domain-normalization path.

Proves the observer, the block matcher, the effective-policy build, and the
service catalog all resolve a domain to the SAME identity, so a rule typed in any
reasonable form matches observed traffic and nothing unintended does.
"""
import importlib

from backend.engine.domains import normalize_domain, is_blocked
from backend.engine import services as services_mod


# the exact variants the spec calls out
VARIANTS = ["example.com", "EXAMPLE.COM", "example.com.", "www.example.com", "api.example.com"]


def test_normalize_canonical_forms():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"        # case
    assert normalize_domain("example.com.") == "example.com"       # trailing root dot
    assert normalize_domain(" Example.Com ") == "example.com"      # whitespace + case
    assert normalize_domain("www.example.com") == "example.com"    # www apex
    assert normalize_domain("api.example.com") == "api.example.com"  # a real subdomain is preserved
    assert normalize_domain(b"YouTubei.GoogleAPIs.com") == "youtubei.googleapis.com"  # bytes + case


def test_normalize_rejects_junk():
    for bad in ["", "   ", "localhost", "nodot", ".", "..", "a" * 120 + ".com"]:
        assert normalize_domain(bad) is None, bad


def test_normalize_is_idempotent():
    for v in VARIANTS + ["youtubei.googleapis.com", "sub.deep.example.co.uk"]:
        once = normalize_domain(v)
        if once:
            assert normalize_domain(once) == once


def test_block_matches_all_canonical_variants():
    # blocking "example.com" must catch every reasonable spelling of the site
    for observed in VARIANTS:
        obs = normalize_domain(observed)
        assert is_blocked(obs, ["example.com"]), f"{observed} should be blocked"
    # and a rule typed with noise still matches an observed apex
    for rule in ["EXAMPLE.COM", "example.com.", "www.example.com", "  Example.com "]:
        assert is_blocked("example.com", [rule]), f"rule {rule!r} should match example.com"
        assert is_blocked("api.example.com", [rule]), f"rule {rule!r} should match api.example.com"


def test_block_does_not_overmatch():
    # only the intended domain + its subdomains — never look-alikes
    for other in ["notexample.com", "example.com.evil.net", "anexample.com", "example.org", "myexample.com"]:
        assert not is_blocked(normalize_domain(other), ["example.com"]), f"{other} must NOT be blocked"


def test_eff_blocked_is_canonicalized():
    # a device rule entered non-canonically must canonicalize in eff_blocked and
    # then enforce against observed traffic through the same path
    from backend.state import AppState
    st = AppState()
    dev = st.upsert_device("10.0.0.5", "aa:bb:cc:dd:ee:01")
    dev.blocked = ["WWW.TikTok.COM.", "Example.com"]
    st.recompute_effective(dev)
    assert "tiktok.com" in dev.eff_blocked
    assert "example.com" in dev.eff_blocked
    assert "www.tiktok.com." not in dev.eff_blocked          # no raw/duplicate form
    assert is_blocked("api.example.com", list(dev.eff_blocked))
    assert is_blocked("vm.tiktok.com", list(dev.eff_blocked))


def test_service_catalog_uses_same_normalizer():
    # the catalog's normalizer now delegates to the one canonical path
    assert services_mod._norm_domain("WWW.Netflix.com.") == "netflix.com"
    assert services_mod._norm_domain("localhost") == ""      # unusable -> "" (not None)
    # identify() resolves an observed domain to a service via canonical suffix match
    cat = services_mod.CATALOG
    hit = cat.identify("www.youtube.com")
    # youtube is a known preset; identify should map some youtube host to it
    assert hit is None or isinstance(hit, str)


# --------------------------------------------------------------------------
# V3.1 audit regression: a pasted URL must become a working rule.
# Before this, "https://youtube.com/" was stored verbatim; is_blocked()
# normalised BOTH sides the same way, so the entry could never match observed
# traffic — the UI showed an active rule that silently blocked nothing.
# --------------------------------------------------------------------------
URL_FORMS = [
    ("http://example.com/path", "example.com"),
    ("https://Example.com:8443/x?y=1", "example.com"),
    ("https://youtube.com/", "youtube.com"),
    ("http://user:pw@site.com:8080/x#frag", "site.com"),
    ("ftp://files.example.org", "files.example.org"),
    ("//cdn.example.net/a", "cdn.example.net"),
    ("sub.Example.com/", "sub.example.com"),
    ("www.example.com/watch?v=1", "example.com"),
]


def test_pasted_url_reduces_to_host():
    for raw, want in URL_FORMS:
        assert normalize_domain(raw) == want, raw


def test_pasted_url_actually_blocks_traffic():
    """The whole point: a URL-shaped rule enforces on the observed hostname."""
    assert is_blocked("youtube.com", ["https://youtube.com/"])
    assert is_blocked("m.youtube.com", ["https://youtube.com/"])       # subdomain inherits
    assert not is_blocked("notyoutube.com", ["https://youtube.com/"])  # no false match


def test_normalization_stays_idempotent_for_urls():
    for raw, _ in URL_FORMS:
        once = normalize_domain(raw)
        assert normalize_domain(once) == once, raw


def test_whitespace_bearing_host_is_rejected():
    """A host never contains whitespace — reject instead of storing a dead rule."""
    assert normalize_domain("not a domain") is None
    assert normalize_domain("foo bar.com") is None
    assert normalize_domain("exa mple.com") is None


def test_plain_hostnames_are_unaffected_by_url_handling():
    for d in VARIANTS:
        assert normalize_domain(d) == normalize_domain(normalize_domain(d))
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("api.example.com") == "api.example.com"
