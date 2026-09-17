"""
i18n / global language support (item 27) — catalog integrity + code audit.

These tests are the automated half of the "NO PARTIAL TRANSLATION" requirement:

  * all 5 locales load as valid JSON, with no duplicate keys;
  * every locale has EXACTLY the same key set (and order) as en.json — the English
    source of truth — so English is always a complete fallback;
  * no empty values, correct _meta (lang/name/dir), Arabic is RTL;
  * runtime placeholders ({n}/{mode}/{ip}/…) survive translation in every value;
  * each locale actually translates the catalogue (only a small whitelist of
    technical tokens — DNS, TTL, brand names — may stay English);
  * every translation key referenced from the HTML (data-i18n*) and the JS (t("…"))
    exists in the catalogue — catches raw/typo'd keys that would render as the key;
  * the UI carries no hard-coded Space Grotesk and loads i18n.js first.

Browser-level checks (all 5 render across major screens, live switch, RTL mirroring,
persistence) are done with real screenshots in the i18n browser pass — see the
Phase-7 i18n report — because they need a DOM, which pytest doesn't have.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "frontend" / "i18n"
JS = ROOT / "frontend" / "js"
CSS = ROOT / "frontend" / "css"
HTML = ROOT / "frontend" / "index.html"

LOCALES = ["en", "ar", "es", "fr", "zh-CN"]
NON_EN = ["ar", "es", "fr", "zh-CN"]
EXPECT_META = {
    "en": ("English", "ltr"),
    "ar": ("العربية", "rtl"),
    "es": ("Español", "ltr"),
    "fr": ("Français", "ltr"),
    "zh-CN": ("简体中文", "ltr"),
}

# tokens that legitimately stay identical to English in some/all languages
# (acronyms, units, brand names, and true cognates). Used only by the
# "actually translated" coverage test.
KEEP_ENGLISH_OK = {
    "defender.title", "intel.dns", "intel.internet", "info.ttl",
    "speed.ping", "speed.dns", "devices.control", "devices.map_internet",
    "devices.map_router", "grade.excellent", "tabs.services", "common.error",
    "monitor.label",   # "Monitor" is a valid Spanish cognate (monitor/monitorear)
    # V3.1: "Notifications" is the correct French word too — identical to English
    # by language, not by omission. (The tray tooltip is the product name and so
    # has no i18n key at all; see backend/tray.py.)
    "tray.notifications", "settings.notifications",
    # "General" is also the Spanish word — identical by language, not by omission.
    "settings.general",
    # Diagnostics: technical terms / cognates identical in some locales by
    # language, not by omission (CPU, RAM, "WebView" brand, es "Normal").
    "settings.diag_cpu", "settings.diag_ram", "settings.diag_webview",
    "settings.perf_normal",
}

PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _raw(code):
    return (I18N / f"{code}.json").read_text(encoding="utf-8")


def _dup_keys(text):
    """Detect duplicate top-level keys (json.loads silently keeps the last)."""
    dups, seen = [], set()

    def hook(pairs):
        for k, _ in pairs:
            if k in seen:
                dups.append(k)
            seen.add(k)
        return dict(pairs)

    json.loads(text, object_pairs_hook=hook)
    return dups


def _load(code):
    return json.loads(_raw(code))


@pytest.fixture(scope="module")
def cats():
    return {code: _load(code) for code in LOCALES}


# ---------------------------------------------------------------- catalog files
def test_all_locales_present_and_valid_json():
    for code in LOCALES:
        p = I18N / f"{code}.json"
        assert p.exists(), f"missing locale file {p}"
        _load(code)  # raises on invalid JSON


def test_no_duplicate_keys():
    for code in LOCALES:
        dups = _dup_keys(_raw(code))
        assert not dups, f"{code}.json has duplicate keys: {dups}"


def test_key_parity_and_order_against_english(cats):
    en_keys = list(cats["en"].keys())
    for code in NON_EN:
        keys = list(cats[code].keys())
        assert set(keys) == set(en_keys), (
            f"{code}.json key set differs: "
            f"missing={set(en_keys) - set(keys)} extra={set(keys) - set(en_keys)}"
        )
        assert keys == en_keys, f"{code}.json key ORDER differs from en.json"


def test_english_is_a_complete_fallback(cats):
    # every key any locale could ask for exists in English
    en = cats["en"]
    for code in NON_EN:
        for k in cats[code]:
            assert k in en, f"{k} in {code}.json but not in en.json (no EN fallback)"


def test_no_empty_values(cats):
    for code in LOCALES:
        empty = [k for k, v in cats[code].items() if not str(v).strip()]
        assert not empty, f"{code}.json has empty values: {empty}"


def test_meta_headers(cats):
    for code in LOCALES:
        d = cats[code]
        name, direction = EXPECT_META[code]
        assert d["_meta.lang"] == code, f"{code}: _meta.lang"
        assert d["_meta.name"] == name, f"{code}: _meta.name"
        assert d["_meta.dir"] == direction, f"{code}: _meta.dir"


def test_arabic_is_rtl(cats):
    assert cats["ar"]["_meta.dir"] == "rtl"


def test_placeholders_preserved(cats):
    en = cats["en"]
    for code in NON_EN:
        d = cats[code]
        for k, v in en.items():
            want = sorted(PLACEHOLDER.findall(str(v)))
            got = sorted(PLACEHOLDER.findall(str(d[k])))
            assert want == got, f"{code}.json[{k}] placeholder mismatch: want {want} got {got}"


def test_each_locale_is_actually_translated(cats):
    """A locale must translate the vast majority of strings — only a tiny
    whitelist of technical tokens may remain byte-identical to English."""
    en = cats["en"]
    translatable = [k for k in en if not k.startswith("_meta")]
    for code in NON_EN:
        d = cats[code]
        same = [k for k in translatable if str(d[k]) == str(en[k])]
        unexpected = [k for k in same if k not in KEEP_ENGLISH_OK]
        assert not unexpected, f"{code}.json leaves these untranslated: {unexpected}"
        # sanity: overwhelmingly translated
        assert len(same) < 0.1 * len(translatable), f"{code}.json barely translated"


def test_arabic_contains_arabic_script(cats):
    ar = cats["ar"]
    arabic = re.compile(r"[؀-ۿ]")
    hits = sum(1 for k, v in ar.items() if not k.startswith("_meta") and arabic.search(str(v)))
    assert hits > 150, f"ar.json has too little Arabic script ({hits} values)"


def test_chinese_contains_han(cats):
    zh = cats["zh-CN"]
    han = re.compile(r"[一-鿿]")
    hits = sum(1 for k, v in zh.items() if not k.startswith("_meta") and han.search(str(v)))
    assert hits > 150, f"zh-CN.json has too little Han script ({hits} values)"


# ------------------------------------------------------- code references audit
STATIC_T = re.compile(r"""\bt\(\s*["']([^"'`+]+?)["']\s*[,)]""")
DATA_I18N = re.compile(r"""data-i18n(?:-title|-aria-label|-placeholder|-html)?=["']([^"']+)["']""")
# dynamic prefixes built at runtime (e.g. t("grade."+g)) → assert the full set exists
DYNAMIC_PREFIX_KEYS = [
    "grade.excellent", "grade.good", "grade.fair", "grade.poor", "grade.offline", "grade.unknown",
    "modes.allow", "modes.limit", "modes.cut",
    "advice.winpcap.title", "advice.winpcap.text",
    "advice.topology.title", "advice.topology.text",
    "smac.done_changed", "smac.done_restored",
    # V3.1 settings panel: t("settings.cat." + category) — one per notification
    # category in backend/engine/notifications.py CATEGORIES
    "settings.cat.new_device", "settings.cat.device_offline", "settings.cat.device_online",
    "settings.cat.cut", "settings.cat.hardcut", "settings.cat.limit",
    "settings.cat.domain_block", "settings.cat.service_block",
    "settings.cat.monitor_started", "settings.cat.monitor_stopped",
    "settings.cat.speedtest", "settings.cat.security",
    # V3.1 background status pill: chosen with a ternary, so not statically matched
    "status.background_on", "status.background_off",
    "status.background_tip_on", "status.background_tip_off",
    # the tray menu is localized by the BACKEND (backend/tray.py), never by JS
    "tray.open", "tray.notifications", "tray.exit",
]


def _referenced_keys():
    keys = set()
    for m in DATA_I18N.finditer(HTML.read_text(encoding="utf-8")):
        keys.add(m.group(1))
    for js in JS.glob("*.js"):
        txt = js.read_text(encoding="utf-8")
        for m in STATIC_T.finditer(txt):
            keys.add(m.group(1))
    return keys


def test_all_referenced_keys_exist_in_catalog(cats):
    en = cats["en"]
    missing = sorted(k for k in _referenced_keys() if k not in en)
    assert not missing, f"UI references keys absent from en.json (would render raw): {missing}"


def test_dynamic_prefix_keys_exist(cats):
    en = cats["en"]
    missing = [k for k in DYNAMIC_PREFIX_KEYS if k not in en]
    assert not missing, f"runtime-composed keys missing from en.json: {missing}"


# ------------------------------------------------------------- UI plumbing
def test_no_space_grotesk_anywhere():
    # match the font, not the mere word (a comment may legitimately mention it):
    # a font-family use is 'Space Grotesk' or Grotesk',/Grotesk"
    bad = re.compile(r"Space Grotesk|Grotesk['\"]")
    for p in list(CSS.glob("*.css")) + [HTML] + list(JS.glob("*.js")):
        assert not bad.search(p.read_text(encoding="utf-8")), f"Space Grotesk font used in {p.name}"


def test_index_loads_i18n_first():
    html = HTML.read_text(encoding="utf-8")
    assert "/js/i18n.js" in html, "i18n.js not loaded"
    # i18n.js must precede the other app scripts so t() is defined for them
    assert html.index("/js/i18n.js") < html.index("/js/a-core.js") < html.index("/js/f-theme.js")


def test_arabic_font_and_early_dir():
    html = HTML.read_text(encoding="utf-8")
    assert "Noto+Sans+Arabic" in html, "Arabic webfont not linked"
    assert '"ar"?"rtl"' in html.replace(" ", ""), "no early RTL bootstrap in <head>"
    assert "sharknet-lang" in html, "language persistence key not referenced in <head>"


def test_language_selector_lives_in_settings():
    """V3.1 Issue 7: the header language selector was removed; the authoritative
    language selector now lives in Settings → Language (g-settings.js paneLanguage,
    a SharkNet-styled .lang-list). setLang() remains the single switch, and the
    header no longer carries the old #langWrap anchor."""
    html = HTML.read_text(encoding="utf-8")
    assert 'id="langWrap"' not in html, "header must no longer carry the language selector"
    settings = (JS / "g-settings.js").read_text(encoding="utf-8")
    assert "lang-list" in settings and "lang-row" in settings, "language pane missing"
    assert "window.setLang" in settings, "language pane must delegate to setLang()"
    assert "setLang" in (JS / "i18n.js").read_text(encoding="utf-8")


def test_rtl_keeps_ip_mac_ltr():
    css = (CSS / "3-features.css").read_text(encoding="utf-8")
    assert 'html[dir="rtl"]' in css, "no RTL rules"
    assert "direction:ltr" in css, "RTL block must force IP/MAC/values back to LTR"
