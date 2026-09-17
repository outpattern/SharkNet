"""
V3.1 UX pass — SHARKmac adapter filtering + settings-drawer regression guards.

Two concerns, both pinned here so they cannot silently come back:

  1. SHARKmac must offer Ethernet and Wi-Fi only. A Bluetooth PAN adapter
     deliberately impersonates Ethernet on Windows (InterfaceType 6, MediaType
     802.3), so any filter based on those fields — or on an English display name —
     is wrong. The authoritative signal is NDIS physical medium 10, backed by the
     driver ComponentID.
  2. The settings drawer must not become a SECOND settings/theme/language state.
     It has to delegate to the existing applyTheme()/setLang()/api("/api/settings")
     paths, and the header background pill must follow real runtime state rather
     than a stored preference.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from backend.engine import macadapter

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "frontend" / "js"
CSS = ROOT / "frontend" / "css"
HTML = ROOT / "frontend" / "index.html"
I18N = ROOT / "frontend" / "i18n"
LOCALES = ["en", "ar", "es", "fr", "zh-CN"]


# ------------------------------------------------ adapter classification
# (medium, if_type, media_str, component_id, name, desc)
REAL_ETHERNET = (14, 6, "802.3", r"PCI\VEN_10EC&DEV_8168", "Ethernet",
                 "Realtek Gaming GbE Family Controller")
REAL_WIFI = (9, 71, "Native 802.11", r"PCI\VEN_8086&DEV_2526", "Wi-Fi",
             "Intel(R) Wireless-AC 9260 160MHz")
# exactly what Windows reports for Bluetooth PAN — note it claims Ethernet/802.3
BLUETOOTH_PAN = (10, 6, "BlueTooth", r"BTH\MS_BTHPAN", "Bluetooth Network Connection",
                 "Bluetooth Device (Personal Area Network)")


def test_real_ethernet_is_offered():
    assert macadapter.adapter_kind(*REAL_ETHERNET) == macadapter.ETHERNET


def test_real_wifi_is_offered():
    assert macadapter.adapter_kind(*REAL_WIFI) == macadapter.WIFI


def test_bluetooth_pan_is_rejected_despite_claiming_ethernet():
    """The regression this guards: InterfaceType 6 + MediaType 802.3 would make a
    naive Ethernet test accept a Bluetooth adapter."""
    assert BLUETOOTH_PAN[1] == 6, "fixture must keep claiming Ethernet"
    assert macadapter.adapter_kind(*BLUETOOTH_PAN) is None


@pytest.mark.parametrize("medium,if_type,media,cid,name,desc", [
    # each Bluetooth signal on its own must be enough
    (10, 6, "802.3", "", "Local Area Connection", "Some adapter"),        # NDIS medium
    (None, 6, "802.3", r"BTH\MS_BTHPAN", "Local Area Connection", "x"),   # ComponentID
    (None, 6, "BlueTooth", "", "Local Area Connection", "x"),             # media string
    (None, 6, "802.3", "", "Bluetooth Network Connection", "x"),          # name fallback
    (None, 6, "802.3", "", "x", "Bluetooth Device (Personal Area Network)"),  # desc
])
def test_every_bluetooth_signal_rejects(medium, if_type, media, cid, name, desc):
    assert macadapter.adapter_kind(medium, if_type, media, cid, name, desc) is None


def test_unknown_media_is_not_offered():
    assert macadapter.adapter_kind(0, 131, "Unspecified", "", "6to4 Adapter", "") is None


# ------------------------------------------------ list_adapters filtering
def _fake_ps(payload):
    return lambda script, timeout=15.0: json.dumps(payload)


def _row(name, desc, guid, medium, if_type, media, cid):
    return {"Name": name, "InterfaceDescription": desc, "ifIndex": 1, "DeviceID": guid,
            "MacAddress": "AA-BB-CC-DD-EE-FF", "PermanentAddress": "AA-BB-CC-DD-EE-FF",
            "Status": "Up", "PhysicalMediaType": media,
            "NdisPhysicalMedium": medium, "InterfaceType": if_type, "ComponentID": cid}


@pytest.fixture(autouse=True)
def _no_adapter_cache():
    macadapter.invalidate_cache()
    yield
    macadapter.invalidate_cache()


def test_list_adapters_drops_bluetooth_and_keeps_ethernet_and_wifi(monkeypatch):
    monkeypatch.setattr(macadapter, "_ps", _fake_ps([
        _row("Ethernet", "Realtek Gaming GbE", "{eth}", 14, 6, "802.3", r"PCI\VEN_10EC"),
        _row("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)",
             "{bt}", 10, 6, "BlueTooth", r"BTH\MS_BTHPAN"),
        _row("Wi-Fi", "Intel(R) Wireless-AC 9260", "{wifi}", 9, 71, "Native 802.11",
             r"PCI\VEN_8086"),
    ]))
    ads = macadapter.list_adapters(force=True)
    names = [a["name"] for a in ads]
    assert names == ["Ethernet", "Wi-Fi"]
    assert not any("bluetooth" in n.lower() for n in names)
    kinds = {a["name"]: a["kind"] for a in ads}
    assert kinds == {"Ethernet": "ethernet", "Wi-Fi": "wifi"}
    assert [a["wireless"] for a in ads] == [False, True]


def test_list_adapters_empty_when_only_bluetooth(monkeypatch):
    """Honest empty state — never fall back to showing Bluetooth."""
    monkeypatch.setattr(macadapter, "_ps", _fake_ps([
        _row("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)",
             "{bt}", 10, 6, "BlueTooth", r"BTH\MS_BTHPAN"),
    ]))
    assert macadapter.list_adapters(force=True) == []


def test_list_adapters_empty_when_os_returns_nothing(monkeypatch):
    monkeypatch.setattr(macadapter, "_ps", lambda script, timeout=15.0: "")
    assert macadapter.list_adapters(force=True) == []


def test_enforcement_interface_list_is_a_separate_module():
    """SHARKmac filtering must not touch SharkNet's enforcement interface source."""
    src = (ROOT / "backend" / "server.py").read_text(encoding="utf-8")
    assert "netinfo.list_interfaces()" in src
    netinfo = (ROOT / "backend" / "engine" / "netinfo.py").read_text(encoding="utf-8")
    assert "macadapter" not in netinfo, "enforcement interface list must not use macadapter"


# ------------------------------------------------ SHARKmac empty state (UI)
def test_sharkmac_ui_has_an_honest_empty_state():
    js = (JS / "e-modals.js").read_text(encoding="utf-8")
    assert "smac.no_adapters" in js, "empty state string not referenced"
    assert "smac-empty" in js
    for loc in LOCALES:
        d = json.loads((I18N / f"{loc}.json").read_text(encoding="utf-8"))
        assert d.get("smac.no_adapters"), f"{loc} missing smac.no_adapters"


# ------------------------------------------------ settings drawer guards
def _settings_js():
    return (JS / "g-settings.js").read_text(encoding="utf-8")


def test_settings_is_a_centered_two_column_popup():
    """The full-height right drawer was replaced by a desktop-style popup with a
    fixed left navigation and a scrolling right pane."""
    js = _settings_js()
    assert "settingsPopup" in js and "sx-scrim" in js
    assert "sxNav" in js and "sxPane" in js, "popup needs nav + pane"
    # the old drawer must be gone from both the script and the stylesheet
    assert "settingsDrawer" not in js and "drawer-scrim" not in js
    # it must NOT hijack the shared modal used by device/about dialogs
    assert "openModal(" not in js, "settings must not reuse the generic modal"
    css = (CSS / "3-features.css").read_text(encoding="utf-8")
    assert ".sx{" in css and ".sx-nav{" in css and ".sx-pane{" in css
    assert ".drawer{" not in css, "old drawer rules still present"


def test_only_the_right_pane_scrolls():
    css = (CSS / "3-features.css").read_text(encoding="utf-8")
    pane = re.search(r"\.sx-pane\{([^}]*)\}", css)
    nav = re.search(r"\.sx-nav\{([^}]*)\}", css)
    head = re.search(r"\.sx-head\{([^}]*)\}", css)
    assert pane and "overflow-y:auto" in pane.group(1), "right pane must scroll"
    assert nav and "overflow:hidden" in nav.group(1), "nav must not scroll"
    assert head and "flex:none" in head.group(1), "header must stay fixed"


def test_popup_uses_logical_properties_for_rtl():
    css = (CSS / "3-features.css").read_text(encoding="utf-8")
    assert "border-inline-end" in css, "nav divider must be logical"
    assert "inset-inline-start" in css, "active accent line must be logical"


def test_popup_closes_via_escape_scrim_and_button():
    js = _settings_js()
    assert '"Escape"' in js
    assert "sxX" in js
    assert "scrim.addEventListener" in js


def test_only_one_section_is_rendered_at_a_time():
    js = _settings_js()
    assert "PANES" in js and "renderPane" in js
    # the pane is replaced wholesale, so two sections can never both be visible
    assert "pane.innerHTML" in js


def test_notification_categories_are_grouped_and_all_real():
    """Every grouped id must be a real backend category — no invented events."""
    from backend.engine.notifications import CATEGORIES
    js = _settings_js()
    m = re.search(r"var GROUPS = \[(.+?)\n  \];", js, re.S)
    assert m, "GROUPS not found"
    listed = set(re.findall(r'"([a-z_]+)"', m.group(1)))
    listed -= {k for k in listed if k.startswith("settings")}
    unknown = listed - set(CATEGORIES)
    assert not unknown, f"UI lists categories the backend does not have: {unknown}"
    assert set(CATEGORIES) <= listed, f"UI omits categories: {set(CATEGORIES) - listed}"


def test_gear_is_the_single_settings_entry_point():
    html = HTML.read_text(encoding="utf-8")
    assert html.count('id="settingsBtn"') == 1
    js = _settings_js()
    assert "settingsBtn" in js and "toggle" in js


def test_drawer_delegates_theme_and_language_instead_of_duplicating_state():
    """The drawer must call the SAME setters the header quick controls use, so the
    two can never drift, and must not keep its own persisted copy."""
    js = _settings_js()
    assert "window.applyTheme" in js, "theme must delegate to applyTheme()"
    assert "window.setLang" in js, "language must delegate to setLang()"
    assert "localStorage" not in js, "drawer must not persist its own settings copy"
    assert 'api("/api/settings"' in js, "writes must go through the settings API"


def test_header_keeps_its_non_redundant_controls():
    """The header keeps the controls that have no dedicated Settings home."""
    html = HTML.read_text(encoding="utf-8")
    for el in ('id="unitToggle"', 'id="speedBtn"', 'id="settingsBtn"',
               'id="aboutBtn"', 'id="bgStatus"'):
        assert el in html, f"header lost {el}"


def test_header_no_longer_carries_language_or_theme_quick_controls():
    """V3.1 Issue 7: language + dark/light quick controls were removed from the
    header — both now live only in Settings (Language / Appearance), driven by the
    same authoritative setLang()/applyTheme() state. Removing the header widgets
    must not remove the header itself, only these two controls."""
    html = HTML.read_text(encoding="utf-8")
    assert 'id="langWrap"' not in html, "header must not carry the language selector"
    assert 'id="themeBtn"' not in html, "header must not carry the theme toggle"
    # the authoritative functions still exist and Settings still drives them
    assert "setLang" in (JS / "i18n.js").read_text(encoding="utf-8")
    assert "function applyTheme" in (JS / "f-theme.js").read_text(encoding="utf-8")
    js = _settings_js()
    assert "window.applyTheme" in js and "window.setLang" in js
    # f-theme must guard the now-optional header theme button so applyTheme() (still
    # the single path, now called from Settings) never throws when it is absent
    ft = (JS / "f-theme.js").read_text(encoding="utf-8")
    assert 'const tb = $("#themeBtn")' in ft and "if (tb)" in ft


def test_background_pill_follows_runtime_not_preference():
    """The pill must be driven by /api/runtime.background (which is tray-gated),
    never by the stored keep_running_on_close preference."""
    js = _settings_js()
    assert "/api/runtime" in js
    assert "RUNTIME.background" in js
    # it must not decide from the settings tree
    assert "SETTINGS.tray.keep_running_on_close" not in js
    server = (ROOT / "backend" / "server.py").read_text(encoding="utf-8")
    # server-side: background requires a live tray
    m = re.search(r'"background":\s*(.+)', server)
    assert m and "tray" in m.group(1), "background must be gated on the tray"


def test_background_pill_uses_the_calmer_status_colour():
    css = (CSS / "3-features.css").read_text(encoding="utf-8")
    base = (CSS / "1-base.css").read_text(encoding="utf-8")
    assert "--status-ok:" in base
    assert base.count("--status-ok:") >= 2, "needs a light-theme value too"
    assert "var(--status-ok)" in css
    m = re.search(r"\.bg-pill\.on\{([^}]*)\}", css)
    assert m and "--status-ok" in m.group(1), "pill must use the calmer token"
    assert "var(--success)" not in m.group(1), "pill should no longer use neon --success"


def test_runtime_status_is_presented_read_only():
    js = _settings_js()
    assert "rt-row" in js and "statusRow" in js
    # the runtime rows must not be checkboxes
    assert 'statusRow' in js and 'type="checkbox"' in js  # checkboxes exist for real settings
    m = re.search(r"function statusRow\(([^)]*)\)\s*\{(.+?)\n  \}", js, re.S)
    assert m, "statusRow not found"
    assert 'type="checkbox"' not in m.group(2), "runtime status must not be editable"


def test_drawer_sections_cover_the_required_groups():
    js = _settings_js()
    for key in ("settings.general", "settings.notifications", "settings.appearance",
                "settings.language", "settings.runtime"):
        assert key in js, f"drawer missing section {key}"


def test_new_drawer_keys_exist_in_every_locale():
    keys = ["settings.general", "settings.appearance", "settings.language",
            "settings.runtime", "settings.theme", "settings.theme_dark",
            "settings.theme_light", "settings.tray_status", "settings.tray_active",
            "settings.tray_off", "settings.background_mode",
            "settings.background_active", "settings.background_off", "settings.close"]
    counts = {}
    for loc in LOCALES:
        d = json.loads((I18N / f"{loc}.json").read_text(encoding="utf-8"))
        missing = [k for k in keys if k not in d]
        assert not missing, f"{loc} missing {missing}"
        counts[loc] = len(d)
    assert len(set(counts.values())) == 1, f"locale key counts drifted: {counts}"
