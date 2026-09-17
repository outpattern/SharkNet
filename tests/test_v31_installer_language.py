"""
V3.1 installer "initial application language" feature.

Setup lets the user choose SharkNet's INITIAL language; the choice is written as a
one-time seed the app consumes on its FIRST launch only (a fresh profile), then the
normal locale/localStorage model is authoritative. An upgrade never overwrites a
saved language or theme. A missing/invalid choice falls back to English, and the
seed can never affect the engine.
"""
from __future__ import annotations

import importlib
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def s(monkeypatch):
    """Fresh %LOCALAPPDATA% so settings + the seed file are per-test and empty."""
    monkeypatch.setenv("LOCALAPPDATA", tempfile.mkdtemp(prefix="sn_lang_"))
    from backend import settings as _s
    importlib.reload(_s)
    return _s


# ---------------------------------------------------------------- backend seed
def test_fresh_install_applies_the_seed(s):
    s._seed_path().write_text("ar", encoding="utf-8")
    assert not s._path().exists(), "precondition: fresh profile (no settings.json)"
    assert s.seed_initial_language() == "ar"
    assert s.load()["locale"] == "ar"
    assert not s._seed_path().exists(), "seed must be consumed (deleted)"


def test_every_shipped_locale_is_accepted(s):
    for code in ("en", "ar", "es", "fr", "zh-CN"):
        # fresh profile per code
        d = s._data_dir()
        for p in (s._path(), s._seed_path()):
            if p.exists():
                p.unlink()
        s._seed_path().write_text(code, encoding="utf-8")
        assert s.seed_initial_language() == code
        assert s.load()["locale"] == code


def test_upgrade_preserves_existing_language(s):
    # user has already run and chosen Spanish
    s.save({"locale": "es"})
    assert s._path().exists()
    # a later Setup seeds French, but the saved choice must win
    s._seed_path().write_text("fr", encoding="utf-8")
    assert s.seed_initial_language() is None, "must not apply on an existing profile"
    assert s.load()["locale"] == "es", "upgrade must preserve the saved language"
    assert not s._seed_path().exists(), "stale seed still consumed, never lingers"


def test_invalid_seed_falls_back_to_english(s):
    s._seed_path().write_text("klingon", encoding="utf-8")
    assert s.seed_initial_language() is None
    assert s.load()["locale"] == "en"
    assert not s._seed_path().exists()


def test_no_seed_is_a_noop(s):
    assert s.seed_initial_language() is None
    assert s.load()["locale"] == "en"


def test_blank_or_whitespace_seed_is_safe(s):
    s._seed_path().write_text("   \n", encoding="utf-8")
    assert s.seed_initial_language() is None
    assert s.load()["locale"] == "en"
    assert not s._seed_path().exists()


def test_seed_is_locale_only_and_never_touches_theme_or_tray(s):
    s.save({"tray": {"minimize_to_tray": False}})   # existing profile w/ a theme-ish pref
    s._seed_path().write_text("fr", encoding="utf-8")
    s.seed_initial_language()                        # upgrade path -> no change
    got = s.load()
    assert got["locale"] == "en", "preserved (was a fresh save with default locale)"
    assert got["tray"]["minimize_to_tray"] is False, "seed must not disturb other settings"


def test_seed_module_pulls_in_no_engine():
    """A language seed must not be able to affect the network engine."""
    src = (ROOT / "backend" / "settings.py").read_text(encoding="utf-8")
    for engine in ("forwarder", "spoofer", "scanner", "protection", "server import"):
        assert f"import {engine}" not in src


# ------------------------------------------------------- server index injection
def test_index_injects_the_locale_seed(monkeypatch):
    from backend import server
    monkeypatch.setattr(server.app_settings, "load", lambda: {"locale": "ar"})
    body = server.index().body.decode("utf-8")
    assert "__SHARKNET_LANG__" not in body, "placeholder must be replaced"
    assert 'name="sharknet-initial-lang" content="ar"' in body


def test_index_defaults_to_en_when_locale_missing(monkeypatch):
    from backend import server
    monkeypatch.setattr(server.app_settings, "load", lambda: {})
    body = server.index().body.decode("utf-8")
    assert 'content="en"' in body


# ------------------------------------------------------------- frontend wiring
def test_index_html_carries_the_seed_placeholders():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert 'name="sharknet-initial-lang" content="__SHARKNET_LANG__"' in html
    # the early bootstrap also honours the seed before scripts load
    assert '"sharknet-lang")||"__SHARKNET_LANG__"' in html


def test_i18n_uses_seed_only_when_localstorage_empty():
    js = (ROOT / "frontend" / "js" / "i18n.js").read_text(encoding="utf-8")
    assert "seededLang" in js and "sharknet-initial-lang" in js
    # the user's saved choice must still take precedence
    assert "if (s && known(s)) return s;" in js


# ------------------------------------------------------------- installer wiring
def test_installer_offers_the_five_application_languages():
    iss = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "CreateInputOptionPage" in iss and "Application language" in iss
    for code in ("'en'", "'ar'", "'es'", "'fr'", "'zh-CN'"):
        assert code in iss, f"installer missing language code {code}"


def test_installer_writes_the_seed_the_app_reads():
    iss = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "initial-language.txt" in iss and "SaveStringToFile" in iss
    assert "{localappdata}\\SharkNet" in iss


def test_installer_preserves_language_on_upgrade():
    iss = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "ExistingLanguagePref" in iss and "ShouldSkipPage" in iss
    # the seed writer bails out when a preference already exists
    assert "if ExistingLanguagePref() then Exit;" in iss


def test_installer_does_not_add_a_theme_choice():
    """Theme stays only in Settings -> Appearance; the installer must not set it."""
    iss = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert "initial-theme" not in iss and "theme.txt" not in iss
