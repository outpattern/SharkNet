// SharkNet · i18n runtime (loaded FIRST, before a-core.js)
// -----------------------------------------------------------------------------
// Centralized, data-driven localization. Translation strings live in
// /i18n/<code>.json (flat dotted keys); this module loads the active locale
// (English always loaded as the fallback), exposes t()/applyI18n()/setLang(),
// wires the header language selector, and handles RTL. Backend/API values stay
// stable English identifiers — only presentation is localized. Technical values
// (IP / MAC / DNS / service names) are never translated.
//
// Loaded before the other app scripts so t() is available synchronously to all
// of them. The dictionaries are fetched with a blocking request against our own
// localhost static server (a few KB, instant) so the very first paint is already
// in the chosen language with no flash of untranslated text.
// -----------------------------------------------------------------------------
(function () {
  "use strict";

  var LANGS = [
    { code: "en", name: "English", dir: "ltr" },
    { code: "ar", name: "العربية", dir: "rtl" },
    { code: "es", name: "Español", dir: "ltr" },
    { code: "fr", name: "Français", dir: "ltr" },
    { code: "zh-CN", name: "简体中文", dir: "ltr" },
  ];
  var STORE_KEY = "sharknet-lang";
  // reuse this script's own ?v= cache-bust for the locale fetches, so a new build
  // never serves a stale locale file from cache.
  var CB = (function () {
    try {
      var s = document.currentScript && document.currentScript.src;
      var m = s && s.match(/[?&]v=([^&]+)/);
      return m ? "?v=" + m[1] : "";
    } catch (e) { return ""; }
  })();

  var I18N = { lang: "en", dict: {}, fb: {}, langs: LANGS };

  function meta(code) {
    for (var i = 0; i < LANGS.length; i++) if (LANGS[i].code === code) return LANGS[i];
    return LANGS[0];
  }
  function known(code) {
    for (var i = 0; i < LANGS.length; i++) if (LANGS[i].code === code) return true;
    return false;
  }
  // the installer/first-run seed injected into index.html by the server. Used
  // ONLY when the user has not chosen a language yet (empty localStorage).
  function seededLang() {
    try {
      var m = document.querySelector('meta[name="sharknet-initial-lang"]');
      var v = m && m.getAttribute("content");
      return (v && known(v)) ? v : "en";
    } catch (e) { return "en"; }
  }
  function savedLang() {
    try {
      var s = localStorage.getItem(STORE_KEY);
      if (s && known(s)) return s;         // the user's own saved choice always wins
    } catch (e) {}
    return seededLang();                    // else the installer/first-run seed, else en
  }

  // synchronous load of a locale file from our own static server. Returns the
  // parsed object, or null on any failure (missing file, bad JSON, offline).
  function loadDict(code) {
    try {
      var x = new XMLHttpRequest();
      x.open("GET", "/i18n/" + encodeURIComponent(code) + ".json", false);
      x.send(null);
      if (x.status >= 200 && x.status < 300) return JSON.parse(x.responseText);
    } catch (e) {}
    return null;
  }

  // local escape (a-core.js's esc() isn't defined yet when this module boots)
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // translate a key with optional {name} interpolation. Missing keys fall back to
  // English, then to the raw key (so a missing string is visible, never blank).
  function t(key, params) {
    var s = I18N.dict && I18N.dict[key];
    if (s == null) s = I18N.fb && I18N.fb[key];
    if (s == null) return key;
    if (params) {
      for (var k in params) {
        if (Object.prototype.hasOwnProperty.call(params, k)) {
          s = s.replace(new RegExp("\\{" + k + "\\}", "g"), params[k]);
        }
      }
    }
    return s;
  }

  // apply translations to a subtree. Supports:
  //   data-i18n           -> textContent
  //   data-i18n-html      -> innerHTML (our own trusted strings only)
  //   data-i18n-title / -aria-label / -placeholder -> that attribute
  var ATTRS = ["title", "aria-label", "placeholder"];
  function applyI18n(root) {
    root = root || document;
    root.querySelectorAll("[data-i18n]").forEach(function (el) {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    root.querySelectorAll("[data-i18n-html]").forEach(function (el) {
      el.innerHTML = t(el.getAttribute("data-i18n-html"));
    });
    ATTRS.forEach(function (a) {
      root.querySelectorAll("[data-i18n-" + a + "]").forEach(function (el) {
        el.setAttribute(a, t(el.getAttribute("data-i18n-" + a)));
      });
    });
  }

  function applyDir(code) {
    var m = meta(code);
    document.documentElement.setAttribute("lang", code);
    document.documentElement.setAttribute("dir", m.dir);
  }

  // ---- boot: load fallback (en) + active locale synchronously ----
  (function boot() {
    var want = savedLang();
    I18N.fb = loadDict("en") || {};
    if (want === "en") {
      I18N.dict = I18N.fb;
      I18N.lang = "en";
    } else {
      var d = loadDict(want);
      if (d) { I18N.dict = d; I18N.lang = want; }
      else { I18N.dict = I18N.fb; I18N.lang = "en"; }   // failed → English
    }
    applyDir(I18N.lang);
  })();

  // ---- language selector (header) ----
  function shortCode(code) {
    return (code === "zh-CN" ? "ZH" : code.split("-")[0]).toUpperCase();
  }
  function buildSelector() {
    var wrap = document.getElementById("langWrap");
    if (!wrap) return;
    wrap.innerHTML =
      '<button id="langBtn" class="lang-btn" aria-haspopup="true" aria-expanded="false">' +
        '<span class="lang-globe" aria-hidden="true"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/></svg></span>' +
        '<span class="lang-code">' + esc(shortCode(I18N.lang)) + '</span>' +
        '<span class="lang-caret" aria-hidden="true">▾</span>' +
      '</button>' +
      '<div id="langMenu" class="lang-menu hidden" role="menu"></div>';
    var menu = wrap.querySelector("#langMenu");
    menu.innerHTML = LANGS.map(function (l) {
      var on = l.code === I18N.lang;
      return '<button role="menuitemradio" aria-checked="' + (on ? "true" : "false") +
        '" data-l="' + esc(l.code) + '" class="lm' + (on ? " on" : "") + '">' +
        '<span class="lm-check" aria-hidden="true">' + (on ? "✓" : "") + '</span>' +
        '<span class="lm-name"' + (l.dir === "rtl" ? ' dir="rtl"' : "") + '>' + esc(l.name) + '</span>' +
        '</button>';
    }).join("");
    var btn = wrap.querySelector("#langBtn");
    btn.setAttribute("title", t("lang.tip"));
    btn.setAttribute("aria-label", t("lang.tip"));
    btn.onclick = function (e) { e.stopPropagation(); toggleMenu(); };
    menu.querySelectorAll("button").forEach(function (b) {
      b.onclick = function (e) { e.stopPropagation(); setLang(b.getAttribute("data-l")); closeMenu(); };
    });
  }
  function toggleMenu() {
    var m = document.getElementById("langMenu"), b = document.getElementById("langBtn");
    if (!m) return;
    var hidden = m.classList.toggle("hidden");
    if (b) b.setAttribute("aria-expanded", hidden ? "false" : "true");
  }
  function closeMenu() {
    var m = document.getElementById("langMenu"), b = document.getElementById("langBtn");
    if (m) m.classList.add("hidden");
    if (b) b.setAttribute("aria-expanded", "false");
  }
  document.addEventListener("click", closeMenu);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenu(); });

  // switch language live — no restart. Loads the locale, persists it, flips
  // dir/lang, re-applies static translations, rebuilds the selector, and asks the
  // app to re-render its dynamic surfaces with the new strings.
  function setLang(code) {
    if (!known(code)) return;
    if (code === "en") { I18N.dict = I18N.fb; }
    else {
      var d = loadDict(code);
      if (d) { I18N.dict = d; }
      else { I18N.dict = I18N.fb; code = "en"; }
    }
    I18N.lang = code;
    try { localStorage.setItem(STORE_KEY, code); } catch (e) {}
    applyDir(code);
    applyI18n(document);
    buildSelector();
    // re-render dynamic UI immediately (functions defined by later scripts)
    try { if (typeof window.rerenderI18n === "function") window.rerenderI18n(); } catch (e) {}
    try { if (typeof window.initIcons === "function") window.initIcons(); } catch (e) {}
    try { if (typeof window.applyUnits === "function") window.applyUnits(); } catch (e) {}
    document.dispatchEvent(new CustomEvent("sharknet-lang", { detail: { lang: code } }));
  }

  // expose for the rest of the (classic-scope) app
  window.I18N = I18N;
  window.t = t;
  window.applyI18n = applyI18n;
  window.setLang = setLang;
  window.i18nLangs = LANGS;

  // first pass — the DOM is already parsed (this script sits at the end of body)
  applyI18n(document);
  buildSelector();
})();
