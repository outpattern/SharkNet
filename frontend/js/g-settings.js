// SharkNet · V3.1 Settings — centered desktop-style popup (left nav + right pane)
// -----------------------------------------------------------------------------
// ONE source of truth per setting — this module never keeps its own copy:
//   * tray + notification policy + backend locale -> POST /api/settings, which
//     routes through server.apply_settings_patch(), the same single write path
//     the tray's Notifications toggle uses.
//   * theme    -> applyTheme()  (f-theme.js)  — the exact function the header
//                 theme button calls, so header and popup cannot drift.
//   * language -> setLang()     (i18n.js)     — likewise for the header picker.
//   * units    -> the header segmented control stays the only control.
// The popup re-reads live state on every open and re-renders on language change,
// so header-side changes are always reflected and vice versa.
//
// Presentation only: nothing here touches ALLOW/LIMIT/CUT/HARD CUT, the policy
// classifier, interception or monitoring.
// -----------------------------------------------------------------------------
(function () {
  "use strict";

  // Notification categories, grouped for the UI. Every id below exists in
  // backend/engine/notifications.py CATEGORIES — no invented event types.
  var GROUPS = [
    { title: "settings.grp_device_events", cats: ["new_device", "device_offline", "device_online"] },
    { title: "settings.grp_network_control", cats: ["cut", "hardcut", "limit", "domain_block", "service_block"] },
    { title: "settings.grp_monitoring", cats: ["monitor_started", "monitor_stopped"] },
    { title: "settings.grp_security", cats: ["security", "speedtest"] },
  ];
  var ALL_CATS = GROUPS.reduce(function (a, g) { return a.concat(g.cats); }, []);

  var SECTIONS = [
    { id: "general", label: "settings.general", icon: "gear" },
    { id: "notifications", label: "settings.notifications", icon: "info" },
    { id: "appearance", label: "settings.appearance", icon: "moon" },
    { id: "language", label: "settings.language", icon: "globe" },
    { id: "runtime", label: "settings.runtime", icon: "chart" },
  ];

  var SETTINGS = null;    // last server settings (re-fetched on open)
  var RUNTIME = null;     // {tray, windowed, background} — launcher facts
  var active = "general";

  // ---------- server I/O ----------
  function getJSON(p) { return apiGet(p).then(function (r) { return r.json(); }); }
  function loadSettings() {
    return getJSON("/api/settings").then(function (r) {
      if (r && r.settings) SETTINGS = r.settings;
      return SETTINGS;
    });
  }
  function loadRuntime() {
    return getJSON("/api/runtime").then(function (r) {
      if (r && r.ok) RUNTIME = r;
      return RUNTIME;
    });
  }
  function patch(p) {
    return api("/api/settings", p).then(function (r) {
      if (r && r.settings) SETTINGS = r.settings;
      return r;
    });
  }

  // ---------- header background pill ----------
  // Driven by REAL runtime capability (tray-gated), never by a stored preference.
  function renderStatus() {
    var pill = document.getElementById("bgStatus");
    if (!pill || !RUNTIME) return;
    var on = !!RUNTIME.background;
    pill.classList.remove("hidden");
    pill.classList.toggle("on", on);
    var txt = pill.querySelector(".bg-txt");
    if (txt) {
      txt.textContent = t(on ? "status.background_on" : "status.background_off");
      txt.setAttribute("data-i18n", on ? "status.background_on" : "status.background_off");
    }
    var tip = !RUNTIME.tray ? t("settings.tray_unavailable")
      : t(on ? "status.background_tip_on" : "status.background_tip_off");
    pill.setAttribute("title", tip);
    pill.setAttribute("aria-label", tip);
  }

  // ---------- markup helpers ----------
  function opt(id, on, label, desc, disabled) {
    return '<label class="opt' + (disabled ? " opt-off" : "") + '">' +
      '<span class="opt-txt"><span class="opt-l">' + esc(label) + "</span>" +
      (desc ? '<span class="opt-d">' + esc(desc) + "</span>" : "") + "</span>" +
      '<input type="checkbox" class="sw" id="' + esc(id) + '"' +
      (on ? " checked" : "") + (disabled ? " disabled" : "") + " /></label>";
  }
  function grp(title, inner) {
    return '<div class="sx-grp"><h4 class="sx-grp-h">' + esc(title) + "</h4>" + inner + "</div>";
  }
  function statusRow(label, value, ok) {
    return '<div class="rt-row"><span class="rt-l">' + esc(label) + "</span>" +
      '<span class="rt-v' + (ok ? " on" : "") + '">' +
      '<span class="rt-dot" aria-hidden="true"></span>' + esc(value) + "</span></div>";
  }

  // ---------- sections ----------
  function paneGeneral() {
    var tray = (SETTINGS && SETTINGS.tray) || {};
    var noTray = !(RUNTIME && RUNTIME.tray);
    var restore = !!(SETTINGS && SETTINGS.restore_rules);
    return (noTray ? '<div class="set-warn">' + icon("warn") + " " +
                     esc(t("settings.tray_unavailable")) + "</div>" : "") +
      grp(t("settings.grp_startup"),
          opt("setAutostart", tray.start_with_windows, t("settings.start_with_windows"),
              t("settings.start_with_windows_desc"), false) +
          opt("setRestoreRules", restore, t("settings.restore_rules"),
              t("settings.restore_rules_desc"), false) +
          // only warn about the destructive consequence WHEN it is enabled
          (restore ? '<div class="set-warn">' + icon("warn") + " " +
                     esc(t("settings.restore_rules_warn")) + "</div>" : "")) +
      grp(t("settings.grp_background"),
          opt("setKeepRunning", tray.keep_running_on_close, t("settings.keep_running"),
              t("settings.keep_running_desc"), noTray) +
          opt("setMinTray", tray.minimize_to_tray, t("settings.minimize_to_tray"),
              t("settings.minimize_to_tray_desc"), noTray));
  }

  function paneNotifications() {
    var n = (SETTINGS && SETTINGS.notifications) || {};
    var off = !n.enabled;
    // master first; the per-category switches grey out but KEEP their saved values
    var head = opt("setNotif", n.enabled, t("settings.notif_enabled"), "", false) +
               opt("setSound", n.sound, t("settings.notif_sound"), "", off);
    var body = GROUPS.map(function (g) {
      return grp(t(g.title), g.cats.map(function (c) {
        return opt("setCat_" + c, n[c], t("settings.cat." + c), "", off);
      }).join(""));
    }).join("");
    return '<div class="set-note">' + icon("info") + " " +
           esc(t("settings.notif_note")) + "</div>" + head + body;
  }

  function paneAppearance() {
    var theme = document.documentElement.getAttribute("data-theme") || "dark";
    return grp(t("settings.theme"),
      '<div class="seg set-seg" id="setTheme" role="group" aria-label="' +
        esc(t("settings.theme")) + '">' +
        '<button data-th="dark"' + (theme !== "light" ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"') +
          ">" + esc(t("settings.theme_dark")) + "</button>" +
        '<button data-th="light"' + (theme === "light" ? ' class="on" aria-pressed="true"' : ' aria-pressed="false"') +
          ">" + esc(t("settings.theme_light")) + "</button>" +
      "</div>");
  }

  function paneLanguage() {
    var lang = (window.I18N && I18N.lang) || "en";
    return '<div class="lang-list">' + (window.i18nLangs || []).map(function (l) {
      var on = l.code === lang;
      return '<button class="lang-row' + (on ? " on" : "") + '" data-l="' + esc(l.code) + '"' +
        ' role="radio" aria-checked="' + (on ? "true" : "false") + '">' +
        '<span class="lr-check" aria-hidden="true">' + (on ? "✓" : "") + "</span>" +
        '<span' + (l.dir === "rtl" ? ' dir="rtl"' : "") + ">" + esc(l.name) + "</span></button>";
    }).join("") + "</div>";
  }

  function paneRuntime() {
    var trayOk = !!(RUNTIME && RUNTIME.tray);
    var bgOk = !!(RUNTIME && RUNTIME.background);
    // application mode reports the REAL window state the launcher publishes
    var windowed = !RUNTIME || RUNTIME.window_visible !== false;
    return '<div class="set-note">' + icon("info") + " " +
             esc(t("settings.runtime_note")) + "</div>" +
      '<div class="rt-box">' +
        statusRow(t("settings.tray_status"),
                  trayOk ? t("settings.tray_active") : t("settings.tray_off"), trayOk) +
        statusRow(t("settings.background_mode"),
                  bgOk ? t("settings.background_active") : t("settings.background_off"), bgOk) +
        statusRow(t("settings.app_mode"),
                  windowed ? t("settings.app_windowed") : t("settings.app_background"), windowed) +
      "</div>" +
      diagnosticsSection();
  }

  // ---------- Diagnostics & Performance (read-only) ----------
  var DIAG = null;            // last /api/diagnostics snapshot
  var diagTimer = null;       // 1 Hz poll, only while Runtime pane is open

  function dgRow(id, label, unit) {
    return '<div class="dg-row"><span class="dg-l">' + esc(label) + "</span>" +
      '<span class="dg-v" id="' + id + '">—</span>' +
      (unit ? '<span class="dg-u">' + esc(unit) + "</span>" : "") + "</div>";
  }

  function diagnosticsSection() {
    return '<div class="dg-sec"><h4 class="sx-grp-h">' + esc(t("settings.diagnostics")) + "</h4>" +
      '<div class="rt-box dg-box">' +
        dgRow("dgCpu", t("settings.diag_cpu"), "%") +
        dgRow("dgRam", t("settings.diag_ram"), "MB") +
        dgRow("dgEngine", t("settings.diag_engine"), "") +
        dgRow("dgWeb", t("settings.diag_webview"), "MB") +
        dgRow("dgMon", t("settings.diag_monitored"), "") +
        dgRow("dgEnf", t("settings.diag_enforced"), "") +
        dgRow("dgPkt", t("settings.diag_packet_rate"), "pkt/s") +
        dgRow("dgThr", t("settings.diag_throughput"), "Mbps") +
        '<div class="dg-row dg-status"><span class="dg-l">' + esc(t("settings.diag_perf_status")) +
          '</span><span class="dg-v" id="dgStatus">—</span></div>' +
      "</div>" +
      '<div class="dg-actions">' +
        '<button class="btn" id="dgRun">' + esc(t("settings.diag_run")) + "</button>" +
        '<button class="btn" id="dgCopy">' + esc(t("settings.diag_copy")) + "</button>" +
      "</div>" +
      '<div id="dgResult" class="dg-result hidden"></div>' +
      "</div>";
  }

  // localized value for a metric that may be the literal "Unavailable"
  function dgVal(v) {
    if (v === "Unavailable" || v == null) return t("settings.diag_unavailable");
    return v;
  }
  function perfLabel(status) {
    var m = { Low: "settings.perf_low", Normal: "settings.perf_normal",
              High: "settings.perf_high" };
    return m[status] ? t(m[status]) : t("settings.diag_unavailable");
  }
  function perfClass(status) {
    return status === "High" ? "bad" : status === "Low" ? "ok" :
           status === "Normal" ? "warn2" : "";
  }

  function renderDiag() {
    if (!DIAG) return;
    var set = function (id, v) { var e = document.getElementById(id); if (e) e.textContent = v; };
    var num = function (v) { return (typeof v === "number") ? v.toLocaleString() : dgVal(v); };
    set("dgCpu", num(DIAG.cpu_percent));
    set("dgRam", num(DIAG.ram_mb));
    // engine status is one of Running/Starting/Stopped/Unavailable — localize
    var eng = { Running: "settings.eng_running", Starting: "settings.eng_starting",
                Stopped: "settings.eng_stopped" };
    set("dgEngine", eng[DIAG.engine] ? t(eng[DIAG.engine]) : dgVal(DIAG.engine));
    set("dgWeb", num(DIAG.webview_mb));
    set("dgMon", num(DIAG.monitored_devices));
    set("dgEnf", num(DIAG.enforced_devices));
    set("dgPkt", num(DIAG.packet_rate));
    set("dgThr", num(DIAG.throughput_mbps));
    var st = document.getElementById("dgStatus");
    if (st) {
      st.textContent = perfLabel(DIAG.performance_status);
      st.className = "dg-v dg-badge " + perfClass(DIAG.performance_status);
    }
  }

  function pollDiagOnce() {
    return getJSON("/api/diagnostics").then(function (r) {
      if (r && r.ok) { DIAG = r.diagnostics; renderDiag(); }
    }).catch(function () {});
  }
  function startDiagPolling() {
    stopDiagPolling();
    pollDiagOnce();
    diagTimer = setInterval(function () {
      // stop cheaply if the popup closed or the pane switched away from Runtime
      if (!isOpen() || active !== "runtime") { stopDiagPolling(); return; }
      pollDiagOnce();
    }, 1000);
  }
  function stopDiagPolling() {
    if (diagTimer) { clearInterval(diagTimer); diagTimer = null; }
  }

  function runPerfCheck() {
    var btn = document.getElementById("dgRun");
    var res = document.getElementById("dgResult");
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    var was = btn.textContent;
    btn.textContent = t("settings.diag_running");
    api("/api/diagnostics/perfcheck").then(function (r) {
      if (!r || !r.ok) throw new Error("perfcheck failed");
      var d = r.result;
      var row = function (label, v, unit) {
        return '<div class="dg-row"><span class="dg-l">' + esc(label) + '</span><span class="dg-v">' +
          esc(String(dgVal(v))) + (unit && v !== "Unavailable" ? " " + unit : "") + "</span></div>";
      };
      if (res) {
        res.classList.remove("hidden");
        res.innerHTML =
          '<div class="dg-row dg-status"><span class="dg-l">' + esc(t("settings.diag_perf_status")) +
            '</span><span class="dg-v dg-badge ' + perfClass(d.performance_status) + '">' +
            esc(perfLabel(d.performance_status)) + "</span></div>" +
          row(t("settings.diag_avg_cpu"), d.cpu_avg, "%") +
          row(t("settings.diag_peak_cpu"), d.cpu_peak, "%") +
          row(t("settings.diag_ram"), d.ram_mb, "MB") +
          row(t("settings.diag_packet_rate"), d.packet_rate_avg, "pkt/s") +
          row(t("settings.diag_throughput"), d.throughput_avg_mbps, "Mbps") +
          row(t("settings.diag_enforced"), d.enforced_devices, "");
      }
    }).catch(function () {
      toast(t("settings.diag_failed"), "", "danger", "warn");
    }).then(function () {
      btn.disabled = false; btn.textContent = was;
    });
  }

  // Copy a concise, NON-SENSITIVE support summary. Never includes tokens,
  // credentials, device lists, or domain history.
  function copyDiagnostics() {
    var d = DIAG || {};
    var lines = [
      "SharkNet " + (d.version || (SETTINGS && SETTINGS.version) || ""),
      "Engine: " + (d.engine || "?"),
      "CPU: " + dgVal(d.cpu_percent) + (typeof d.cpu_percent === "number" ? "%" : ""),
      "RAM: " + dgVal(d.ram_mb) + (typeof d.ram_mb === "number" ? " MB" : ""),
      "UI/WebView: " + dgVal(d.webview_mb) + (typeof d.webview_mb === "number" ? " MB" : ""),
      "Monitored devices: " + dgVal(d.monitored_devices),
      "Enforced devices: " + dgVal(d.enforced_devices),
      "Packet rate: " + dgVal(d.packet_rate) + (typeof d.packet_rate === "number" ? " pkt/s" : ""),
      "Intercepted throughput: " + dgVal(d.throughput_mbps) + (typeof d.throughput_mbps === "number" ? " Mbps" : ""),
      "Performance status: " + (d.performance_status || "?"),
    ];
    copyText(lines.join("\n"), t("settings.diagnostics"));
  }

  var PANES = {
    general: paneGeneral, notifications: paneNotifications,
    appearance: paneAppearance, language: paneLanguage, runtime: paneRuntime,
  };

  // ---------- wiring ----------
  function bind(id, build) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("change", function () {
      patch(build(el.checked)).then(function (r) {
        if (!r || !r.ok) throw new Error("save failed");
        return loadRuntime();
      }).then(function () {
        renderStatus();
        renderPane();
        toast("✓ " + t("settings.saved"), "", "", "info");
      }).catch(function () {
        toast(t("settings.save_failed"), "", "danger", "warn");
        loadSettings().then(renderPane);
      });
    });
  }

  function wirePane() {
    bind("setAutostart", function (v) { return { tray: { start_with_windows: v } }; });
    // top-level setting (not under tray) — reuses the exact same write path
    bind("setRestoreRules", function (v) { return { restore_rules: v }; });
    bind("setKeepRunning", function (v) { return { tray: { keep_running_on_close: v } }; });
    bind("setMinTray", function (v) { return { tray: { minimize_to_tray: v } }; });
    bind("setNotif", function (v) { return { notifications: { enabled: v } }; });
    bind("setSound", function (v) { return { notifications: { sound: v } }; });
    ALL_CATS.forEach(function (c) {
      bind("setCat_" + c, function (v) {
        var p = { notifications: {} };
        p.notifications[c] = v;
        return p;
      });
    });
    var seg = document.getElementById("setTheme");
    if (seg) seg.querySelectorAll("button").forEach(function (b) {
      b.addEventListener("click", function () {
        if (typeof window.applyTheme === "function") window.applyTheme(b.dataset.th);
        renderPane();
      });
    });
    document.querySelectorAll("#settingsPopup .lang-row").forEach(function (b) {
      b.addEventListener("click", function () {
        if (typeof window.setLang === "function") window.setLang(b.getAttribute("data-l"));
      });
    });
    // Diagnostics (Runtime pane only): wire the buttons + start the 1 Hz poll.
    var run = document.getElementById("dgRun");
    if (run) run.addEventListener("click", runPerfCheck);
    var copy = document.getElementById("dgCopy");
    if (copy) copy.addEventListener("click", copyDiagnostics);
    if (active === "runtime") { renderDiag(); startDiagPolling(); }
    else stopDiagPolling();
  }

  function renderPane() {
    stopDiagPolling();     // switching/redrawing panes clears any prior poll
    var pane = document.getElementById("sxPane");
    if (!pane || !isOpen()) return;
    pane.innerHTML = '<h3 class="sx-pane-h">' + esc(t(sectionLabel(active))) + "</h3>" +
                     '<div class="sx-pane-body">' + (PANES[active] || paneGeneral)() + "</div>";
    pane.scrollTop = 0;
    wirePane();
  }

  function sectionLabel(id) {
    for (var i = 0; i < SECTIONS.length; i++) if (SECTIONS[i].id === id) return SECTIONS[i].label;
    return "settings.general";
  }

  function renderNav() {
    var nav = document.getElementById("sxNav");
    if (!nav) return;
    nav.innerHTML = SECTIONS.map(function (s) {
      var on = s.id === active;
      return '<button class="sx-nav-item' + (on ? " on" : "") + '" data-sec="' + esc(s.id) + '"' +
        ' role="tab" aria-selected="' + (on ? "true" : "false") + '">' +
        icon(s.icon, "sx-nav-ic") + "<span>" + esc(t(s.label)) + "</span></button>";
    }).join("");
    nav.querySelectorAll(".sx-nav-item").forEach(function (b) {
      b.addEventListener("click", function () {
        active = b.getAttribute("data-sec");
        renderNav();
        renderPane();
      });
    });
  }

  // ---------- popup shell ----------
  function ensureShell() {
    if (document.getElementById("settingsPopup")) return;
    var scrim = document.createElement("div");
    scrim.id = "settingsScrim";
    scrim.className = "sx-scrim hidden";
    var box = document.createElement("div");
    box.id = "settingsPopup";
    box.className = "sx hidden";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-labelledby", "sxTitle");
    box.innerHTML =
      '<header class="sx-head"><span id="sxTitle">' + esc(t("settings.title")) + "</span>" +
        '<button id="sxX" class="a-x" aria-label="' + esc(t("settings.close")) + '">✕</button></header>' +
      '<div class="sx-body"><nav class="sx-nav" id="sxNav" role="tablist"></nav>' +
      '<div class="sx-pane" id="sxPane" role="tabpanel"></div></div>';
    document.body.appendChild(scrim);
    document.body.appendChild(box);
    scrim.addEventListener("click", close);
    document.getElementById("sxX").addEventListener("click", close);
  }

  function isOpen() {
    var b = document.getElementById("settingsPopup");
    return !!b && !b.classList.contains("hidden");
  }

  function open() {
    ensureShell();
    Promise.all([loadSettings(), loadRuntime()]).then(function () {
      var box = document.getElementById("settingsPopup");
      var scrim = document.getElementById("settingsScrim");
      document.getElementById("sxTitle").textContent = t("settings.title");
      renderNav();
      scrim.classList.remove("hidden");
      box.classList.remove("hidden");
      renderPane();
      renderStatus();
      // forced reflow rather than rAF — see h-notify.js: rAF does not fire when
      // the window is not painting, which would leave the popup invisible.
      void box.offsetWidth;
      scrim.classList.add("show");
      box.classList.add("show");
      var gear = document.getElementById("settingsBtn");
      if (gear) gear.setAttribute("aria-expanded", "true");
    }).catch(function () { toast(t("common.error"), "", "danger", "warn"); });
  }

  function close() {
    var box = document.getElementById("settingsPopup");
    var scrim = document.getElementById("settingsScrim");
    if (!box || box.classList.contains("hidden")) return;
    stopDiagPolling();     // never poll diagnostics while the popup is closed
    box.classList.remove("show");
    scrim.classList.remove("show");
    var gear = document.getElementById("settingsBtn");
    if (gear) gear.setAttribute("aria-expanded", "false");
    setTimeout(function () {
      box.classList.add("hidden");
      scrim.classList.add("hidden");
    }, 180);                     // matches the CSS transition
  }

  function toggle() { isOpen() ? close() : open(); }

  // ---------- boot ----------
  var btn = document.getElementById("settingsBtn");
  if (btn) {
    btn.setAttribute("aria-expanded", "false");
    btn.addEventListener("click", toggle);
  }
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape" || !isOpen()) return;
    var m = document.getElementById("modal");
    if (m && !m.classList.contains("hidden")) return;   // a modal on top wins
    close();
  });

  // keep the BACKEND locale aligned with the UI language, so notifications raised
  // while the window is closed are in the language the user picked
  function syncLocale(code) {
    if (!code || !SETTINGS || SETTINGS.locale === code) return;
    patch({ locale: code }).catch(function () {});
  }
  document.addEventListener("sharknet-lang", function (e) {
    syncLocale(e && e.detail && e.detail.lang);
    var head = document.getElementById("sxTitle");
    if (head) head.textContent = t("settings.title");
    renderNav();
    renderPane();
    renderStatus();
  });

  loadSettings()
    .then(function () { syncLocale((window.I18N && I18N.lang) || "en"); })
    .then(loadRuntime)
    .then(renderStatus)
    .catch(function () {});

  window.addEventListener("focus", function () {
    loadRuntime().then(renderStatus).catch(function () {});
  });
})();
