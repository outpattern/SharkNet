// SharkNet · theme + units + event wiring + init (loaded last)
// ---------- theme + units ----------
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  // the header theme button was removed (V3.1); guard so applyTheme() — still the
  // single authoritative path, now driven from Settings → Appearance — never throws
  const tb = $("#themeBtn");
  if (tb) tb.innerHTML = icon(t === "light" ? "sun" : "moon");
  try { localStorage.setItem("sharknet-theme", t); } catch (e) {}
  syncTitlebar(t);
}
function syncTitlebar(t) {
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.set_theme)
      window.pywebview.api.set_theme(t !== "light");
  } catch (e) {}
}
window.addEventListener("pywebviewready", () =>
  syncTitlebar(document.documentElement.getAttribute("data-theme")));
function initIcons() {
  $("#speedBtn").innerHTML = icon("zap");
  $("#aboutBtn").innerHTML = icon("heart");
  const sh = document.querySelector(".defender .shield"); if (sh) sh.innerHTML = icon("shield");
  $("#viewList").innerHTML = icon("list") + t("devices.list");
  $("#viewMap").innerHTML = icon("grid") + t("devices.map");
}
initIcons();
function initTheme() {
  let t = "dark"; try { t = localStorage.getItem("sharknet-theme") || "dark"; } catch (e) {}
  applyTheme(t);
}
// header theme toggle removed (V3.1) — theme now lives in Settings → Appearance.
// Guard so a future header without the button (or with it) both work.
const _themeBtn = $("#themeBtn");
if (_themeBtn) _themeBtn.addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  applyTheme(cur === "light" ? "dark" : "light");
});
initTheme();

function applyUnits() {
  $$("#unitToggle button").forEach((b) => {
    const on = b.dataset.u === UNITS;
    b.classList.toggle("on", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
  });
}
$$("#unitToggle button").forEach((b) => b.addEventListener("click", () => {
  UNITS = b.dataset.u;
  try { localStorage.setItem("sharknet-units", UNITS); } catch (e) {}
  applyUnits();
  if (lastHealth) renderIntel(lastHealth, lastPolicy);  // update tiles immediately
  if (lastDevices.length) renderDevices(lastDevices);   // update device speeds
}));
applyUnits();

// ---------- wire up ----------
$("#ifaceSelect").addEventListener("change", () => { updateIfaceMeta(); selectInterface(); });
$("#viewList").addEventListener("click", () => setView("list"));
$("#viewMap").addEventListener("click", () => setView("map"));
$("#startBtn").addEventListener("click", (e) => guard(e.currentTarget, () => api("/api/control/start")));
$("#scanBtn").addEventListener("click", (e) => guard(e.currentTarget, () => api("/api/scan")));
$("#stopAllBtn").addEventListener("click", (e) => guard(e.currentTarget, () => api("/api/control/stop")));
$("#cutOthersBtn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;   // capture BEFORE await — e.currentTarget is null after the dialog awaits
  const ok = await confirmDialog(t("confirm.cut_others_title"),
    t("confirm.cut_others_msg"),
    t("control.cut_others"), "danger");
  if (!ok) return;
  guard(btn, () => api("/api/cut_all_except_me").then((r) => {
    if (r && r.ok) toast("✓ " + t("toast.others_cut"), t("toast.others_cut_sub"));
    else toast("✕ " + t("toast.cut_others_failed"), (r && r.error) || "", "danger");
    return r;
  }));
});
// E: Uncut / Restore others — set every other device back to Allow (reuses /api/stop_all)
$("#uncutOthersBtn").addEventListener("click", (e) =>
  guard(e.currentTarget, () => api("/api/stop_all").then((r) => {
    if (r && r.ok) toast("✓ " + t("toast.others_restored"), t("toast.others_restored_sub"));
    else toast("✕ " + t("toast.restore_failed"), (r && r.error) || "", "danger");
    return r;
  })));

// ---------- Phase 7: network rules + bulk selection ----------
$("#netRulesBtn").addEventListener("click", openNetworkRules);
$("#netClear").addEventListener("click", (e) =>
  guard(e.currentTarget, () => api("/api/network/block", { services: [], domains: [] })
    .then((r) => { if (r && r.ok) toast("✓ " + t("toast.net_cleared"), ""); return r; })));
$("#selAll").addEventListener("change", (e) => selectAll(e.target.checked));
$("#bulkClear").addEventListener("click", clearSelection);
$$("#bulkBar .bbtn").forEach((b) => b.addEventListener("click", () => applyBulk(b.dataset.m)));

loadServices();
loadInterfaces();
connectWS();
