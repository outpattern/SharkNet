// SharkNet · devices: list rows + live network map
// ---------- device stats + list ----------
function renderDevices(devs) {
  const seen = new Set();
  let online = 0, lim = 0, cut = 0;
  devs.forEach((d) => {
    seen.add(d.ip);
    if (d.online) online++;
    if (d.mode === "limit") lim++;
    if (d.mode === "cut" || d.mode === "hardcut") cut++;   // Cut stat = cut + hard cut
    upsertRow(d);
  });
  Object.keys(rows).forEach((ip) => {
    if (!seen.has(ip)) { rows[ip].remove(); delete rows[ip]; }
  });
  $("#stOnline").textContent = online;
  $("#stLimit").textContent = lim;
  $("#stCut").textContent = cut;
  $("#empty").classList.toggle("hidden", devs.length > 0 || currentView === "map");
  lastDevices = devs;
  // multi-select: drop selections for devices that vanished, refresh the bulk bar
  [...SEL].forEach((ip) => { if (!seen.has(ip)) SEL.delete(ip); });
  updateBulkBar();
  if (currentView === "map") renderMap(devs);
}

// ---------- multi-device selection + bulk actions (Phase 7) ----------
function actionableIps() {
  return lastDevices.filter((d) => !d.is_self && !d.is_gateway && d.online).map((d) => d.ip);
}
function toggleSelect(ip, on) {
  if (on) SEL.add(ip); else SEL.delete(ip);
  const row = rows[ip];
  if (row) row.classList.toggle("selected", on);
  updateBulkBar();
}
function updateBulkBar() {
  const n = SEL.size;
  const bar = $("#bulkBar");
  if (bar) bar.classList.toggle("hidden", n === 0);
  const nb = $("#bulkN"); if (nb) nb.textContent = n;
  const all = actionableIps();
  const sa = $("#selAll");
  if (sa) {
    sa.checked = all.length > 0 && all.every((ip) => SEL.has(ip));
    sa.indeterminate = n > 0 && !sa.checked;
  }
}
function clearSelection() {
  SEL.forEach((ip) => {
    const r = rows[ip];
    if (r) { r.classList.remove("selected"); const cb = $(".selbox", r); if (cb) cb.checked = false; }
  });
  SEL.clear();
  updateBulkBar();
}
function selectAll(on) {
  if (on) actionableIps().forEach((ip) => SEL.add(ip)); else SEL.clear();
  Object.entries(rows).forEach(([ip, r]) => {
    const sel = SEL.has(ip);
    r.classList.toggle("selected", sel);
    const cb = $(".selbox", r); if (cb) cb.checked = sel;
  });
  updateBulkBar();
}
async function applyBulk(mode) {
  const ips = [...SEL];
  if (!ips.length) return;
  if (mode === "cut" || mode === "hardcut") {
    const hard = mode === "hardcut";
    const ok = await confirmDialog(
      hard ? t("confirm.hardcut_selected_title") : t("confirm.cut_selected_title"),
      hard ? t("confirm.hardcut_selected_msg", { n: ips.length }) : t("confirm.cut_selected_msg", { n: ips.length }),
      hard ? t("modes.hardcut") : t("confirm.cut"), "danger");
    if (!ok) return;
  }
  const body = { ips, mode, down_kbps: 0, up_kbps: 0 };
  if (mode === "limit") { body.down_kbps = 1024; body.up_kbps = 512; }   // same default as a row LIMIT
  let r;
  try { r = await api("/api/bulk/rule", body); }
  catch (e) { toast(t("toast.bulk_failed"), t("toast.request_error"), "danger", "warn"); return; }
  const applied = r.applied || 0, failed = r.failed || 0;
  if (r.ok) {
    toast("✓ " + t("toast.applied"), t("toast.applied_sub", { mode: t("modes." + mode), n: applied }));
  } else if (applied > 0) {
    const fails = (r.results || []).filter((x) => !x.ok).map((x) => x.ip).join(", ");
    toast(t("toast.partial"), t("toast.partial_sub", { ok: applied, failed: failed, fails: fails }), "warn", "warn");
  } else {
    toast(t("toast.not_applied"), r.error || t("toast.no_devices_updated"), "danger", "warn");
  }
  clearSelection();
}

// ---------- right-click context menu: Copy IP / MAC (Phase 7) ----------
function showRowMenu(e, ip) {
  e.preventDefault();
  const d = lastDevices.find((x) => x.ip === ip);
  if (!d) return;
  const menu = $("#ctxMenu");
  if (!menu) return;
  menu.innerHTML =
    `<button data-a="ip">${icon("copy")} ${esc(t("ctx.copy_ip"))}</button>` +
    `<button data-a="mac">${icon("copy")} ${esc(t("ctx.copy_mac"))}</button>`;
  menu.style.left = Math.min(e.clientX, window.innerWidth - 210) + "px";
  menu.style.top = Math.min(e.clientY, window.innerHeight - 90) + "px";
  menu.classList.remove("hidden");
  $$("#ctxMenu button").forEach((b) => b.onclick = () => {
    copyText(b.dataset.a === "ip" ? d.ip : d.mac, b.dataset.a === "ip" ? "IP" : "MAC");
    hideCtxMenu();
  });
}
function hideCtxMenu() { const m = $("#ctxMenu"); if (m) m.classList.add("hidden"); }
// language switch: row labels baked in by buildRow (ALLOW/LIMIT/CUT, copy/aria
// tooltips) and the map base (Internet/Router) are only written once, so tear both
// down and rebuild them in the new language from the last device snapshot.
document.addEventListener("sharknet-lang", () => {
  mapBaseDone = false; mapNodeEls = {}; mapLinkEls = {};
  Object.keys(rows).forEach((ip) => { rows[ip].remove(); delete rows[ip]; });
  renderDevices(lastDevices);   // rebuild list rows (and map, if showing) localized
});
document.addEventListener("click", hideCtxMenu);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideCtxMenu(); });
window.addEventListener("blur", hideCtxMenu);

// ---------- Live Network Map ----------
const SVGNS = "http://www.w3.org/2000/svg";
const MAP = { cx: 450, cy: 290, R: 300, Ry: 165 };
let mapNodeEls = {}, mapLinkEls = {}, mapBaseDone = false;

function svgEl(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function svgText(x, y, txt, cls, extra) {
  const t = svgEl("text", Object.assign({ x, y, class: cls }, extra || {}));
  t.textContent = txt;
  return t;
}

function renderMap(devices) {
  const svg = $("#mapSvg");
  if (!mapBaseDone) {
    svg.innerHTML = "";
    svg.appendChild(svgEl("g", { id: "mapLinks" }));
    svg.appendChild(svgEl("g", { id: "mapNodes" }));
    const nodeG = $("#mapNodes", svg), linkG = $("#mapLinks", svg);
    linkG.appendChild(svgEl("line", { class: "map-link", x1: MAP.cx, y1: 88, x2: MAP.cx, y2: MAP.cy - 36 }));
    const mapIcon = (name, cx, cy) => {
      const ig = svgEl("g", { class: "n-ico2" });
      ig.innerHTML = SVG[name];
      ig.setAttribute("transform", `translate(${cx - 12},${cy - 12})`);
      return ig;
    };
    const inet = svgEl("g", { class: "map-node map-inet" });
    inet.appendChild(svgEl("circle", { cx: MAP.cx, cy: 60, r: 24 }));
    inet.appendChild(mapIcon("globe", MAP.cx, 60));
    inet.appendChild(svgText(MAP.cx, 100, t("devices.map_internet"), "n-label"));
    nodeG.appendChild(inet);
    const rt = svgEl("g", { class: "map-node map-center" });
    rt.appendChild(svgEl("circle", { cx: MAP.cx, cy: MAP.cy, r: 36 }));
    rt.appendChild(mapIcon("router", MAP.cx, MAP.cy));
    rt.appendChild(svgText(MAP.cx, MAP.cy + 56, t("devices.map_router"), "n-label", { id: "mapRouterLabel" }));
    nodeG.appendChild(rt);
    mapBaseDone = true;
  }
  const nodeG = $("#mapNodes", svg), linkG = $("#mapLinks", svg);
  const gw = devices.find((d) => d.is_gateway);
  if (gw) $("#mapRouterLabel", svg).textContent = (gw.label || t("devices.map_router")).slice(0, 18);

  const others = devices.filter((d) => !d.is_gateway);
  const n = others.length, seen = new Set();
  others.forEach((d, i) => {
    seen.add(d.ip);
    const ang = -Math.PI / 2 + (i / Math.max(n, 1)) * 2 * Math.PI;
    const x = MAP.cx + MAP.R * Math.cos(ang);
    const y = MAP.cy + MAP.Ry * Math.sin(ang);
    const active = (d.down_bps + d.up_bps) > 1500;

    let link = mapLinkEls[d.ip];
    if (!link) { link = svgEl("line", {}); linkG.appendChild(link); mapLinkEls[d.ip] = link; }
    link.setAttribute("x1", MAP.cx); link.setAttribute("y1", MAP.cy);
    link.setAttribute("x2", x); link.setAttribute("y2", y);
    link.setAttribute("class", "map-link " + d.mode + (active ? " flow" : ""));
    link.style.strokeWidth = active ? Math.min(5, 1.5 + (d.down_bps + d.up_bps) / 1024 / 150) : 1.5;

    let g = mapNodeEls[d.ip];
    if (!g) {
      g = svgEl("g", {});
      g.appendChild(svgEl("circle", { r: 24 }));
      g.appendChild(svgEl("g", { class: "n-ico2" }));
      g.appendChild(svgEl("text", { class: "n-label" }));
      g.appendChild(svgEl("text", { class: "n-speed" }));
      g.addEventListener("click", () => selectDeviceFromMap(d.ip));
      nodeG.appendChild(g); mapNodeEls[d.ip] = g;
    }
    const cls = d.is_self ? "node-self" : "node-" + d.mode;
    g.setAttribute("class", "map-node " + cls + (d.online ? "" : " node-off"));
    const c = g.children[0], ico = g.children[1], lab = g.children[2], spd = g.children[3];
    c.setAttribute("cx", x); c.setAttribute("cy", y);
    ico.innerHTML = SVG[d.dtype] || SVG.unknown;
    ico.setAttribute("transform", `translate(${(x - 11).toFixed(1)},${(y - 11).toFixed(1)}) scale(0.92)`);
    lab.setAttribute("x", x); lab.setAttribute("y", y + 40); lab.textContent = (d.label || "").slice(0, 16);
    spd.setAttribute("x", x); spd.setAttribute("y", y + 54);
    spd.textContent = active ? "↓" + speedStr(d.down_bps) : "";
  });
  Object.keys(mapNodeEls).forEach((ip) => {
    if (!seen.has(ip)) {
      mapNodeEls[ip].remove(); delete mapNodeEls[ip];
      if (mapLinkEls[ip]) { mapLinkEls[ip].remove(); delete mapLinkEls[ip]; }
    }
  });
}

function selectDeviceFromMap(ip) {
  setView("list");
  const row = rows[ip];
  if (row) {
    row.scrollIntoView({ behavior: "smooth", block: "center" });
    row.style.transition = "box-shadow .3s";
    row.style.boxShadow = "var(--glow)";
    setTimeout(() => { row.style.boxShadow = ""; }, 1200);
  }
}

function setView(v) {
  currentView = v;
  const map = v === "map";
  $("#mapView").classList.toggle("hidden", !map);
  $("#deviceList").classList.toggle("hidden", map);
  $("#listHead").classList.toggle("hidden", map);
  $("#viewMap").classList.toggle("active", map);
  $("#viewList").classList.toggle("active", !map);
  $("#viewMap").setAttribute("aria-pressed", map ? "true" : "false");
  $("#viewList").setAttribute("aria-pressed", !map ? "true" : "false");
  $("#empty").classList.toggle("hidden", lastDevices.length > 0 || map);
  if (map) renderMap(lastDevices);
}

function upsertRow(d) {
  let row = rows[d.ip];
  if (!row) { row = buildRow(d); rows[d.ip] = row; $("#deviceList").appendChild(row); }
  updateRow(row, d);
}

function buildRow(d) {
  const row = document.createElement("div");
  row.className = "row";
  row.dataset.ip = d.ip;
  const actionable = !d.is_self && !d.is_gateway;
  row.innerHTML = `
    <div class="dev">
      ${actionable ? `<input type="checkbox" class="selbox" aria-label="${esc(t("devices.select_tip"))}" />` : '<span class="selspacer" aria-hidden="true"></span>'}
      <div class="ico"></div>
      <div class="meta">
        <div class="nm"><input class="nameIn" value="" aria-label="${esc(t("devices.name_aria"))}" ${actionable ? "" : "disabled"} /><span class="badges"></span></div>
        <div class="vdrow"><span class="vd"></span><span class="mstat" aria-live="polite"></span></div>
      </div>
    </div>
    <div class="net"><div class="ip-row"><span class="ip"></span><button class="ipcopy" title="${esc(t("copy.ip"))}" aria-label="${esc(t("copy.ip"))}" tabindex="-1">${icon("copy")}</button></div><div class="mac-row"><span class="mac"></span><button class="maccopy" title="${esc(t("copy.mac"))}" aria-label="${esc(t("copy.mac"))}" tabindex="-1">${icon("copy")}</button></div></div>
    <div class="spd">
      <div class="line"><span class="tag">↓</span><div class="bar"><div class="fill d"></div></div><span class="num numd"></span></div>
      <div class="line"><span class="tag">↑</span><div class="bar"><div class="fill u"></div></div><span class="num numu"></span></div>
    </div>
    <div class="ctrl ${actionable ? "" : "disabled"}">
      <div class="modes">
        <button class="mbtn" data-m="allow">${esc(t("modes.allow"))}</button>
        <button class="mbtn" data-m="limit">${esc(t("modes.limit"))}</button>
        <button class="mbtn" data-m="cut">${esc(t("modes.cut"))}</button>
        <button class="mbtn mbtn-hard" data-m="hardcut" title="${esc(t("hardcut.tip"))}" data-i18n-title="hardcut.tip">${esc(t("modes.hardcut"))}</button>
        ${actionable ? `<button class="monbtn" title="${esc(t("monitor.tip"))}" aria-pressed="false">${icon("eye")}<span class="mlbl">${esc(t("monitor.label"))}</span></button>` : ""}
      </div>
      <div class="limits">
        <div class="fld">↓<input class="limd" type="number" min="0" step="64" value="1024"/>KB/s</div>
        <div class="fld">↑<input class="limu" type="number" min="0" step="64" value="512"/>KB/s</div>
        <div class="presets">
          <button class="pbtn" data-k="256">256</button>
          <button class="pbtn" data-k="1024">1M</button>
          <button class="pbtn" data-k="5120">5M</button>
        </div>
      </div>
    </div>
    <div class="row-more"><button class="dtl" title="${esc(t("devices.details_tip"))}" aria-label="${esc(t("devices.details_tip"))}">${icon("gear")}</button></div>`;
  const openDetails = () => showDevice(d.ip, d.label, d.is_self || d.is_gateway);
  $(".dtl", row).addEventListener("click", openDetails);
  $(".ico", row).addEventListener("click", openDetails);   // click the device icon too
  // Copy IP / MAC: small affordances beside each value + right-click menu (every
  // row). stopPropagation so a copy click never selects the row, opens the modal,
  // or triggers block/cut (item 13). Copies ONLY that one value.
  const ipc = $(".ipcopy", row);
  if (ipc) ipc.addEventListener("click", (e) => { e.stopPropagation(); e.preventDefault(); copyText($(".ip", row).textContent, "IP"); });
  const mcp = $(".maccopy", row);
  if (mcp) mcp.addEventListener("click", (e) => { e.stopPropagation(); e.preventDefault(); copyText($(".mac", row).textContent, "MAC"); });
  row.addEventListener("contextmenu", (e) => showRowMenu(e, d.ip));
  if (actionable) {
    const cb = $(".selbox", row);
    if (cb) cb.addEventListener("change", () => toggleSelect(d.ip, cb.checked));
    const nameIn = $(".nameIn", row);
    nameIn.addEventListener("keydown", (e) => { if (e.key === "Enter") nameIn.blur(); });
    nameIn.addEventListener("blur", () => api("/api/rename", { ip: d.ip, name: nameIn.value }));
    $$(".mbtn", row).forEach((b) => b.addEventListener("click", () => applyMode(d.ip, b.dataset.m, row)));
    const mon = $(".monbtn", row);
    if (mon) mon.addEventListener("click", () => toggleMonitor(d.ip, row));
    $$(".pbtn", row).forEach((p) => p.addEventListener("click", () => {
      $(".limd", row).value = p.dataset.k; applyMode(d.ip, "limit", row);
    }));
    [".limd", ".limu"].forEach((s) => {
      const inp = $(s, row);
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") inp.blur(); });
      inp.addEventListener("blur", () => { if (currentMode(row) === "limit") applyMode(d.ip, "limit", row); });
    });
  }
  return row;
}

function updateRow(row, d) {
  row.className = "row " + d.mode + (d.is_self ? " self" : "") + (d.is_gateway ? " gateway" : "") + (SEL.has(d.ip) ? " selected" : "");
  const selbox = $(".selbox", row);
  if (selbox && document.activeElement !== selbox) selbox.checked = SEL.has(d.ip);
  $(".ico", row).innerHTML = icon(SVG[d.dtype] ? d.dtype : "unknown");
  const nameIn = $(".nameIn", row);
  const unnamed = !d.name && !d.hostname;
  if (document.activeElement !== nameIn) nameIn.value = d.label;
  nameIn.classList.toggle("unnamed", unnamed && !d.is_self && !d.is_gateway);
  nameIn.title = (unnamed && !d.is_self && !d.is_gateway)
    ? t("devices.name_hint")
    : (d.label || "");   // full name on hover when the input clips it
  $(".badges", row).innerHTML =
    (d.is_self ? `<span class="badge you">${esc(t("badge.you"))}</span>` : "") +
    (d.is_gateway ? `<span class="badge gw">${esc(t("badge.gateway"))}</span>` : "") +
    (!d.online ? `<span class="badge off">${esc(t("badge.offline"))}</span>` : "");
  $(".vd", row).textContent = d.vendor;
  $(".ip", row).textContent = d.ip;
  $(".mac", row).textContent = d.mac;
  $(".numd", row).textContent = speedStr(d.down_bps);
  $(".numu", row).textContent = speedStr(d.up_bps);
  $(".fill.d", row).style.width = barPct(d.down_bps) + "%";
  $(".fill.u", row).style.width = barPct(d.up_bps) + "%";
  $$(".mbtn", row).forEach((b) => b.classList.toggle("active", b.dataset.m === d.mode));
  // OBSERVATION state (P1) — reflect Monitor independently of enforcement mode.
  const monb = $(".monbtn", row);
  if (monb && monb.dataset.busy !== "1") {
    const on = !!d.monitor;
    monb.classList.toggle("on", on);
    monb.setAttribute("aria-pressed", on ? "true" : "false");
    const lbl = $(".mlbl", monb);
    if (lbl) lbl.textContent = on ? t("monitor.on") : t("monitor.label");
  }
  $(".limits", row).classList.toggle("show", d.mode === "limit");
  const limd = $(".limd", row), limu = $(".limu", row);
  if (document.activeElement !== limd && d.mode === "limit" && d.down_kbps) limd.value = d.down_kbps;
  if (document.activeElement !== limu && d.mode === "limit" && d.up_kbps) limu.value = d.up_kbps;
  paintStatus(row, d.mode, d.down_kbps || +limd.value || 0);   // Applying… / Limited / Cut pill
}

function currentMode(row) { const a = $(".mbtn.active", row); return a ? a.dataset.m : "allow"; }
// limit value shown in the SAME unit as live traffic (respects the KB/MB toggle);
// speedStr() is the single, centralized bandwidth formatter. kbps is KB/s.
function fmtLimit(kbps) { return speedStr((+kbps || 0) * 1024); }
// paint the per-row enforcement status pill (transient "Applying…" then settled)
function paintStatus(row, mode, downKbps) {
  const el = $(".mstat", row);
  if (!el) return;
  const applying = +(row.dataset.applyingUntil || 0) > Date.now();
  if (mode === "limit") {
    el.className = "mstat limit" + (applying ? " applying" : "");
    el.textContent = applying ? t("mstat.engaging", { rate: fmtLimit(downKbps) }) : t("mstat.limited");
  } else if (mode === "cut") {
    el.className = "mstat cut" + (applying ? " applying" : "");
    el.textContent = applying ? t("mstat.cutting") : t("mstat.cut");
  } else if (mode === "hardcut") {
    el.className = "mstat hardcut" + (applying ? " applying" : "");
    el.textContent = applying ? t("mstat.cutting") : t("mstat.hardcut");
  } else {
    el.className = "mstat"; el.textContent = "";
  }
}
function applyMode(ip, mode, row) {
  const ctrl = $(".ctrl", row);
  if (ctrl.dataset.busy === "1") return;          // in-flight -> ignore rapid re-click
  let down = 0, up = 0;
  if (mode === "limit") {
    down = parseInt($(".limd", row).value) || 0;
    up = parseInt($(".limu", row).value) || 0;
    if (!down && !up) down = 1024;
  }
  // show a ~6s "Engaging…" state — the MITM/ARP takes a few seconds to take hold
  row.dataset.applyingUntil = mode === "allow" ? "0" : String(Date.now() + 6000);
  paintStatus(row, mode, down);
  $$(".mbtn", row).forEach((b) => b.classList.toggle("active", b.dataset.m === mode));
  $(".limits", row).classList.toggle("show", mode === "limit");
  ctrl.dataset.busy = "1"; ctrl.classList.add("busy");
  api("/api/rule", { ip, mode, down_kbps: down, up_kbps: up })
    .finally(() => setTimeout(() => { ctrl.dataset.busy = ""; ctrl.classList.remove("busy"); }, 250));
}

// ---------- OBSERVATION: per-device Monitor toggle (P1) ----------
// Toggles ONLY observation intent (/api/monitor). It NEVER touches enforcement:
// no ALLOW/LIMIT/CUT/block change. Monitor ⇒ intercept + observe, forward untouched.
async function toggleMonitor(ip, row) {
  const btn = $(".monbtn", row);
  if (!btn || btn.dataset.busy === "1") return;
  const turnOn = !btn.classList.contains("on");
  const lbl = $(".mlbl", btn);
  const paint = (on) => {
    btn.classList.toggle("on", on);
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    if (lbl) lbl.textContent = on ? t("monitor.on") : t("monitor.label");
  };
  btn.dataset.busy = "1"; btn.disabled = true;   // busy blocks updateRow clobber
  paint(turnOn);                                  // optimistic — WS state confirms/corrects
  let r = null;
  try { r = await api("/api/monitor", { ip, on: turnOn }); } catch (e) {}
  btn.dataset.busy = ""; btn.disabled = false;
  if (r && r.ok) {
    toast("✓ " + (turnOn ? t("toast.monitor_on") : t("toast.monitor_off")), (r.device && r.device.label) || ip);
  } else {
    paint(!turnOn);                               // revert on failure
    toast(t("toast.monitor_failed"), (r && r.error) || t("toast.request_error"), "danger", "warn");
  }
}

// ---------- events / toasts ----------
function handleEvent(ev) {
  // NOTE: "new_device" deliberately does NOT toast here any more. The backend
  // NotificationManager already turns that event into a notification and the
  // presentation router decides whether it is drawn in-app or on the desktop —
  // toasting here too was the duplicate (in-app toast + Windows balloon).
  if (ev.kind === "mac_changed" || ev.kind === "mac_change_failed") {
    onMacResult(ev);   // SharkMAC coordinator result (defined in e-modals.js)
  }
}
// App feedback (saved / copied / failed). Routed through the SAME component the
// event notifications use, so everything SharkNet shows looks like one system.
function toast(title, body, kind, iconName) {
  if (window.SNNotify) {
    window.SNNotify.show({ title: title, body: body, kind: kind, icon: iconName });
    return;
  }
  // component missing (should not happen) — fail quietly rather than throw
  try { console.warn("SNNotify unavailable:", title); } catch (e) {}
}

// Event notifications chosen by the backend router for IN-APP display. The
// router sends each notice to exactly one renderer, so nothing here can double
// up with a desktop/OS notification.
function renderServerToasts(list) {
  (list || []).forEach((n) => {
    if (window.SNNotify) window.SNNotify.show({
      title: n.title, body: n.body, category: n.category,
    });
  });
}

// ---------- modal + intelligence features ----------
