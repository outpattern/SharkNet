// SharkNet · modals: device tabs (info/domains/history), speed gauge, about
let onModalClose = null;   // optional cleanup (timers/aborts) run when modal closes
let histTimer = null;      // live traffic-history redraw timer (device modal)
let dTok = 0;              // device-modal render token: an async tab render only
                          // writes if it is still the active tab (no clobbering
                          // when the user switches tabs before a fetch returns)
// friendly, localized label for the hostname source. DHCP/mDNS/NetBIOS are
// technical acronyms (kept); rdns/saved/user are words → localized.
function nameSrcLabel(src) {
  const tech = { dhcp: "DHCP", mdns: "mDNS", netbios: "NetBIOS" };
  if (tech[src]) return tech[src];
  const k = { rdns: "info.src_rdns", saved: "info.src_saved", user: "info.src_user" }[src];
  return k ? t(k) : (src || "");
}
function openModal(title, html) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = html;
  $("#modal").classList.remove("hidden");
}
function closeModal() {
  $("#modal").classList.add("hidden");
  if (histTimer) { clearInterval(histTimer); histTimer = null; }
  if (typeof smac !== "undefined") smac.open = false;
  if (onModalClose) { try { onModalClose(); } catch (e) {} onModalClose = null; }
}
$("#modalX").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });

// themed confirm dialog (replaces the native Windows confirm() popup). Resolves
// true on confirm, false on cancel / X / Escape / backdrop. Uses the existing modal.
function confirmDialog(title, message, confirmLabel, kind) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; onModalClose = null; resolve(v); };
    openModal(title,
      `<div class="confirm-box"><p class="confirm-msg">${esc(message)}</p>` +
      `<div class="confirm-actions"><button class="btn" id="cfCancel">${esc(t("confirm.cancel"))}</button>` +
      `<button class="btn ${kind === "danger" ? "btn-danger" : "btn-primary"}" id="cfOk">${esc(confirmLabel || t("confirm.confirm"))}</button></div></div>`);
    onModalClose = () => finish(false);              // X / Escape / backdrop = cancel
    $("#cfCancel").onclick = () => { finish(false); closeModal(); };
    $("#cfOk").onclick = () => { finish(true); closeModal(); };
  });
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#modal").classList.contains("hidden")) closeModal();
});

function showDevice(ip, label, restricted) {
  // items 15/16: SERVICES / DOMAINS / VISITED SITES / HISTORY are distinct tabs.
  // Services + Domains are explicit BLOCK controls; Visited sites is observation
  // only (read-only) so viewing a site NEVER blocks anything.
  openModal(label,
    `<div class="dtabs">` +
    `<button data-t="info" class="on">${icon("info")} ${esc(t("tabs.info"))}</button>` +
    `<button data-t="svc">${icon("ban")} ${esc(t("tabs.services"))}</button>` +
    `<button data-t="dom">${icon("globe")} ${esc(t("tabs.domains"))}</button>` +
    `<button data-t="vis">${icon("eye")} ${esc(t("tabs.visited"))}</button>` +
    `<button data-t="hist">${icon("chart")} ${esc(t("tabs.history"))}</button>` +
    `</div><div id="dBody"></div>`);
  const tabs = $$(".dtabs button");
  const box = () => $("#dBody");
  function go(t) {
    if (histTimer) { clearInterval(histTimer); histTimer = null; }   // leaving a tab stops the live redraw
    dTok++;                                                          // supersede any in-flight tab render
    tabs.forEach((b) => b.classList.toggle("on", b.dataset.t === t));
    if (t === "info") fpInto(box(), ip);
    else if (t === "svc") servicesInto(box(), ip, restricted);
    else if (t === "dom") domainsInto(box(), ip, restricted);
    else if (t === "vis") visitedInto(box(), ip);
    else histInto(box(), ip);
  }
  tabs.forEach((b) => (b.onclick = () => go(b.dataset.t)));
  go("info");
}

function fmtWhen(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts * 1000), diff = (Date.now() - d.getTime()) / 1000;
    const rel = diff < 60 ? t("info.just_now") : diff < 3600 ? t("info.mins_ago", { n: Math.floor(diff / 60) })
      : diff < 86400 ? t("info.hours_ago", { n: Math.floor(diff / 3600) }) : t("info.days_ago", { n: Math.floor(diff / 86400) });
    return `${d.toLocaleString()} (${rel})`;
  } catch (e) { return "—"; }
}
async function fpInto(box, ip) {
  const tok = dTok;
  const dev = lastDevices.find((d) => d.ip === ip) || {};
  // POLICY-AWARE (P7-05): make clear that low/zero throughput on a managed device
  // is SharkNet's own enforcement, not a genuine network problem.
  const pol = dev.mode === "hardcut" ? t("info.pol_hardcut")
    : dev.mode === "cut" ? t("info.pol_cut")
    : dev.mode === "limit" ? t("info.pol_limit") : "";
  const polHtml = pol ? `<div class="pol-banner">${icon("gear")} ${esc(pol)}</div>` : "";
  // stable device identity (kept by MAC across IP changes & restarts)
  const idHtml = polHtml +
    `<div class="sec-t">${esc(t("info.identity"))}</div>` +
    `<div class="kv"><span>${esc(t("info.device_id"))}</span><b>${esc(dev.mac || "—")}</b></div>` +
    `<div class="kv"><span>${esc(t("info.vendor"))}</span><b>${esc(dev.vendor || "—")}</b></div>` +
    (dev.hostname ? `<div class="kv"><span>${esc(t("info.hostname"))}</span><b>${esc(dev.hostname)}</b></div>` : "") +
    (dev.hostname && dev.name_source ? `<div class="kv"><span>${esc(t("info.name_via"))}</span><b>${esc(nameSrcLabel(dev.name_source))}</b></div>` : "") +
    `<div class="kv"><span>${esc(t("info.first_seen"))}</span><b>${fmtWhen(dev.first_seen)}</b></div>` +
    `<div class="kv"><span>${esc(t("info.last_seen"))}</span><b>${fmtWhen(dev.last_seen)}</b></div>`;
  box.innerHTML = idHtml + `<div class="sec-t">${esc(t("info.scan"))}</div><div class="muted">${esc(t("info.scanning", { ip: ip }))}</div>`;
  try {
    const r = await (await apiGet("/api/fingerprint/" + ip)).json();
    if (tok !== dTok) return;                 // user switched tabs — don't clobber
    const f = (r.ok && r.result) || { ip, os_guess: "—", ttl: null, open_ports: [] };
    const ports = f.open_ports.length
      ? f.open_ports.map((p) => `<span class="chip">${esc(p.port)} · ${esc(p.name)}</span>`).join("")
      : `<span class='muted'>${esc(t("info.no_ports"))}</span>`;
    box.innerHTML = idHtml +
      `<div class="sec-t">${esc(t("info.scan"))}</div>` +
      `<div class="kv"><span>${esc(t("info.current_ip"))}</span><b>${esc(f.ip)}</b></div>` +
      `<div class="kv"><span>${esc(t("info.os_guess"))}</span><b>${esc(f.os_guess)}</b></div>` +
      `<div class="kv"><span>${esc(t("info.ttl"))}</span><b>${f.ttl == null ? "—" : esc(f.ttl)}</b></div>` +
      `<div class="kv"><span>${esc(t("info.open_ports"))}</span></div><div class="chips">${ports}</div>`;
  } catch (e) { if (tok === dTok) box.innerHTML = idHtml + `<div class='muted'>${esc(t("info.scan_error"))}</div>`; }
}

// draw a down/up line chart from [{ts,down,up}] samples into a canvas
function drawHistory(cv, samples) {
  const ctx = cv.getContext("2d"), W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  if (samples.length < 2) return 0;
  const cs = getComputedStyle(document.documentElement);
  const acc = cs.getPropertyValue("--accent").trim(), suc = cs.getPropertyValue("--success").trim();
  const max = Math.max(1, ...samples.map((x) => Math.max(x.down, x.up)));
  [["down", acc], ["up", suc]].forEach(([k, col]) => {
    ctx.beginPath();
    samples.forEach((x, i) => {
      const px = (i / (samples.length - 1)) * W, py = H - (x[k] / max) * (H - 6) - 3;
      i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
    });
    ctx.strokeStyle = col; ctx.lineWidth = 1.8; ctx.stroke();
  });
  return max;
}

async function histInto(box, ip) {
  // HARD CUT (V3.1) intentionally provides no traffic inspection, so there is no
  // history to chart — show the isolation note instead of an empty/zero graph.
  const dev0 = lastDevices.find((x) => x.ip === ip) || {};
  if (dev0.mode === "hardcut") {
    box.innerHTML = `<div class="hardcut-note">${icon("ban")} ${esc(t("hardcut.note"))}</div>`;
    return;
  }
  box.innerHTML = `<canvas id="histCanvas" width="540" height="170"></canvas><div class="muted" id="histNote">${esc(t("history.title") + " — " + t("history.subtitle"))}</div>`;
  if (histTimer) { clearInterval(histTimer); histTimer = null; }
  let samples = [];
  try {
    const r = await (await apiGet("/api/history/" + ip + "?seconds=600")).json();
    samples = r.history || [];
  } catch (e) { return; }
  const cv = $("#histCanvas"), note = $("#histNote");
  if (!cv) return;   // tab switched/closed while fetching

  const managed = (d) => d && (d.mode === "limit" || d.mode === "cut" || (d.blocked && d.blocked.length));
  function paint() {
    const max = drawHistory(cv, samples);
    if (!samples.length) {
      note.textContent = t("history.empty");
    } else {
      note.textContent = `${t("history.title")} — ${t("history.subtitle")} · ${t("history.peak")} ${speedStr(max)} (${t("history.legend")})`;
    }
  }
  paint();

  // extend the chart live from the per-tick speeds the UI already receives over
  // the WebSocket (no extra payload). Only append real samples for a device we
  // actually intercept; drop points older than the 10-minute window.
  histTimer = setInterval(() => {
    if (!document.body.contains(cv)) { clearInterval(histTimer); histTimer = null; return; }
    const d = lastDevices.find((x) => x.ip === ip);
    if (managed(d)) {
      samples.push({ ts: Date.now() / 1000, down: d.down_bps, up: d.up_bps });
      const cutoff = Date.now() / 1000 - 600;
      while (samples.length && samples[0].ts < cutoff) samples.shift();
      paint();
    }
  }, 1000);
}

// ---- SERVICES tab: block whole services (explicit "Block services" control) ----
async function servicesInto(box, ip, restricted) {
  const tok = dTok;
  box.innerHTML = `<div class="muted">${esc(t("common.loading"))}</div>`;
  let services = [];
  try {
    if (!SERVICES.length) await loadServices();
    const dr = await apiGet("/api/domains/" + ip).then((r) => r.json());
    services = dr.services || [];
  } catch (e) { if (tok === dTok) box.innerHTML = `<div class='muted'>${esc(t("common.error"))}</div>`; return; }
  if (tok !== dTok) return;                     // user switched tabs — don't clobber
  if (restricted) { box.innerHTML = `<div class="muted">${esc(t("services.restricted"))}</div>`; return; }
  // F1/F2: pending state on the clicked chip, commit + toast ONLY on backend success.
  async function apply(next, name, unblock) {
    let ok = false;
    try { const r = await api("/api/services/block", { ip, services: next }); ok = !!(r && r.ok); } catch (e) {}
    if (ok) { services = next; toast(unblock ? "✓ " + t("toast.service_unblocked") : "✓ " + t("toast.service_blocked"), name); }
    else { toast(unblock ? "✕ " + t("toast.unblock_failed") : "✕ " + t("toast.block_failed"), name, "danger"); }
    render();
  }
  function render() {
    box.innerHTML =
      `<div class="sec-t">${esc(t("services.block_title"))}</div>` +
      `<div class="hint">${esc(t("services.hint"))}</div>` +
      `<div class="psets">${serviceChipsHtml(services)}</div>`;
    $$(".pset", box).forEach((b) => b.onclick = () => {
      if (b.classList.contains("pending")) return;
      const id = b.dataset.s, on = services.includes(id), name = svcName(id);
      b.classList.add("pending"); b.disabled = true;
      b.textContent = on ? t("state.unblocking", { name: name }) : t("state.blocking", { name: name });
      apply(on ? services.filter((x) => x !== id) : services.concat([id]), name, on);
    });
  }
  render();
}

// ---- DOMAINS tab: block ad-hoc domains ("Block domains" control) ----
async function domainsInto(box, ip, restricted) {
  const tok = dTok;
  box.innerHTML = `<div class="muted">${esc(t("common.loading"))}</div>`;
  let blocked = [];
  try { const dr = await apiGet("/api/domains/" + ip).then((r) => r.json()); blocked = dr.blocked || []; }
  catch (e) { if (tok === dTok) box.innerHTML = `<div class='muted'>${esc(t("common.error"))}</div>`; return; }
  if (tok !== dTok) return;                     // user switched tabs — don't clobber
  if (restricted) { box.innerHTML = `<div class="muted">${esc(t("domains.restricted"))}</div>`; return; }
  async function apply(next, dom, unblock) {
    let ok = false;
    try { const r = await api("/api/domains/block", { ip, domains: next }); ok = !!(r && r.ok); } catch (e) {}
    if (ok) { blocked = next; toast(unblock ? "✓ " + t("toast.domain_unblocked") : "✓ " + t("toast.domain_blocked"), dom); }
    else { toast(unblock ? "✕ " + t("toast.unblock_failed") : "✕ " + t("toast.block_failed"), dom, "danger"); }
    render();
  }
  function render() {
    const chips = blocked.length
      ? blocked.map((d) => `<span class="chip block" data-d="${esc(d)}">${esc(d)} ✕</span>`).join("")
      : `<span class='muted'>${esc(t("domains.no_domains"))}</span>`;
    box.innerHTML =
      `<div class="sec-t">${esc(t("domains.block_title"))}</div>` +
      `<div class="chips">${chips}</div>` +
      `<div class="addrow"><input id="domIn" placeholder="${esc(t("domains.placeholder"))}"/><button id="domAdd" class="btn">${esc(t("domains.block_btn"))}</button></div>` +
      `<div class="scope-note">${esc(t("domains.disclaimer"))}</div>`;
    $$(".chip.block", box).forEach((c) => c.onclick = () => {
      if (c.classList.contains("pending")) return;
      const d = c.dataset.d; c.classList.add("pending"); c.textContent = t("state.unblocking", { name: d });
      apply(blocked.filter((x) => x !== d), d, true);
    });
    $("#domAdd").onclick = () => {
      const v = $("#domIn").value.trim().toLowerCase();
      if (!v || blocked.includes(v)) return;
      const btn = $("#domAdd"); btn.disabled = true; btn.textContent = t("state.blocking_short");
      apply(blocked.concat([v]), v, false);
    };
    $("#domIn").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#domAdd").click(); });
  }
  render();
}

// ---- VISITED SITES tab: observed sites (READ-ONLY; NOT a block list, item 16) ----
async function visitedInto(box, ip) {
  const tok = dTok;
  box.innerHTML = `<div class="muted">${esc(t("common.loading"))}</div>`;
  let visited = [], blocked = [], services = [];
  try {
    const dr = await apiGet("/api/domains/" + ip).then((r) => r.json());
    visited = dr.visited || []; blocked = dr.blocked || []; services = dr.services || [];
  } catch (e) { if (tok === dTok) box.innerHTML = `<div class='muted'>${esc(t("common.error"))}</div>`; return; }
  if (tok !== dTok) return;                     // user switched tabs — don't clobber
  const isBlk = (dom) => blocked.some((b) => dom === b || dom.endsWith("." + b));
  // HONEST empty state (P0): reflect ACTUAL observability, never prescribe Cut/Limit.
  // A device is observed when it is intercepted = monitored OR has an enforcement
  // rule (limit/block/service) OR a network rule is active. CUT is intercepted but
  // intentionally forwards nothing, so it observes nothing (documented limitation).
  const dev = lastDevices.find((x) => x.ip === ip) || {};
  const netActive = !!(lastNetwork && ((lastNetwork.services || []).length || (lastNetwork.domains || []).length));
  const observed = dev.monitor || dev.mode === "limit" || blocked.length || services.length || netActive;
  const emptyMsg = dev.mode === "hardcut" ? t("visited.hardcut")
    : dev.mode === "cut" ? t("visited.cut")
    : observed ? t("visited.empty") : t("visited.off");
  const vis = visited.length
    ? visited.map((v) =>
        `<div class="vrow">${esc(v.domain)}` +
        (v.service ? ` <span class="vsvc">${esc(svcName(v.service))}</span>` : "") +
        (isBlk(v.domain) ? ` <span class="vblk">${esc(t("visited.blocked_tag"))}</span>` : "") + `</div>`).join("")
    : `<div class='muted'>${esc(emptyMsg)}</div>`;
  // NOTE: no click handlers here — viewing a visited site is observation only and
  // never blocks anything. A site shows a "blocked" tag only if it's ALSO in the
  // device's block rules (a visited site is not automatically blocked).
  box.innerHTML =
    `<div class="sec-t">${esc(t("visited.title"))} (${visited.length})</div>` +
    `<div class="hint">${esc(t("visited.hint"))}</div>` +
    `<div class="vlist">${vis}</div>`;
}

// shared service-chip renderer (data-driven from the catalog). `on` ids are ✓.
// A small "Q" marks QUIC-heavy services (blocked best-effort on UDP/443).
function serviceChipsHtml(onIds) {
  return SERVICES.map((s) => {
    const on = onIds.includes(s.id);
    const q = s.quic ? ` <span class="q" title="${esc(t("services.quic_tip"))}">Q</span>` : "";
    const tip = (s.regions || []).join(", ").toUpperCase() + (s.notes ? " — " + s.notes : "");
    return `<button class="pset ${on ? "on" : ""}" data-s="${esc(s.id)}" title="${esc(tip)}">${on ? "✓ " : ""}${esc(s.name)}${q}</button>`;
  }).join("");
}

// ---------- Network-wide rules modal (Phase 7, session-only) ----------
async function openNetworkRules() {
  openModal(t("network.title"), `<div id="netBody"><div class="muted">${esc(t("common.loading"))}</div></div>`);
  let services = [], domains = [];
  try {
    if (!SERVICES.length) await loadServices();
    const nr = await apiGet("/api/network").then((r) => r.json());
    services = (nr.network && nr.network.services) || [];
    domains = (nr.network && nr.network.domains) || [];
  } catch (e) {}
  // commit + toast ONLY on backend success (F2); the clicked element shows a
  // pending state meanwhile (F1). Network block/unblock, services + domains.
  async function apply(nextServices, nextDomains, label, unblock) {
    let ok = false;
    try { const r = await api("/api/network/block", { services: nextServices, domains: nextDomains }); ok = !!(r && r.ok); } catch (e) {}
    if (ok) { services = nextServices; domains = nextDomains; toast(unblock ? "✓ " + t("toast.network_unblocked") : "✓ " + t("toast.network_blocked"), label); }
    else { toast(unblock ? "✕ " + t("toast.unblock_failed") : "✕ " + t("toast.block_failed"), label, "danger"); }
    render();
  }
  function render() {
    const box = $("#netBody"); if (!box) return;
    const chips = domains.length
      ? domains.map((d) => `<span class="chip block" data-d="${esc(d)}">${esc(d)} ✕</span>`).join("")
      : `<span class='muted'>${esc(t("network.no_domains"))}</span>`;
    box.innerHTML =
      `<div class="net-note">${esc(t("network.note"))}</div>` +
      `<div class="sec-t">${esc(t("network.block_services"))}</div><div class="psets">${serviceChipsHtml(services)}</div>` +
      `<div class="sec-t">${esc(t("network.blocked_domains"))}</div><div class="chips">${chips}</div>` +
      `<div class="addrow"><input id="netDomIn" placeholder="${esc(t("network.placeholder"))}"/><button id="netDomAdd" class="btn">${esc(t("domains.block_btn"))}</button></div>`;
    $$("#netBody .pset").forEach((b) => b.onclick = () => {
      if (b.classList.contains("pending")) return;
      const id = b.dataset.s, on = services.includes(id), name = svcName(id);
      b.classList.add("pending"); b.disabled = true; b.textContent = on ? t("state.unblocking", { name: name }) : t("state.blocking", { name: name });
      apply(on ? services.filter((x) => x !== id) : services.concat([id]), domains, name, on);
    });
    $$("#netBody .chip.block").forEach((c) => c.onclick = () => {
      if (c.classList.contains("pending")) return;
      const d = c.dataset.d; c.classList.add("pending"); c.textContent = t("state.unblocking", { name: d });
      apply(services, domains.filter((x) => x !== d), d, true);
    });
    $("#netDomAdd").onclick = () => {
      const v = $("#netDomIn").value.trim().toLowerCase();
      if (!v || domains.includes(v)) return;
      const btn = $("#netDomAdd"); btn.disabled = true; btn.textContent = t("state.blocking_short");
      apply(services, domains.concat([v]), v, false);
    };
    $("#netDomIn").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#netDomAdd").click(); });
  }
  render();
}

// ============================================================
// SharkMAC — MAC Address Manager (native, isolated from Cut/Limit core)
// ============================================================
let smac = { adapters: [], vendors: [], guid: "", preset: "random", generated: "", busy: false, open: false, timer: null };

$(".smi", $("#sharkmacBtn")).innerHTML = icon("sharkmac");   // icon only; keep the "SharkMAC" label
$("#sharkmacBtn").addEventListener("click", openSharkmac);

async function openSharkmac() {
  smac.open = true;
  openModal(t("smac.title"), `<div id="smacBody" class="smac"><div class="muted">${esc(t("smac.reading"))}</div></div>`);
  smac.open = true;   // openModal doesn't clear it, but keep explicit
  try {
    const [ar, vr] = await Promise.all([
      apiGet("/api/mac/adapters").then((r) => r.json()),
      apiGet("/api/mac/vendors").then((r) => r.json()),
    ]);
    smac.adapters = ar.adapters || [];
    smac.vendors = vr.vendors || [];
    // SHARKmac only offers Ethernet / Wi-Fi (the backend filters out Bluetooth PAN
    // and other non-LAN media). With none present, say so honestly instead of
    // rendering an empty picker.
    if (!smac.adapters.length) {
      const b = $("#smacBody");
      if (b) b.innerHTML = `<div class="smac-empty">${icon("warn")}<span>${esc(t("smac.no_adapters"))}</span></div>`;
      return;
    }
    smac.guid = ar.selected_guid || (smac.adapters[0] || {}).guid || "";
    smac.preset = "random"; smac.generated = "";
    renderSmac();
    genSmac();          // show an initial suggestion
  } catch (e) {
    const b = $("#smacBody"); if (b) b.innerHTML = `<div class='muted'>${esc(t("smac.read_error"))}</div>`;
  }
}

function smacAdapter() { return smac.adapters.find((a) => a.guid === smac.guid) || {}; }

function renderSmac() {
  const a = smacAdapter();
  const cap = a.capability || "unsupported";
  const capCls = cap === "supported" ? "ok" : cap === "maybe" ? "warn" : "bad";
  const capTxt = cap === "supported" ? "✓ " + t("smac.supported") : cap === "maybe" ? "⚠ " + t("smac.maybe") : "✗ " + t("smac.unsupported");
  const spoofed = a.current && a.permanent && a.current !== a.permanent;
  const adOpts = smac.adapters.map((x) =>
    `<option value="${esc(x.guid)}" ${x.guid === smac.guid ? "selected" : ""}>${esc(x.name)} — ${esc((x.description || "").slice(0, 28))}</option>`).join("");
  const vendorRow = smac.preset === "vendor"
    ? `<div class="smac-row"><label>${esc(t("smac.vendor"))}</label><select id="smacVendor">${smac.vendors.map((v) => `<option>${esc(v)}</option>`).join("")}</select></div>` : "";
  const customRow = smac.preset === "custom"
    ? `<div class="smac-row"><label>${esc(t("smac.enter_mac"))}</label><input id="smacCustom" placeholder="02:11:22:33:44:55" maxlength="17" value="${esc(smac.generated || "")}"/></div>` : "";
  $("#smacBody").innerHTML = `
    <div class="smac-row"><label>${esc(t("smac.adapter"))}</label><select id="smacAdapter">${adOpts}</select></div>
    <div class="smac-cap ${capCls}">${esc(capTxt)}${a.reason ? " · " + esc(a.reason) : ""}</div>
    <div class="smac-cards">
      <div class="smac-card"><span>${esc(t("smac.original_mac"))}</span><b>${esc(a.permanent || "—")}</b></div>
      <div class="smac-card"><span>${esc(t("smac.current_mac"))}</span><b class="${spoofed ? "spoofed" : ""}">${esc(a.current || "—")}</b></div>
    </div>
    <div class="smac-row"><label>${esc(t("smac.preset"))}</label>
      <div class="seg smac-preset">
        <button data-p="random" class="${smac.preset === "random" ? "on" : ""}">${esc(t("smac.random"))}</button>
        <button data-p="vendor" class="${smac.preset === "vendor" ? "on" : ""}">${esc(t("smac.vendor"))}</button>
        <button data-p="custom" class="${smac.preset === "custom" ? "on" : ""}">${esc(t("smac.custom"))}</button>
      </div>
    </div>
    ${vendorRow}${customRow}
    <div class="smac-gen"><span>${esc(t("smac.generated"))}</span><b id="smacGen">${esc(smac.generated || "—")}</b>
      <button class="ubtn sm" id="smacCopy" title="${esc(t("smac.copy_tip"))}" aria-label="${esc(t("smac.copy_tip"))}">${icon("copy")}</button>
      <button class="ubtn sm" id="smacRefresh" title="${esc(t("smac.regen_tip"))}" aria-label="${esc(t("smac.regen_tip"))}">${icon("refresh")}</button></div>
    <div class="smac-warn">${icon("warn")} ${esc(t("smac.warn"))}</div>
    <div class="smac-actions">
      <button class="btn" id="smacGenerate">${esc(t("smac.generate"))}</button>
      <button class="btn btn-primary" id="smacChange" ${cap === "unsupported" ? "disabled" : ""}>${esc(t("smac.change"))}</button>
      <button class="btn" id="smacRestore" ${!spoofed ? "disabled" : ""} title="${esc(t("smac.restore_tip"))}">${esc(t("smac.restore"))}</button>
    </div>
    <div class="smac-status" id="smacStatus" aria-live="polite"></div>`;
  wireSmac();
}

function wireSmac() {
  $("#smacAdapter").onchange = (e) => { smac.guid = e.target.value; smac.generated = ""; renderSmac(); genSmac(); };
  $$(".smac-preset button").forEach((b) => b.onclick = () => { smac.preset = b.dataset.p; smac.generated = ""; renderSmac(); if (smac.preset !== "custom") genSmac(); });
  const vsel = $("#smacVendor"); if (vsel) vsel.onchange = genSmac;
  const gen = $("#smacGenerate"); if (gen) gen.onclick = genSmac;
  const rf = $("#smacRefresh"); if (rf) rf.onclick = genSmac;
  const cp = $("#smacCopy"); if (cp) cp.onclick = () => { const m = macToApply(); if (m) { try { navigator.clipboard.writeText(m); smacStatus(t("smac.copied", { mac: m })); } catch (e) {} } };
  const ch = $("#smacChange"); if (ch) ch.onclick = () => doMacChange(false);
  const rs = $("#smacRestore"); if (rs) rs.onclick = () => doMacChange(true);
  const ci = $("#smacCustom"); if (ci) ci.oninput = () => { smac.generated = ci.value; const g = $("#smacGen"); if (g) g.textContent = ci.value || "—"; };
}

function macToApply() {
  if (smac.preset === "custom") { const ci = $("#smacCustom"); return ci ? ci.value.trim() : ""; }
  return smac.generated;
}

async function genSmac() {
  // pass the adapter's current MAC (already known client-side) so the server
  // doesn't do a second Get-NetAdapter — keeps Generate instant.
  const body = { preset: smac.preset, current: (smacAdapter().current || "") };
  if (smac.preset === "vendor") body.vendor = ($("#smacVendor") || {}).value || (smac.vendors[0] || "");
  if (smac.preset === "custom") body.mac = macToApply();
  try {
    const r = await api("/api/mac/generate", body);
    if (r.ok) { smac.generated = r.mac; const g = $("#smacGen"); if (g) g.textContent = r.mac; smacStatus(""); }
    else smacStatus("⚠ " + (r.error || t("smac.could_not_generate")));
  } catch (e) { smacStatus("⚠ " + t("smac.gen_error")); }
}

function smacStatus(t, cls) { const s = $("#smacStatus"); if (s) { s.textContent = t || ""; s.className = "smac-status" + (cls ? " " + cls : ""); } }

async function doMacChange(restore) {
  if (smac.busy) return;
  const mac = restore ? "" : macToApply();
  if (!restore && !mac) { smacStatus("⚠ " + t("smac.need_mac"), "bad"); return; }
  smac.busy = true;
  $$(".smac-actions button").forEach((b) => b.disabled = true);
  smacStatus(restore ? t("smac.restoring") : t("smac.changing"), "busy");
  clearTimeout(smac.timer);
  smac.timer = setTimeout(() => { if (smac.busy) { smac.busy = false; $$(".smac-actions button").forEach((b) => b.disabled = false); smacStatus("⚠ " + t("smac.timeout"), "bad"); } }, 30000);
  try {
    const r = await api("/api/mac/change", { guid: smac.guid, mac, restore });
    if (!r.ok) { clearTimeout(smac.timer); smac.busy = false; $$(".smac-actions button").forEach((b) => b.disabled = false); smacStatus("⚠ " + (r.error || t("smac.change_refused")), "bad"); }
    // success/failure of the actual apply arrives via WS event -> onMacResult()
  } catch (e) { clearTimeout(smac.timer); smac.busy = false; smacStatus("⚠ " + t("smac.request_failed"), "bad"); }
}

// called from handleEvent() when the coordinator finishes
function onMacResult(ev) {
  clearTimeout(smac.timer);
  smac.busy = false;
  if (ev.kind === "mac_changed") {
    smac.open = false;
    closeModal();
    const resetNote = ev.session_reset
      ? `<p class="muted">${esc(t("smac.session_reset"))}</p>`
      : `<p class="muted">${esc(t("smac.no_reset"))}</p>`;
    openModal("✓ " + t("smac.changed_title"), `
      <div class="smac-done">
        <div class="smac-done-mac">${esc(ev.mac || "")}</div>
        <p>${t(ev.restored ? "smac.done_restored" : "smac.done_changed", { adapter: "<b>" + esc(ev.adapter || "") + "</b>" })}</p>
        ${resetNote}
        <button class="btn btn-primary" id="smacDoneOk">${esc(t("smac.back"))}</button>
      </div>`);
    const ok = $("#smacDoneOk"); if (ok) ok.onclick = closeModal;
    toast("✓ " + t("smac.mac_changed"), (ev.adapter || "") + " → " + (ev.mac || ""));
  } else {
    // failure — the session is preserved. Refresh the adapter cards, THEN show
    // the error LAST so the re-render can't wipe it (fixes the red message
    // vanishing instantly). The message stays until the next action.
    const msg = (ev.message || t("smac.change_fail_generic")) + (ev.reverted ? " " + t("smac.reverted") : "");
    if (smac.open) {
      apiGet("/api/mac/adapters").then((r) => r.json())
        .then((ar) => { smac.adapters = ar.adapters || smac.adapters; })
        .catch(() => {})
        .finally(() => { if (smac.open) { renderSmac(); smacStatus("⚠ " + msg, "bad"); } });
    } else {
      toast(t("smac.mac_failed"), msg, "danger", "warn");
    }
  }
}

$("#aboutBtn").addEventListener("click", () => {
  // version (kept in sync with the footer, which the server fills)
  const ver = (($("#verNum") || {}).textContent || "v3.2.0").trim();
  // dedication heading: localizes with the UI language; English shows BOTH the
  // Arabic original and the English line. The du'a (prayer) below stays Arabic only.
  const AR_DED = "إهداءٌ إلى روح والدي الغالي";
  const lang = (window.I18N && I18N.lang) || "en";
  const dedHead = lang === "ar"
    ? `<div class="dua-title" dir="rtl">${AR_DED}</div>`
    : lang === "en"
    ? `<div class="dua-title" dir="rtl">${AR_DED}</div><div class="dua-title-en" dir="ltr">${esc(t("about.dedication"))}</div>`
    : `<div class="dua-title" dir="ltr">${esc(t("about.dedication"))}</div>`;
  openModal(t("about.title"), `
    <div class="about">
      <img class="about-logo" src="/logo.png?v=3.2.0" alt="SharkNet" />
      <p class="about-app">${esc(t("about.desc"))}</p>
      <div class="about-ver">SharkNet ${esc(ver)}</div>
      <div class="disclaimer">${icon("warn")} ${esc(t("about.disclaimer"))} 🤍</div>
      <div class="dua" dir="rtl">
        ${dedHead}
        <div class="dua-body">
          اللَّهُمَّ اغْفِرْ لَهُ وَارْحَمْهُ، وَعَافِهِ وَاعْفُ عَنْهُ، وَأَكْرِمْ نُزُلَهُ،
          وَوَسِّعْ مُدْخَلَهُ، وَاغْسِلْهُ بِالْمَاءِ وَالثَّلْجِ وَالْبَرَدِ، وَنَقِّهِ مِنَ
          الْخَطَايَا كَمَا يُنَقَّى الثَّوْبُ الْأَبْيَضُ مِنَ الدَّنَسِ. اللَّهُمَّ اجْعَلْ
          قَبْرَهُ رَوْضَةً مِنْ رِيَاضِ الْجَنَّةِ، وَآنِسْ وَحْشَتَهُ، وَاجْعَلْ هَذَا الْعَمَلَ
          فِي مِيزَانِ حَسَنَاتِهِ.
        </div>
        <div class="dua-sign">رحمه الله وأسكنه فسيح جِنانه 🤍</div>
      </div>
    </div>`);
});

// ---- Ookla-style speed gauge ----
const SPEED_STOPS = [0, 5, 10, 50, 100, 250, 500, 750, 1000];
const GG = { cx: 170, cy: 188, r: 140 };
function speedToFrac(v) {
  v = Math.max(0, Math.min(1000, v));
  for (let i = 1; i < SPEED_STOPS.length; i++) {
    if (v <= SPEED_STOPS[i]) {
      const a = SPEED_STOPS[i - 1], b = SPEED_STOPS[i];
      return (i - 1 + (v - a) / (b - a)) / (SPEED_STOPS.length - 1);
    }
  }
  return 1;
}
const fracDeg = (f) => 225 - 270 * f;
function polar(r, deg) {
  const rad = deg * Math.PI / 180;
  return [GG.cx + r * Math.cos(rad), GG.cy - r * Math.sin(rad)];
}
function arcD(r, segs = 72) {
  let s = "";
  for (let i = 0; i <= segs; i++) {
    const p = polar(r, fracDeg(i / segs));
    s += (i ? " L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1);
  }
  return s;
}

$("#speedBtn").addEventListener("click", () => runSpeedTest());

function runSpeedTest() {
  // modern progress-ring gauge: clean glowing arc + big readout, no dashboard
  // needle/tick clutter. The arc fill IS the value indicator.
  openModal(t("speed.title"), `
    <div class="gauge-wrap">
      <div class="gg-tabs"><span id="ggPhase" class="on">↓ ${esc(t("speed.download"))}</span><span id="ggPhase2">↑ ${esc(t("speed.upload"))}</span></div>
      <svg viewBox="0 0 340 250" class="gauge">
        <defs>
          <linearGradient id="ggGrad" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" style="stop-color:var(--accent)"/><stop offset="1" style="stop-color:var(--success)"/>
          </linearGradient>
          <filter id="ggGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <path d="${arcD(GG.r)}" class="gg-track"/>
        <path id="ggFill" d="${arcD(GG.r)}" class="gg-fill" pathLength="1" style="stroke-dasharray:1;stroke-dashoffset:1"/>
        <text id="ggVal" x="${GG.cx}" y="${GG.cy - 4}" class="gg-val">0</text>
        <text x="${GG.cx}" y="${GG.cy + 24}" class="gg-unit">Mbps</text>
      </svg>
      <div class="gg-stats" id="ggStats">
        <div><b id="ggPing">—</b><span>${esc(t("speed.ping"))}</span></div>
        <div><b id="ggJit">—</b><span>${esc(t("speed.jitter"))}</span></div>
        <div><b id="ggLoss">—</b><span>${esc(t("speed.loss"))}</span></div>
        <div><b id="ggDns">—</b><span>${esc(t("speed.dns"))}</span></div>
        <div><b id="ggGrade">—</b><span>${esc(t("speed.grade"))}</span></div>
      </div>
      <div class="gg-isp" id="ggIsp"></div>
    </div>`);
  setNeedle(0);
  const idle = idleSweep();
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 35000);   // hard cap on the test
  // closing the modal must stop the sweep + abort the request (no leaked timers)
  onModalClose = () => { clearInterval(idle); clearTimeout(timer); try { ac.abort(); } catch (e) {} };

  const fail = (msg) => {
    clearInterval(idle); clearTimeout(timer);
    setNeedle(0);
    const stats = $("#ggStats"); if (stats) stats.style.opacity = ".35";
    const box = $("#ggIsp");
    if (box) box.innerHTML =
      `<div class="gg-error" role="alert">${icon("warn")} ${esc(msg)}` +
      `<button class="btn" id="ggRetry">${esc(t("speed.try_again"))}</button></div>`;
    const rb = $("#ggRetry"); if (rb) rb.onclick = () => runSpeedTest();
  };

  apiGet("/api/speedtest", { signal: ac.signal }).then((r) => r.json()).then(async (r) => {
    clearInterval(idle); clearTimeout(timer);
    const s = r.result || {};
    if (!s.ok) return fail(t("speed.failed"));
    if (!s.download_mbps && !s.upload_mbps)
      return fail(t("speed.no_throughput"));
    await animateTo(s.download_mbps || 0, 1600);
    $("#ggPhase").classList.remove("on"); $("#ggPhase2").classList.add("on");
    await animateTo(s.upload_mbps || 0, 1400);
    // settle: show download as the headline again
    await animateTo(s.download_mbps || 0, 700);
    $("#ggPhase").classList.add("on"); $("#ggPhase2").classList.remove("on");
    $("#ggPing").textContent = s.ping_ms == null ? "—" : s.ping_ms;
    $("#ggJit").textContent = s.jitter_ms == null ? "—" : s.jitter_ms;
    $("#ggLoss").textContent = s.packet_loss == null ? "—" : s.packet_loss;
    $("#ggDns").textContent = s.dns_ms == null ? "—" : s.dns_ms;
    const g = (s.grade || "").toLowerCase();
    const ge = $("#ggGrade");
    ge.textContent = t("grade." + g) === ("grade." + g) ? (s.grade || "—") : t("grade." + g);
    ge.className = "hgrade-" + (g === "excellent" ? "excellent" : g === "good" ? "good" : g === "fair" ? "fair" : "poor");
    const loc = [s.city, s.country].filter(Boolean).join(", ");
    if (s.isp || loc) {
      $("#ggIsp").innerHTML =
        `<div class="isp-row"><span>${esc(t("speed.provider"))}</span><b>${esc(s.isp || "—")}</b></div>` +
        `<div class="isp-row"><span>${esc(t("speed.location"))}</span><b>${esc(loc || "—")}</b></div>` +
        `<div class="isp-row"><span>${esc(t("speed.public_ip"))}</span><b>${esc(s.public_ip || "—")}</b></div>` +
        `<div class="isp-final">${esc(String(s.download_mbps))} Mbps ↓ &nbsp; · &nbsp; ${esc(String(s.upload_mbps))} Mbps ↑</div>`;
    }
  }).catch(() => {
    fail(ac.signal.aborted ? t("speed.timeout") : t("speed.could_not_run"));
  });
}

function setNeedle(v) {
  // arc fill is the indicator now (no needle) — animate the ring + the readout
  const fill = $("#ggFill"); if (fill) fill.style.strokeDashoffset = 1 - speedToFrac(v);
  const val = $("#ggVal"); if (val) val.textContent = v >= 100 ? Math.round(v) : v.toFixed(1);
}
function idleSweep() {
  let t = 0;
  return setInterval(() => { t += 0.12; setNeedle(30 + 28 * Math.sin(t)); }, 60);
}
function animateTo(target, ms) {
  return new Promise((resolve) => {
    const startV = parseFloat($("#ggVal")?.textContent || "0") || 0;
    const t0 = performance.now();
    function step(now) {
      const p = Math.min(1, (now - t0) / ms);
      const e = 1 - Math.pow(1 - p, 3);
      setNeedle(startV + (target - startV) * e);
      if (p < 1) requestAnimationFrame(step); else resolve();
    }
    requestAnimationFrame(step);
  });
}
