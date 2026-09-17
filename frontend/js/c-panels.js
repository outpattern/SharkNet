// SharkNet · panels: advice banner, control status, traffic intel + chart, Defender
const dismissedAdvice = new Set();
function renderAdvice(list) {
  const wrap = $("#advice");
  const show = list.filter((a) => !dismissedAdvice.has(a.kind));
  wrap.innerHTML = "";
  show.forEach((a) => {
    const el = document.createElement("div");
    el.className = "advice " + (a.kind || "");
    const iconName = { wifi: "wifi", winpcap: "warn", topology: "shuffle" }[a.kind] || "info";
    el.innerHTML =
      `<span class="ico">${icon(iconName)}</span>` +
      `<div class="body"><div class="a-title"></div><div class="a-text"></div></div>` +
      `<button class="a-x"></button>`;
    // localize by kind when we have strings for it; otherwise fall back to the
    // server-provided English text (backend advice stays a stable identifier).
    const tk = "advice." + a.kind + ".title", xk = "advice." + a.kind + ".text";
    $(".a-title", el).textContent = (I18N.dict[tk] || I18N.fb[tk]) ? t(tk) : a.title;
    $(".a-text", el).textContent = (I18N.dict[xk] || I18N.fb[xk]) ? t(xk) : a.text;
    $(".a-x", el).title = t("advice.dismiss");
    $(".a-x", el).setAttribute("aria-label", t("advice.dismiss"));
    $(".a-x", el).textContent = "✕";
    $(".a-x", el).onclick = () => { dismissedAdvice.add(a.kind); el.remove(); };
    wrap.appendChild(el);
  });
}

function renderStatus(st) {
  const active = st.controlling;
  $("#startBtn").classList.toggle("hidden", active);
  $("#scanBtn").classList.toggle("hidden", !active);
  $("#cutOthersBtn").classList.toggle("hidden", !active);
  $("#uncutOthersBtn").classList.toggle("hidden", !active);
  $("#netRulesBtn").classList.toggle("hidden", !active);
  $("#stopAllBtn").classList.toggle("hidden", !active);
  $("#ifaceSelect").disabled = active;
  const cc = $(".control-card");
  cc.classList.toggle("active", active);
  cc.classList.toggle("scanning", !!st.scanning);
  // empty-state observe indicator: red while idle, green once controlling (observing)
  const emptyEl = $("#empty");
  if (emptyEl) emptyEl.classList.toggle("observing", active);
  // localized status pill (replaces the old CSS ::before "● ACTIVE/SCANNING")
  const cs = $("#ccStatus");
  if (cs) cs.textContent = st.scanning ? "● " + t("control.scanning")
                          : active ? "● " + t("control.active") : "";
  const i = st.interface;
  if (i) { $("#ccIp").textContent = i.ip; $("#ccGw").textContent = i.gateway || "—"; }
  if (st.version) $("#verNum").textContent = st.version;
}

// ---------- Traffic Intelligence + Health ----------
const HIST = { down: [], up: [] };
let lastHealth = null;
function renderIntel(h, policy) {
  if (!h) return;
  lastHealth = h;
  policy = policy || lastPolicy;
  const [dn, du] = speedParts(h.down_bps || 0);
  const [un, uu] = speedParts(h.up_bps || 0);
  $("#iDown").innerHTML = `${dn} <span class="u">${du}</span>`;
  $("#iUp").innerHTML = `${un} <span class="u">${uu}</span>`;
  $("#iLat").innerHTML = (h.latency_ms == null ? "—" : Math.round(h.latency_ms)) + ' <span class="u">ms</span>';
  $("#iPps").innerHTML = fmtK(h.pps || 0) + ' <span class="u">/s</span>';

  const g = h.grade || "unknown";
  const gi = $("#iGrade");
  gi.textContent = t("grade." + g) === ("grade." + g) ? (g.charAt(0).toUpperCase() + g.slice(1)) : t("grade." + g);
  gi.className = "t-val hgrade-" + g;
  const dot = (ok) => ok ? '<b style="color:var(--success)">●</b>' : '<b style="color:var(--danger)">●</b>';
  let html =
    `<div class="hr"><span>${t("intel.loss")}</span><b>${(h.packet_loss || 0).toFixed(1)}%</b></div>` +
    `<div class="hr"><span>${t("intel.gateway")}</span>${dot(h.gateway_online)}</div>` +
    `<div class="hr"><span>${t("intel.dns")}</span>${dot(h.dns_online)}</div>` +
    `<div class="hr"><span>${t("intel.internet")}</span>${dot(h.internet_online)}</div>`;
  // POLICY-AWARE health (item 9): distinguish PHYSICAL network health from SharkNet
  // POLICY. The grade above is reachability-first while enforcing (health.py caps
  // it at >= "good" when the path is reachable and sets policy_influenced), so a
  // LIMIT/CUT never shows a misleading "Poor". Here we label the policy state.
  if (policy && policy.enforcing && (policy.cut || policy.limited || policy.network)) {
    const bits = [];
    if (policy.cut) bits.push(policy.cut + " " + t("intel.policy_blocked"));
    if (policy.limited) bits.push(policy.limited + " " + t("intel.policy_limited"));
    if (policy.network) bits.push(t("intel.policy_network"));
    const infl = h.policy_influenced ? " " + t("intel.policy_tip_load") : "";
    html += `<div class="hr pol" title="${esc(t("intel.policy_tip") + infl)}">` +
            `<span>${t("intel.policy")}</span><b>${esc(bits.join(" · "))}</b></div>`;
  }
  $("#healthRows").innerHTML = html;

  HIST.down.push(h.down_bps || 0); HIST.up.push(h.up_bps || 0);
  if (HIST.down.length > 60) { HIST.down.shift(); HIST.up.shift(); }
  drawChart();
}

// ---------- NETWORK-wide rules strip (Phase 7) ----------
function renderNetwork(net) {
  const strip = $("#netStrip");
  if (!strip) return;
  const svc = (net && net.services) || [];
  const dom = (net && net.domains) || [];
  if (svc.length + dom.length === 0) {
    strip.classList.add("hidden");
    $("#netChips").innerHTML = "";
    return;
  }
  strip.classList.remove("hidden");
  const chips =
    svc.map((id) => `<span class="net-chip svc" title="${esc(t("network.svc_tip"))}">${esc(svcName(id))}</span>`).join("") +
    dom.map((d) => `<span class="net-chip" title="${esc(t("network.dom_tip"))}">${esc(d)}</span>`).join("");
  $("#netChips").innerHTML = chips;
}
function fmtK(n) { return n >= 1000 ? (n / 1000).toFixed(1) + "K" : Math.round(n).toString(); }

function drawChart() {
  const cv = $("#netChart"); if (!cv) return;
  const ctx = cv.getContext("2d");
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  const cs = getComputedStyle(document.documentElement);
  const acc = cs.getPropertyValue("--accent").trim() || "#00d4ff";
  const suc = cs.getPropertyValue("--success").trim() || "#00ff88";
  const max = Math.max(1, ...HIST.down, ...HIST.up);
  const series = [[HIST.down, acc], [HIST.up, suc]];
  series.forEach(([arr, col]) => {
    if (arr.length < 2) return;
    ctx.beginPath();
    arr.forEach((v, i) => {
      const x = (i / (60 - 1)) * W;
      const y = H - (v / max) * (H - 4) - 2;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = col; ctx.lineWidth = 1.6; ctx.stroke();
    ctx.lineTo((arr.length - 1) / 59 * W, H); ctx.lineTo(0, H); ctx.closePath();
    ctx.globalAlpha = 0.12; ctx.fillStyle = col; ctx.fill(); ctx.globalAlpha = 1;
  });
}

// ---------- SharkNet Defender ----------
function renderDefender(d) {
  if (!d) return;
  const el = $("#defender"), sub = $("#defSub"), right = $("#defRight");
  const mkBadge = (txt) => { const b = document.createElement("span"); b.className = "def-badge"; b.id = "defBadge"; b.textContent = txt; return b; };
  const prot = d.protection || {};
  const protBtn = () => {
    const b = document.createElement("button");
    b.className = "def-lock" + (prot.locked ? " on" : "");
    b.innerHTML = (prot.locked ? icon("lock") : icon("unlock")) + " " +
      esc(prot.locked ? t("defender.protected") : t("defender.protect"));
    b.title = t("defender.protect_tip");
    b.onclick = () => {
      b.innerHTML = icon("loader", "spin") + " " + esc(t("defender.loading")); b.disabled = true; b.classList.add("loading");
      api("/api/protection", { enable: !prot.locked });
    };
    return b;
  };

  right.innerHTML = "";
  if (!d.active) {                                   // ── IDLE (neutral) ──
    el.className = "defender idle";
    sub.textContent = t("defender.idle_sub");
    right.appendChild(mkBadge("○ " + t("defender.inactive")));
    return;
  }
  const a = d.alert || {};
  const atk = a.attacker || {};
  // attacker suffix — the label is localized; IP / MAC / vendor stay verbatim
  const who = atk.ip || atk.mac
    ? ` — ${t("defender.attacker_label")}: ${atk.ip || "?"} (${atk.mac || "?"}${atk.vendor && atk.vendor !== "Unknown" ? " · " + atk.vendor : ""})`
    : "";

  if (!d.secure && !prot.locked) {                   // ── UNDER ATTACK (red) ──
    el.className = "defender alert";
    sub.textContent = (a.message || t("defender.anomaly")) + who;
    right.appendChild(mkBadge("⚠ " + t("defender.under_attack")));
    right.appendChild(protBtn());
    const ack = document.createElement("button");
    ack.className = "def-invest"; ack.textContent = t("defender.acknowledge");
    ack.onclick = () => { ack.textContent = "…"; ack.disabled = true; api("/api/defender/ack"); };
    right.appendChild(ack);
    if (!renderDefender._warned) {
      renderDefender._warned = true;
      toast(t("toast.security_alert"), (a.message || t("defender.spoofing")) + who, "warn", "warn");
    }
  } else if (prot.locked) {                          // ── PROTECTED (green) ──
    el.className = "defender protected";
    sub.textContent = d.secure
      ? t("defender.immune", { n: d.anomalies })
      : t("defender.autohealed", { msg: (a.message || "attack") + who });
    right.appendChild(protBtn());   // single Protected/Protect lock control (no duplicate badge)
  } else {                                           // ── SECURE (neutral) ──
    el.className = "defender";
    sub.textContent = t("defender.secure_sub", { ip: d.gateway_ip, mac: d.gateway_mac || "…", n: d.anomalies });
    right.appendChild(protBtn());
    right.appendChild(mkBadge("● " + t("defender.secure")));
  }
  if (d.secure) renderDefender._warned = false;
}
