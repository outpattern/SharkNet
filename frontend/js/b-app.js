// SharkNet · app: interface list, WebSocket connect, incoming-state dispatch
// ---------- interfaces ----------
async function loadInterfaces() {
  const data = await (await apiGet("/api/interfaces")).json();
  const sel = $("#ifaceSelect");
  sel.innerHTML = "";
  data.interfaces.forEach((i) => {
    const o = document.createElement("option");
    o.value = i.name;
    o.textContent = `${i.description || i.name} — ${i.ip}`;
    o.dataset.ip = i.ip; o.dataset.gw = i.gateway || "—";
    sel.appendChild(o);
  });
  if (data.selected) sel.value = data.selected;
  updateIfaceMeta();
  if (!data.selected && data.interfaces.length) selectInterface();
}
function updateIfaceMeta() {
  const opt = $("#ifaceSelect").selectedOptions[0];
  if (opt) { $("#ccIp").textContent = opt.dataset.ip; $("#ccGw").textContent = opt.dataset.gw; }
}
async function selectInterface() {
  const name = $("#ifaceSelect").value;
  if (!name) return;
  await api("/api/interface", { name });
  updateIfaceMeta();
}

// ---------- websocket ----------
let ws;
function connectWS() {
  ws = new WebSocket(`ws://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(connectWS, 1500); };
  ws.onmessage = (e) => { try { onState(JSON.parse(e.data)); } catch (err) {} };
}
let lastConn = false;
function setConn(on) {
  lastConn = on;
  const c = $("#conn");
  c.className = "conn " + (on ? "on" : "off");
  const label = on ? t("conn.online") : t("conn.offline");
  c.title = label;
  c.setAttribute("aria-label", label);
}

// ---------- state ----------
let lastState = null;   // last full state message (for instant language re-render)
function onState(msg) {
  if (msg.type !== "state") return;
  lastState = msg;
  applyState(msg, true);
}
// render every surface from a state message. `withEvents` replays one-shot events
// (toasts) — skipped on a language re-render so switching never re-fires toasts.
function applyState(msg, withEvents) {
  lastPolicy = msg.policy || null;
  lastNetwork = msg.network || { services: [], domains: [] };
  renderStatus(msg.status);
  renderIntel(msg.health, lastPolicy);
  renderDefender(msg.defender);
  renderAdvice(msg.advice || []);
  renderNetwork(lastNetwork);
  renderDevices(msg.devices);
  if (withEvents) (msg.events || []).forEach(handleEvent);
  // in-app notifications the backend router selected for this tick
  if (withEvents) renderServerToasts(msg.toasts);
}
// called by i18n.setLang() — repaint all dynamic content in the new language
// using the last state we received (no network round-trip, no event replay).
function rerenderI18n() {
  setConn(lastConn);                 // re-localize the connection tooltip
  if (lastState) applyState(lastState, false);
}
