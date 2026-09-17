// SharkNet · core: DOM helpers, api(), SVG icons, shared state, speed formatting
// SharkNet frontend
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// per-process capability token, injected into the page by the server. Only our
// own same-origin JS can read it; every /api call and the WebSocket must carry
// it, so cross-origin browser pages cannot drive the API.
const TOKEN = (document.querySelector('meta[name="sharknet-token"]') || {}).content || "";
const api = (path, body) =>
  fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-SharkNet-Token": TOKEN },
    body: body ? JSON.stringify(body) : undefined,
  }).then((r) => r.json());
// authenticated GET (same token header)
const apiGet = (path, opts) =>
  fetch(path, Object.assign({ headers: { "X-SharkNet-Token": TOKEN } }, opts || {}));

// debounce a button-triggered async action: disable + mark busy while it's in
// flight so rapid clicks can't fire duplicate requests. Returns the action's
// promise. A short tail keeps it disabled briefly after settling.
function guard(btn, fn) {
  if (!btn || btn.disabled || btn.classList.contains("busy")) return Promise.resolve();
  btn.disabled = true;
  btn.classList.add("busy");
  const release = () => setTimeout(() => {
    btn.disabled = false;
    btn.classList.remove("busy");
  }, 300);
  return Promise.resolve()
    .then(fn)
    .then((r) => { release(); return r; })
    .catch((e) => { release(); throw e; });
}

// ---- inline SVG icon set (Lucide-style, replaces emoji) ----
const SVG = {
  zap: '<path d="M13 2L4.5 12.5H11l-1 9.5 8.5-10.5H12l1-9.5z"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  heart: '<path d="M20.8 5.1a5.4 5.4 0 0 0-7.7 0L12 6.2l-1.1-1.1a5.4 5.4 0 1 0-7.7 7.7L12 21.5l8.8-8.7a5.4 5.4 0 0 0 0-7.7z"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 13a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 6.6 19l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H2a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 3.3 6.6l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H8a1.7 1.7 0 0 0 1-1.6V2a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V8a1.7 1.7 0 0 0 1.6 1H22a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  grid: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="14" r="2"/><circle cx="19" cy="14" r="2"/><path d="M12 7v2M10.5 12.5l-3.7 1M13.5 12.5l3.7 1"/>',
  shield: '<path d="M12 2l8 3v6c0 5-3.4 8.2-8 11-4.6-2.8-8-6-8-11V5l8-3z"/>',
  phone: '<rect x="7" y="2" width="10" height="20" rx="2.2"/><path d="M11 18.5h2"/>',
  computer: '<rect x="2" y="4" width="20" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  console: '<rect x="2" y="7" width="20" height="11" rx="4"/><path d="M7 11v3M5.5 12.5h3"/><circle cx="16" cy="11.5" r="1"/><circle cx="18.5" cy="13.5" r="1"/>',
  router: '<rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 17h.01M11 17h.01"/><path d="M12 6v4M8.8 8.5a4.5 4.5 0 0 1 6.4 0M6.5 6.2a8 8 0 0 1 11 0"/>',
  iot: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
  unknown: '<rect x="2" y="4" width="20" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/>',
  sharkmac: '<rect x="2" y="4.5" width="20" height="15" rx="2.5"/><path d="M2 9h20"/><circle cx="6.4" cy="14" r="1.3"/><path d="M10.5 13.3h7.5M10.5 15.5h4.5"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  // added V3.0 (emoji → SVG): consistent Lucide-style monochrome glyphs.
  // NOTE: the control-bar buttons (Start/Refresh/Cut/Uncut/Network/Stop) inline
  // their own SVG in index.html for no-flash first paint, so play/scissors/rotate/
  // square live there, not here — this registry holds only JS-rendered icons.
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  chart: '<path d="M3 3v18h18"/><path d="M7 13l3.5-4 3 2.5L20 6"/>',
  lock: '<rect x="4.5" y="11" width="15" height="9.5" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 8 0V11"/>',
  unlock: '<rect x="4.5" y="11" width="15" height="9.5" rx="2"/><path d="M8 11V7.5a4 4 0 0 1 7.6-1.7"/>',
  loader: '<path d="M12 3v3M12 18v3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M3 12h3M18 12h3M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/>',
  antenna: '<path d="M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4"/><circle cx="12" cy="12" r="1.6"/>',
  wifi: '<path d="M5 12.5a10 10 0 0 1 14 0M8.5 15.7a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.1"/>',
  warn: '<path d="M12 3.2L21 19H3z"/><path d="M12 10v4M12 17.5h.01"/>',
  shuffle: '<path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/>',
};
function icon(name, cls) {
  return `<svg class="ic ${cls || ""}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${SVG[name] || SVG.unknown}</svg>`;
}

// escape untrusted network-derived strings before putting them in innerHTML
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

let rows = {};
let currentView = "list";
let lastDevices = [];
let UNITS = "kbs";
try { UNITS = localStorage.getItem("sharknet-units") || "kbs"; } catch (e) {}
// Phase 7 shared state (classic scripts share the top-level scope)
let lastPolicy = null;                    // { enforcing, limited, cut, managed, network }
let lastNetwork = { services: [], domains: [] };   // NETWORK-scope rules snapshot
const SEL = new Set();                     // multi-select: selected device IPs
let SERVICES = [];                          // service catalog (from /api/services)
let SERVICES_BY_ID = {};                    // id -> service meta

// PRESENTATION-ONLY display order — most-popular first (global + MENA prevalence).
// Service IDs stay stable; this only decides the chip order in the UI. Any service
// not listed here (e.g. one added later via the catalog) sorts after these, by name.
const SERVICE_ORDER = [
  "netflix", "youtube", "whatsapp", "shahid", "watch-it", "tiktok", "instagram",
  "facebook", "snapchat", "twitter-x", "spotify", "anghami", "disney-plus",
  "amazon-prime-video", "bein", "osn-plus", "apple-music", "soundcloud",
  "apple-tv-plus", "max", "starzplay", "pubg-games", "tod", "weyyak", "rotana",
  "jawwy-tv", "viu", "yango-play", "hulu", "peacock", "paramount-plus", "espn-plus",
  "dazn", "crunchyroll", "mubi", "tubi", "pluto-tv", "bbc-iplayer", "itvx",
  "channel-4", "now-sky", "canal-plus", "rtl-plus", "movistar-plus", "viaplay",
  "skyshowtime", "molotov",
];
const SERVICE_RANK = {};
SERVICE_ORDER.forEach((id, i) => { SERVICE_RANK[id] = i; });
function sortServicesByPopularity(list) {
  return list.slice().sort((a, b) => {
    const ra = SERVICE_RANK[a.id] == null ? 900 : SERVICE_RANK[a.id];
    const rb = SERVICE_RANK[b.id] == null ? 900 : SERVICE_RANK[b.id];
    return ra - rb || String(a.name || "").localeCompare(String(b.name || ""));
  });
}

// load the service catalog once (data-driven; used by the Domains + Network UIs)
async function loadServices() {
  try {
    const r = await (await apiGet("/api/services")).json();
    SERVICES = sortServicesByPopularity(r.services || []);   // popularity display order
    SERVICES_BY_ID = {};
    SERVICES.forEach((s) => { SERVICES_BY_ID[s.id] = s; });
  } catch (e) {}
}
const svcName = (id) => (SERVICES_BY_ID[id] && SERVICES_BY_ID[id].name) || id;

// clipboard helper with a small toast. writeText() is async, so we toast success
// ONLY after it resolves and toast failure on reject — never a fake "✓ Copied"
// (and no uncaught promise rejection when the clipboard is blocked/unfocused).
function copyText(text, label) {
  const ok = () => toast("✓ " + t("copy.copied"), (label ? label + ": " : "") + text);
  const fail = () => toast(t("copy.failed"), t("copy.clipboard_unavailable"), "warn", "warn");
  try {
    const p = navigator.clipboard && navigator.clipboard.writeText(text);
    if (p && p.then) p.then(ok, fail); else ok();
  } catch (e) { fail(); }
}

// ---------- speed formatting (unit-aware) ----------
function speedStr(bps) {
  if (UNITS === "mbps") {
    return ((bps * 8) / 1e6).toFixed(2) + " Mb/s";   // always Mb/s so the toggle is obvious
  }
  const kb = bps / 1024;
  return kb >= 1024 ? (kb / 1024).toFixed(2) + " MB/s" : kb.toFixed(1) + " KB/s";
}
function speedParts(bps) { const p = speedStr(bps).split(" "); return [p[0], p.slice(1).join(" ")]; }
function barPct(bps) { const kb = bps / 1024; return Math.min(100, (kb / 2048) * 100); }
