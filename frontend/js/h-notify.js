// SharkNet · notification component (V3.1)
// -----------------------------------------------------------------------------
// ONE visual component, TWO hosts:
//   * the main window  -> in-app stack, bottom-right inside the app
//   * the desktop toast window (toast.html) -> same markup/CSS, bottom-right of
//     the Windows work area
// so a notification looks identical whether SharkNet is in front or in the tray.
//
// This module renders only. It never decides WHICH host is used — the backend
// NotificationRouter already made that choice, and it sends a notice to exactly
// one of them. There is no second notification pipeline here.
// -----------------------------------------------------------------------------
(function () {
  "use strict";

  var MAX_VISIBLE = 3;      // never flood the UI; the rest queue
  var MAX_QUEUE = 24;       // bounded backlog — a pathological storm drops the
                            // OLDEST waiting card rather than growing without limit
  var DEFAULT_MS = 5000;    // informational auto-dismiss

  var queue = [];
  var visible = 0;

  // category -> glyph from the shared SVG registry (a-core.js)
  var ICONS = {
    new_device: "antenna",
    device_offline: "wifi",
    device_online: "wifi",
    cut: "ban",
    hardcut: "ban",
    limit: "zap",
    domain_block: "ban",
    service_block: "ban",
    monitor_started: "eye",
    monitor_stopped: "eye",
    speedtest: "chart",
    security: "shield",
  };

  function host() {
    return document.getElementById("toasts");
  }

  // Fire the empty hook when the stack has fully drained (no visible cards and
  // nothing queued). The desktop toast host (toast.html) uses this to hide its
  // frameless window so no ghost rectangle/shadow lingers; the in-app host does
  // not define it, so this is a no-op there.
  function notifyIfEmpty() {
    if (visible <= 0 && queue.length === 0) {
      try { if (typeof window.snOnEmpty === "function") window.snOnEmpty(); } catch (e) {}
    }
  }

  // Ask the desktop host to re-fit its native window to the current stack, so it
  // grows upward / shrinks from the top and never shows a blank host strip. The
  // in-app host does not define snReflow, so this is a no-op there.
  function reflowHost() {
    try { if (typeof window.snReflow === "function") window.snReflow(); } catch (e) {}
  }

  // `icon()` lives in a-core.js; the desktop window loads it too. Degrade to no
  // glyph rather than throwing if a host ever omits it.
  function glyph(name) {
    try {
      if (typeof window.icon === "function") return window.icon(name, "sn-ic");
    } catch (e) {}
    return "";
  }

  function build(n) {
    var el = document.createElement("div");
    el.className = "sn-toast" + (n.kind ? " " + n.kind : "");
    if (n.category) el.setAttribute("data-cat", n.category);

    var ic = document.createElement("span");
    ic.className = "sn-ico";
    ic.setAttribute("aria-hidden", "true");
    ic.innerHTML = glyph(n.icon || ICONS[n.category] || "info");

    var txt = document.createElement("div");
    txt.className = "sn-txt";
    var ti = document.createElement("div");
    ti.className = "sn-title";
    ti.textContent = n.title || "";          // textContent: never HTML-inject
    txt.appendChild(ti);
    // body may carry several short lines ("label\n192.168.0.5")
    String(n.body == null ? "" : n.body).split("\n").forEach(function (line) {
      if (!line) return;
      var b = document.createElement("div");
      b.className = "sn-body";
      b.textContent = line;
      txt.appendChild(b);
    });

    var x = document.createElement("button");
    x.className = "sn-x";
    x.type = "button";
    x.textContent = "✕";
    try { x.setAttribute("aria-label", window.t ? window.t("common.close") : "Close"); } catch (e) {}

    el.appendChild(ic);
    el.appendChild(txt);
    el.appendChild(x);
    return { el: el, x: x };
  }

  function show(n) {
    var h = host();
    if (!h) return;
    if (visible >= MAX_VISIBLE) {           // queue rather than flood
      queue.push(n);
      if (queue.length > MAX_QUEUE) queue.shift();   // bounded: drop the oldest
      return;
    }
    visible++;
    var made = build(n);
    var el = made.el;
    h.appendChild(el);
    // Force a reflow so the transition has a start state, then enter. A
    // requestAnimationFrame here is NOT reliable: rAF is throttled (or never
    // fires) while the window is hidden/backgrounded, which would leave the card
    // stuck at opacity 0 — invisible but still occupying a visible slot.
    void el.offsetWidth;
    el.classList.add("in");
    reflowHost();                           // grow the desktop host to fit the new card

    var ms = typeof n.ms === "number" ? n.ms : DEFAULT_MS;
    var remaining = ms;
    var startedAt = Date.now();
    var timer = null;
    var done = false;

    function dismiss() {
      if (done) return;
      done = true;
      clearTimeout(timer);
      el.classList.remove("in");
      el.classList.add("out");
      setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
        visible--;
        if (queue.length) show(queue.shift());   // promote (its add re-fits the host)
        else if (visible <= 0) notifyIfEmpty();   // stack drained -> hide desktop host
        else reflowHost();                        // shrink host to the remaining cards
      }, 200);
    }
    function resume() {
      clearTimeout(timer);
      if (remaining <= 0) return dismiss();
      startedAt = Date.now();
      timer = setTimeout(dismiss, remaining);
    }
    // hover pauses the countdown; leaving continues the REMAINING time
    el.addEventListener("mouseenter", function () {
      clearTimeout(timer);
      remaining -= Date.now() - startedAt;
    });
    el.addEventListener("mouseleave", resume);

    made.x.addEventListener("click", function (e) {
      e.stopPropagation();                  // dismiss only; never touches state
      dismiss();
    });
    el.addEventListener("click", function () {
      try { if (typeof n.onclick === "function") n.onclick(); } catch (e) {}
      dismiss();
    });

    resume();
    return dismiss;
  }

  function clear() {
    queue.length = 0;
    var h = host();
    if (h) h.innerHTML = "";
    visible = 0;
    notifyIfEmpty();                              // stack cleared -> hide desktop host
  }

  window.SNNotify = { show: show, clear: clear, MAX_VISIBLE: MAX_VISIBLE };
})();
