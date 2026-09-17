/*
 * Browser-level regression: "provider click != server block" (Phase 7, item 14).
 *
 * There is NO browser-automation harness wired into the Python suite, so this is
 * a repeatable console test: run SharkNet (demo is fine), open the DevTools
 * console on the SharkNet page, paste this, and read the JSON result.
 *
 * PROVES:
 *   - opening a device's details and switching through EVERY tab (Info, Services,
 *     Domains, Visited sites, History) makes ONLY read-only GET calls — zero
 *     block/rule/cut mutations (viewing/selecting a provider never blocks).
 *   - the Visited-sites tab has NO block controls.
 *   - clicking a service chip under "Block services" makes EXACTLY ONE
 *     POST /api/services/block and shows the toast "✓ Service blocked" (the word
 *     is "Service", never "Server").
 *
 * EXPECT: blockOrRuleCallsFromViewing = [], visitedTabHasBlockControls = false,
 *         chipClickCalls = ["POST /api/services/block"], chipToast starts "✓ Service blocked".
 */
(async () => {
  const net = [];
  const _fetch = window.fetch;
  window.fetch = function (u, o) { net.push((o && o.method || "GET") + " " + u); return _fetch.apply(this, arguments); };
  const toastBodies = () => Array.from(document.querySelectorAll("#toasts .toast .tt")).map((t) => t.textContent);
  const dev = lastDevices.find((d) => !d.is_self && !d.is_gateway);

  // 1) navigate every tab — must be read-only
  showDevice(dev.ip, dev.ip, false);
  for (const t of ["info", "svc", "dom", "vis", "hist"]) {
    document.querySelector(`.dtabs button[data-t="${t}"]`).click();
    await new Promise((r) => setTimeout(r, 250));
  }
  document.querySelector('.dtabs button[data-t="vis"]').click();
  await new Promise((r) => setTimeout(r, 250));
  const visitedTabHasBlockControls = !!document.querySelector("#dBody .pset, #dBody .chip.block");
  const blockOrRuleCallsFromViewing = net.filter((c) => /block|rule|cut/.test(c));

  // 2) explicit service block — exactly one POST, correct toast
  document.querySelector('.dtabs button[data-t="svc"]').click();
  await new Promise((r) => setTimeout(r, 300));
  net.length = 0;
  document.querySelector("#dBody .pset").click();
  await new Promise((r) => setTimeout(r, 600));

  window.fetch = _fetch;
  const result = {
    blockOrRuleCallsFromViewing,
    visitedTabHasBlockControls,
    chipClickCalls: net.slice(),
    chipToast: toastBodies()[0] || "",
    PASS: blockOrRuleCallsFromViewing.length === 0 &&
          visitedTabHasBlockControls === false &&
          net.length === 1 && net[0] === "POST /api/services/block" &&
          (toastBodies()[0] || "").startsWith("✓ Service blocked"),
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
})();
