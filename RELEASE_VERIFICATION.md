# SharkNet v3.2.0 — Release Verification

- **SharkNet version:** 3.2.0
- **Build date:** 2026-09-17 (Africa/Cairo)
- **Installer:** `installer_output\SharkNet-Setup-3.2.0.exe`
- **Installer size:** 24,785,122 bytes (23.64 MB)
- **Installer SHA-256:** `bfc40eb7386e866e247daf059ee4b4ff02e05031e8c9ff52808e8a4ca3c697d4`
- **Frozen app:** `dist\SharkNet\SharkNet.exe` — FileVersion / ProductVersion **3.2.0.0**
- **Source branch / commit:** N/A — not a git repository (see `HANDOFF.md`); built from the
  validated working tree.

## Version consistency (all authoritative locations = 3.2.0)

| Location | Value |
|---|---|
| `backend/server.py` `SHARKNET_VERSION` | `v3.2.0` |
| `frontend/index.html` `#verNum` + cache-bust | `v3.2.0` / `?v=3.2.0` |
| `frontend/toast.html`, `frontend/js/e-modals.js` | `?v=3.2.0`, fallback `v3.2.0` |
| `installer.iss` `AppVersion` → output name | `3.2.0` → `SharkNet-Setup-3.2.0.exe` |
| `version_info.txt` FileVersion/ProductVersion | `3.2.0.0` |
| Frozen `SharkNet.exe` PE metadata | `3.2.0.0` |
| Frozen `_internal/frontend/index.html` | `v3.2.0` (no `3.1.0` present) |
| Frozen backend PYZ `SHARKNET_VERSION` | `v3.2.0` (no `v3.1.0`) |

## Test result

`python -m pytest` → **475 passed, 0 failed, 0 skipped, 0 xfailed** (6 pre-existing
FastAPI/scapy deprecation warnings, unrelated).

## Fresh-build (anti-stale) verification

- `SharkNet.exe` (19:24:45), `PYZ-00.pyz` (19:24:44), `SharkNet-Setup-3.2.0.exe`
  (19:24:56) — all newer than the last source edit; installer built from the fresh EXE.
- Stale-asset sweep: every frozen `_internal/frontend` file is ≥ its source (none stale).
- Frozen frontend content confirmed: `v3.2.0` throughout, notification host fix
  (`snReflow`, opaque `--bg-deep` ground), theme sync, `max 3`/queue, no `3.1.0`.
- Frozen backend PYZ (extracted bytecode) confirmed: `SHARKNET_VERSION=v3.2.0`;
  desktop-toast `toolwindow_exstyle` (clears `WS_EX_APPWINDOW`), `ground_for`,
  `set_theme`; `settings.seed_initial_language`; `diagnostics.snapshot`/`performance_check`;
  `tray.on_cut_others`/`on_uncut_others`; defender identity re-key fix
  (`restore_device`/`recompute_effective`).
- No loose/stale backend `.py` shadows the PYZ.

## Validation summary (labels are precise; not upgraded without evidence)

| Capability | Status |
|---|---|
| Automated test suite (475) | **AUTOMATED VERIFIED** |
| ALLOW / LIMIT / CUT / HARD CUT semantics; self/gateway protection; token-bucket lifecycle; ARP cleanup idempotency; identity re-key | **STATICALLY VERIFIED** (full engine audit + unit tests) |
| Desktop notifications: dark+light, live theme switch, 1/2/3 stacking, queue, host hides when empty, no taskbar button / hover thumbnail / Alt+Tab entry (`WS_EX_APPWINDOW` cleared on the live HWND), no white/scrollbar/black-bar | **WINDOWS VERIFIED** (real desktop pixels + live-HWND inspection this session) |
| Settings: dark/light, EN + Arabic RTL; SharkNet-styled Language/Appearance/close-X; Diagnostics & Performance (live values, Run Perf Check, Copy) | **WINDOWS/BROWSER VERIFIED** |
| Installer: compiles; application-language page (5 locales); seed → first launch; upgrade preserves language/theme (backend guard) | **STATICALLY + BROWSER VERIFIED**; clean-install/upgrade run-through **NOT RUNTIME-VERIFIED** |
| Live-LAN packet enforcement (ALLOW/LIMIT/CUT/HARDCUT/domain/service against a real device); ARP restore on a live target | **NOT RUNTIME-VERIFIED** (no designated owned test device driven this session) |
| Performance (CPU/RAM/throughput/latency under load; diagnostics overhead) | **NOT RUNTIME-BENCHMARKED** |

## Full audit — defects found & fixed

1. **Passive same-IP identity re-key (MAJOR, fixed).** `backend/engine/defender._discover`
   updated `online/last_seen` for a known IP but never re-keyed the MAC. If a CUT/HARD CUT
   device left and DHCP reassigned its IP to a new device before a full rescan, the
   IP-keyed gateway poison could blackhole the new (never-cut) device's inbound traffic.
   **Fix:** on a non-gateway known IP whose observed MAC differs, re-key to the new MAC and
   reset enforcement/observation to neutral, then un-poison immediately (the gateway is
   excluded — guarded by dedicated gateway-spoof detection). Regression tests added
   (`tests/test_defender.py`). Full suite green.

No other release-blocking defects were found. Two non-blocking minors are documented in
the final report (self-healing lock-free `blocked_ips` `KeyError` → drops one packet; a
cosmetic IP-diff transition toast).

## Historical artifacts preserved

- `installer_output\SharkNet-Setup-3.0.0.exe` — intact (unchanged).
- `installer_output\SharkNet-Setup-3.1.0.exe` — intact (unchanged).
- `SharkNet-Setup-3.2.0.exe` — new, separate artifact.

## Not runtime-verified (explicit)

- Live-LAN enforcement/observation against a real device, and ARP restore on a live target.
- Installer clean-install and upgrade run-through (launch, language reaches first run,
  upgrade preserves existing language/theme).
- Performance benchmarks under real traffic.

These require Administrator elevation, the Npcap driver, and a designated owned test
device on a real LAN, which were not driven in this session. They are missing physical
tests, not observed failures.
