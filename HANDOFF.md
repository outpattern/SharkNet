# SharkNet Handoff (V3.1 in progress)

Last updated: 2026-09-17 (Africa/Cairo). Everything marked **Verified** was checked
against the actual working tree on this machine on that date.

## 0. TL;DR for the next account

- Project root: `C:\Users\ODS\Downloads\My Work\01- SharkNet\sharknet`
- **This directory is NOT a git repository** — no `.git` here or in any parent.
  Version history is kept as **folder/installer copies** under
  `..\sharknet versions\`. Do not run `git` commands expecting a repo; there is
  nothing to branch, commit, reset or push. **Every file in the tree is current
  work** — treat all of it as uncommitted and preserve it.
- V3.1 **backend** (notifications, settings, single-instance, server wiring,
  5-locale strings) — **done**.
- V3.1 **tray + `run.py` runtime integration**, **frontend settings UI**,
  **background status indicator**, and **pystray/Pillow packaging** — **done this
  session** (see §5).
- **Verified today: `383 passed`** (`python -m pytest tests/`), 359 i18n keys in
  each of the 5 locales. (320 -> 325 audit regressions -> 383 after the UX + notification pass.)
- **A full release audit was run — see `V3.1 RELEASE AUDIT` at the end of this
  file.** It found and fixed 3 real defects and lists the exact blockers.
- **Not done: real Windows desktop validation** of the tray/GUI, and packet-level
  enforcement on live LAN devices. Those are the remaining gates (§7, audit §B/§D).
- **The stale-artifact blocker is RESOLVED**: `dist\` and
  `SharkNet-Setup-3.1.0.exe` were rebuilt after every fix and verified to contain
  them (see the UX + notification pass at the end of this file).
- The V3.0.0 installer is preserved at `installer_output\SharkNet-Setup-3.0.0.exe`
  (also in `..\sharknet versions\`). Do not overwrite or delete it.

## 1. Project purpose

SharkNet is a Windows desktop LAN-control / network-security tool (NetCut /
SelfishNet style): discover devices on the local network, then
**ALLOW / LIMIT / CUT** them, block domains and services, or **Monitor** (observe)
a device — from a multi-language dark/light UI.

Enforcement is **one** mechanism: native **Npcap** packet I/O driven by **ARP
spoofing / MITM**. No kernel driver, no WinDivert/pydivert, and **no Scapy at
runtime** (Scapy is a test-only "golden oracle" — Gate 6.4).

The product model keeps three concepts strictly separate:
- **Enforcement** — ALLOW / LIMIT / CUT / HARD CUT / domain-block / service-block.
- **Observation** — Monitor + Visited Sites (never implies CUT/LIMIT/BLOCK).
- **Interception** — a device is ARP-MITM'd if it is *enforced* **or** *monitored*.

### Constraints that MUST be preserved

- Preserve `ALLOW` / `LIMIT` / `CUT` / `HARD CUT` behavior and semantics.
- **Notifications and the tray are presentation/UX only** — they must never change
  or duplicate enforcement decisions. Enforced in code: `backend/tray.py` and
  `backend/engine/notifications.py` both carry an explicit layer-boundary docstring
  and touch no policy; the tray's only write is a notification-policy setting.
- Reuse the **existing monitoring/state flow** (`backend/state.py`,
  `backend/engine/monitor.py`, `backend/engine/policy.py`). No parallel state
  engine — notification transitions are derived by diffing the snapshot the pump
  already produces.
- Keep **cleanup/shutdown idempotent** (`backend/server.py:cleanup`, Phase-12
  ordering: notifications stop first).
- Preserve existing V3.0.0 release artifacts.
- **Do not claim Windows tray/GUI/notification behavior is tested unless you
  actually exercise it on Windows.** The automated suite uses a fake pystray and
  fake window; it proves the logic, not the OS integration.

## 2. Architecture (engine ⟂ UI)

- `run.py` — desktop entry point: elevation, Npcap check, single-instance guard,
  server thread, tray, PyWebView window, coordinated shutdown (`AppRuntime`).
- `engine_service.py` — same server, headless, `http://127.0.0.1:8734`.
- `backend/server.py` — FastAPI + WebSocket API; V3.1 settings/notification wiring,
  `/api/settings`, `/api/runtime`, idempotent `cleanup()`.
- `backend/engine/` — networking only, no UI imports.
- `backend/state.py`, `db.py`, `settings.py`, `single_instance.py`, `tray.py`,
  `localization.py` — app-level state, persistence and the V3.1 background runtime.
- `frontend/` — static UI (`index.html`, `js/*.js`, `css/*.css`, `i18n/*.json`)
  served by the backend and hosted in the PyWebView window.

## 3. Setup, run, and test commands (verified)

Environment used to verify (2026-09-17): **Python 3.11.2**, pytest 9.1.1,
scapy 2.7.0, pystray 0.19.5, Pillow 12.3.0.

```powershell
pip install -r requirements.txt          # fastapi, uvicorn[standard], pywebview, psutil, pystray, pillow
pip install -r requirements-dev.txt      # adds scapy + pytest (test-only)

python run.py                            # desktop app (needs Admin + Npcap on real HW)
python engine_service.py                 # headless engine at http://127.0.0.1:8734
python -m pytest tests/ -q               # full suite  (VERIFIED: 383 passed)

powershell -ExecutionPolicy Bypass -File build.ps1   # PyInstaller -> Inno Setup
```

Useful during development:
- `SHARKNET_DEMO=1 SHARKNET_PORT=8791 python engine_service.py` — serves the real
  UI with fake devices, no Admin and no Npcap needed. This is how the settings
  panel was visually validated (§6).
- `SHARKNET_DIAG=1 python run.py` — foreground server, no elevation/webview.

## 4. Repository state (verified)

- **No VCS.** `git rev-parse` fails at the project root and all parents. There is
  no branch, commit or remote to record.
- `.gitignore` exists (prepared for an eventual repo) and ignores `build/`,
  `dist/`, `installer_output/`, `__pycache__/`, `.pytest_cache/`, venvs, `*.log`,
  `active_spoof.json`, and any bundled `vendor/npcap*.exe`.

### Discrepancies vs. the original historical checkpoint (files win)

1. The checkpoint named `engine/notifications.py`, `settings.py`,
   `single_instance.py` at the repo root. **Actual paths are under `backend/`.**
2. The checkpoint assumed a git checkout. There is **no git repo**.
3. The checkpoint said "32 new V3.1 tests" implying one file. **Actually 32 =
   `test_v31_runtime.py` (12) + `test_notifications.py` (20).** An earlier draft of
   this handoff mis-stated that as 32 in one file; corrected here.

## 5. What is IMPLEMENTED (verified)

### Backend V3.1 (pre-existing)

- `backend/engine/notifications.py` — `NotificationManager` (`MANAGER` as
  `NOTIFY`), `DEFAULT_POLICY`, `feed()`, `start()`/`stop()`, `set_policy()`.
  Bounded queue, daemon worker, failures swallowed. **Added this session:**
  `set_dispatch()` / `set_translator()` public injection points.
- `backend/settings.py` — `DEFAULTS` (`locale`, `tray`, `notifications`),
  `load()`/`save()` (deep-merge + bool coercion, atomic write),
  `apply_autostart()` (HKCU Run key).
- `backend/single_instance.py` — loopback-socket guard; second launch pings the
  first to restore its window.
- `backend/server.py` — single event tap feeds `NOTIFY` even with no UI client;
  `/api/settings`; `_notif_translator`; startup/shutdown ordering.

### Added this session

- **`backend/localization.py`** (new) — one backend-side loader for the bundled
  `frontend/i18n/*.json`, used by both notification text (`notif.`) and the tray
  menu (`tray.`). `server._notif_translator` now delegates to it, so there is a
  single locale source.
- **`backend/tray.py`** (new) — `TrayController`: icon from `assets/sharknet.ico`
  via Pillow (with a generated fallback), menu **Open · Notifications (checkbox) ·
  Exit**, `notify()` balloon sink, `is_live()`, idempotent `stop()`.
  **pystray/Pillow are optional**: if the import fails, `start()` returns `False`
  and SharkNet runs windowed exactly as V3.0. Backend + image are injectable, so
  it is fully testable headlessly.
- **`backend/server.py`** — `apply_settings_patch()` is now THE single settings
  write path (the HTTP endpoint and the tray both call it, so they cannot drift);
  `SETTINGS_LISTENERS` so the tray checkbox re-syncs after a UI change;
  `RUNTIME` + **`GET /api/runtime`** reporting launcher facts (`tray`, `windowed`,
  `background`).
- **`run.py`** — `AppRuntime` class:
  - single-instance guard claimed after elevation, released on every exit path;
    a second launch calls `show_window()` on the first;
  - **close-to-tray** via the pywebview `closing` event (returns `False` to veto),
    gated on `settings.tray.keep_running_on_close` **and** a live tray;
  - **restore** (`show`/`restore` + Win32 `SetForegroundWindow`);
  - tray **Exit** destroys the window and marks a real quit;
  - **one idempotent `shutdown()`**: tray → notification sink → `server.cleanup()`
    → guard release, guarded by a lock + flag so all paths run it exactly once;
  - `NOTIFY.set_dispatch(tray.notify)` — the only OS-toast sink.
- **Frontend** — `frontend/js/g-settings.js` (new) settings panel + background
  status pill; header **⚙ Settings** button and `#bgStatus` pill in `index.html`;
  switch/panel/pill styles appended to `frontend/css/3-features.css` (logical
  properties, so RTL mirrors with no extra rules).
- **i18n** — 37 new keys **in all five locales**; each file now has **334 keys**
  (was 297). Keys: `tray.*` (3, read by the backend), `settings.*` (17),
  `settings.cat.*` (12), `status.background*` (4). The tray tooltip is the product
  name and deliberately has no key.
- **Packaging** — `requirements.txt` adds `pystray>=0.19.4`, `pillow>=10.0.0`;
  `sharknet.spec` adds `collect_all` for pystray/PIL plus explicit hidden imports
  (`pystray._win32`, `PIL.IcoImagePlugin`, …) and the new backend modules.
  `PIL._tkinter_finder` is deliberately excluded (tkinter is in `excludes`).

## 6. Test results (ACTUALLY VERIFIED 2026-09-17)

`python -m pytest tests/ -q` → **`325 passed, 6 warnings`** (320 at the end of the
implementation session, +5 regression tests added by the release audit).

| file | tests |
|---|---|
| `tests/test_v31_runtime.py` | 12 |
| `tests/test_notifications.py` | 20 |
| `tests/test_v31_tray.py` (**new**) | 31 |

`tests/test_v31_tray.py` covers, with a **fake pystray and a fake window**: menu
construction and ordering, tray absence being non-fatal, idempotent `stop()`,
balloon dispatch + failure swallowing, the settings-backed toggle (including a
failing store), tray menu localization in all 5 locales, the `localization`
contract, `NotificationManager.set_dispatch` routing, `AppRuntime` close-to-tray /
quit / no-tray-honesty / tray-exit / **idempotent shutdown** (cleanup and guard
release exactly once), and the `/api/runtime` + `SETTINGS_LISTENERS` contracts.

`tests/test_i18n.py` was extended: the new dynamic keys (`settings.cat.*`,
`status.background*`, `tray.*`) are registered in `DYNAMIC_PREFIX_KEYS`, and
`tray.notifications`/`settings.notifications` are whitelisted as legitimately
identical in French.

Warnings are pre-existing and non-fatal: FastAPI `on_event` deprecation and a
scapy DNS-field deprecation. A reasonable future cleanup is migrating
`@app.on_event` to lifespan handlers.

### Also verified by hand (browser, not Windows GUI)

The settings panel was rendered against a live `SHARKNET_DEMO=1` server and
checked in a real browser:
- dark, light, and **Arabic RTL** layouts all render correctly (switches, knob
  travel direction, alignment, warning banner all mirror properly);
- a full save round-trip: toggling "Enable notifications" persisted to the server,
  disabled the dependent controls, and toasted "Settings saved";
- disabled-state logic is right (tray options greyed at 0.45 opacity when no tray);
- all 12 category toggles match `DEFAULT_POLICY`;
- switching the UI language pushed `locale` to the backend, so background
  notifications follow the UI language;
- with no tray the pill correctly reads **"Background off"** and the panel shows
  "The system tray is unavailable…" — the UI never claims a background mode the
  launcher didn't start.

**This is browser rendering of the frontend, NOT Windows desktop validation.**

## 7. What is INCOMPLETE — exact next steps

### 7.1 Real Windows desktop validation (the remaining gate)

Nothing below has been exercised on a Windows desktop. Run `python run.py` as
Administrator on a machine with Npcap and confirm, by hand:

- tray icon appears, with the correct icon and the "SharkNet" tooltip;
- menu **Open / Notifications / Exit** works; double-click opens the window;
- the **Notifications** checkbox reflects and flips the setting, and stays in sync
  when the same toggle is changed in the UI (via `SETTINGS_LISTENERS`);
- **close-to-tray**: X hides the window, the engine keeps enforcing, the pill in
  the UI reads "Background on";
- **restore** from the tray, and from launching a **second instance** (must not
  start a second engine);
- a real OS **balloon** appears for a real event (e.g. cut a device) and is
  localized when the UI language is Arabic/French/etc.;
- **Exit** from the tray and X-with-background-off both fully quit, restore ARP,
  and leave no stray process or tray icon;
- dark/light themes and Arabic RTL in the real WebView2 window.

Two specific risks to check first:
- `window.events.closing` returning `False` to veto the close is **pywebview
  version dependent**. `run.py` logs a warning and falls back to V3.0 behavior if
  the event is unavailable — confirm which path the installed pywebview takes.
- `pystray` on Windows needs its own message loop; it runs on a daemon thread
  alongside the pywebview loop. Confirm both coexist and that Exit tears down cleanly.

### 7.2 Packaging verification

- Run `build.ps1` and confirm the frozen build actually gets a tray (the spec
  changes are untested — a frozen app that silently loses pystray would fall back
  to windowed mode).
- Bump `AppVersion` in `installer.iss` and `version_info.txt` to `3.1.0` only when
  releasing.
- Consider bumping the `?v=3.0.0` cache-bust query strings in `index.html` to
  `3.1.0` at release so the new CSS/JS are not served stale.
  (`g-settings.js` is already `?v=3.1.0`.)

### 7.3 Release preparation (only after 7.1 and 7.2 pass)

- Build the 3.1.0 installer with the existing process.
- Keep the V3.0.0 installer/artifacts intact.
- Record the new artifact's SHA-256 and the test evidence.

## 8. Known issues / risks

- FastAPI `on_event` handlers are deprecated (warnings only).
- Close-to-tray depends on pywebview's cancellable `closing` event (see §7.1).
- Tray + WebView2 message loops coexisting is unproven on real Windows.
- Frozen builds can silently lose pystray/Pillow → no tray. The app degrades
  gracefully, but the tray would just be missing; check after the first build.
- Arabic/RTL verified in a browser, not in WebView2.
- **No VCS** means no safety net — copy the folder before large edits.

## 9. Missing context (ask the user if needed)

- Whether SharkNet will be put under git, and the canonical remote.
- Signing certificate / publisher identity for the installer (currently unsigned,
  `AppPublisher=SharkNet`).
- Target Npcap version to bundle (`build.ps1` fetches `npcap-1.82.exe`).
- Whether the 3.1.0 tray/notification UX has a spec beyond this handoff (none
  found in-workspace; `COMPETITIVE_AUDIT_v3.0.md` is a v3.0 audit).

## 10. Transferring to another machine / account

Because there is **no git repo**, transfer the **whole working directory** as a
filesystem copy — a clone/bundle/patch would lose everything.

### Copy

- The entire `sharknet\` project directory (all source, `frontend/`, `backend/`,
  `tests/`, `assets/`, `i18n/`, `*.spec`, `*.iss`, `*.ps1`, `requirements*.txt`,
  `version_info.txt`, `HANDOFF.md`, `NEXT_ACCOUNT_PROMPT.md`).
- `installer_output\SharkNet-Setup-3.0.0.exe` (preserved release artifact).
  Optionally the `..\sharknet versions\` archive.

### Exclude (secrets / regenerable / account data)

- Any `.env` / credential files, API keys, tokens, cookies, credential stores.
- Claude/ChatGPT/account session or auth caches. **Do not export account auth.**
- Virtualenvs (`.venv/`, `venv/`), `__pycache__/`, `.pytest_cache/`,
  `.mypy_cache/`, `.ruff_cache/`.
- Regenerable build outputs `build/`, `dist/`, `*.log`, `active_spoof.json`.
  (Keep the 3.0.0 installer per above.)
- `%LOCALAPPDATA%\SharkNet\` (runtime settings/log/db) — per-machine user data,
  not source. It is recreated at defaults on first run.

After copying, run `pip install -r requirements-dev.txt` then
`python -m pytest tests/` and confirm **383 passed** before continuing.

---

# V3.1 RELEASE AUDIT — 2026-09-17

Status legend: **VERIFIED** (actually exercised) · **PARTIALLY VERIFIED** ·
**NOT TESTED** · **FAILED**. Nothing is marked VERIFIED on code reading alone.

## A. Baseline actually tested

| item | value |
|---|---|
| Source version | `SHARKNET_VERSION = "v3.1.0"`, `installer.iss AppVersion 3.1.0` |
| Automated suite | **325 passed**, 6 warnings (`python -m pytest tests/ -q`) |
| Frozen exe used for manual tests | `dist\SharkNet\SharkNet.exe`, FileVersion 3.1.0.0, 9.56 MB, built 13:34 |
| Installer built | `installer_output\SharkNet-Setup-3.1.0.exe`, 23.3 MB |
| V3.0.0 artifact | SHA-256 `428f716c…03b2` — **unchanged**, verified before and after every build |

The suite went 320 → 325: +5 regression tests for the domain defect found in this
audit (§C-1). No test was removed or weakened.

## B. BLOCKERS before 3.1.0 can be called validated

1. **The current frozen build and installer contain STALE code.**
   `dist\SharkNet\SharkNet.exe` is timestamped 13:34, the `domains.py` fix landed at
   14:01, and the installer was compiled at 14:04 from that stale bundle. Confirmed by
   reading the frozen PYZ: the fixed `normalize_domain` is **not** in the artifact.
   Root cause is §C-2. **Fix: exit SharkNet, re-run `build.ps1`, re-verify.**
2. **A SharkNet instance (PID 4116) is still running and cannot be stopped from an
   unelevated session** — it runs elevated, so `Stop-Process` and `WM_CLOSE` both
   return Access Denied under Windows UIPI. It must be exited from its tray icon.
   Doing so also supplies the outstanding tray-Exit validation (§F).
3. Real packet-level enforcement was **NOT** exercised on live LAN devices (§D).

## C. Issues found and fixed in this audit

### C-1 Pasted URLs produced silently dead block rules — FIXED
`normalize_domain()` is the single canonical path, but it never reduced a URL to a
host. `https://youtube.com/` was stored verbatim; `is_blocked()` normalises both
sides identically, so the entry could never match observed traffic. The UI showed an
**active rule that blocked nothing** — a silent failure in a security tool.

Fix (`backend/engine/domains.py`): strip scheme, path/query/fragment, userinfo and
port before the existing lowercase / `www.` / trailing-dot handling, and reject hosts
containing whitespace instead of storing a dead rule. Idempotent; plain hostnames
normalise exactly as before. 5 regression tests added to `tests/test_normalization.py`.

### C-2 `build.ps1` could ship the previous version's code — FIXED
`$ErrorActionPreference` does not apply to native commands, so a failed PyInstaller
run fell through and Inno Setup packaged whatever stale `dist\` remained — reporting
a **successful build**. Reproduced exactly: PyInstaller exits 1 with
`PermissionError: Access is denied: dist\SharkNet\SharkNet.exe` when the app is
running, and the build still produced an installer.

Fix (`build.ps1`): explicit `$LASTEXITCODE` checks after pip / PyInstaller / ISCC, a
post-build existence check, and an upfront guard that refuses to build while SharkNet
is running. Verified: the guard aborts with a clear message and leaves existing
artifacts untouched.

### C-3 Installer summary showed a blank destination — FIXED
Inno defaults `DisableDirPage=auto`, which hides the location page once a previous
version is installed; `MemoDirInfo` is then empty and the Ready page showed a gap.
Fixed with `DisableDirPage=no` plus an `{app}` fallback in `UpdateReadyMemo`.
Verified visually.

## D. Enforcement engine

Exercised through the **real** `policy.decide()` classifier, the real `STATE` devices
and the real `_apply_device_rule()` API helper. No ARP spoofing was performed, so no
third party's traffic was touched.

| mode | managed | intercepted | up | down | result |
|---|---|---|---|---|---|
| ALLOW | False | False | pass | pass | **VERIFIED** (decision layer) |
| LIMIT | True | True | limit | limit | **VERIFIED** (decision layer) |
| CUT | True | True | drop | drop | **VERIFIED** (decision layer) |
| HARD CUT | True | True | drop | drop | **VERIFIED** (decision layer) |
| ALLOW + domain block | True | True | forward (blocked domain → drop) | — | **VERIFIED** — never a full cut |
| Monitor only | False | True | forward | — | **VERIFIED** — observation ≠ enforcement |

**HARD CUT vs CUT, as implemented:** both return `DROP` from `action_for()`. The
difference is in `forwarder._handle` — a `hardcut` device is blackholed at the
earliest point after identification and returns **before** byte counting, DNS/IP
pinning, domain parsing and observation, so it gets zero access **and** is not
observed (its live traffic reads zero). `CUT` still counts bytes, so a cut device
keeps showing its blocked attempts. `_apply_device_rule` zeroes `down_bps/up_bps` for
`allow` and `hardcut` only. The CUT path is untouched by the hardcut branch.

**NOT TESTED (packet level):** that packets are physically dropped on the wire for
CUT / HARD CUT; that the token bucket achieves a given kbps for LIMIT; LIMIT
threshold boundaries under real load; ARP restore against real devices; and
Windows-restart recovery while enforcing. Each requires ARP-spoofing real devices on
the user's LAN and cutting someone's connectivity, which is outside "controlled
testing on this machine".

## E. Transition matrix — all 12, **VERIFIED** (decision layer)

Each transition deliberately left a domain rule set in the source state, to catch
stale carry-over.

| transition | mode | managed | non-blocked traffic | blocked domain | stale rate limit |
|---|---|---|---|---|---|
| allow→limit | limit | True | limit | drop | no |
| allow→cut | cut | True | drop | drop | no |
| allow→hardcut | hardcut | True | drop | drop | no |
| limit→allow | allow | True* | forward | drop | no |
| limit→cut | cut | True | drop | drop | no |
| limit→hardcut | hardcut | True | drop | drop | no |
| cut→allow | allow | True* | forward | drop | no |
| cut→limit | limit | True | limit | drop | no |
| cut→hardcut | hardcut | True | drop | drop | no |
| hardcut→allow | allow | True* | forward | drop | no |
| hardcut→limit | limit | True | limit | drop | no |
| hardcut→cut | cut | True | drop | drop | no |

\* correct: a domain rule was deliberately left set, and `allow + blocks` is managed
by design. With no rules, `→allow` leaves the managed set (verified separately).

**Idempotency:** 25 × (hardcut→allow→cut→allow) ends at `mode=allow, managed=False,
blocked=[]` with no accumulation. **VERIFIED**.

## F. Other audit areas

| area | status | evidence |
|---|---|---|
| Domain normalization / matching | **VERIFIED** | exact, subdomain, deep subdomain, case, label boundary (`example.com.evil.com` must not match), suffix (`notexample.com`), multi-domain, duplicate collapse, invalid input rejected, URL forms (after C-1) |
| Domain precedence | **VERIFIED** | device ∪ network union; a device ALLOW cannot override a NETWORK block |
| 12 categories | **VERIFIED** | all 12 present; every default matches `DEFAULT_POLICY`; `settings.DEFAULTS` has no extra/missing category; `enabled`/`sound` masters present |
| Notification independence | **VERIFIED** | with notifications disabled, CUT still drops and 0 notifications emit; enabling changes no enforcement decision |
| Notification storm control | **VERIFIED** | 30 identical monitoring ticks after one change → 0 extra notifications |
| Settings persistence (frozen app) | **VERIFIED** | POST `/api/settings` → read back → confirmed on disk in `%LOCALAPPDATA%\SharkNet\settings.json` |
| `/api/runtime` honesty | **VERIFIED** | reports `tray:true, background:true` with a live tray; flipping `keep_running_on_close` flips `background` while `tray` stays true |
| Frontend round-trip, dark / light / Arabic RTL | **VERIFIED** (browser) | rendered against a live demo server; toggle persisted with toast; RTL mirrors correctly; no console errors |
| Single instance (frozen) | **VERIFIED** | second launch logged "already running — activating the existing window", exited; PID 4116 kept ports 8733/8734 |
| Close-to-tray (frozen) | **VERIFIED** | log: "close -> staying in the background (tray)"; process survived |
| Tray icon exists (frozen) | **VERIFIED** | two `SharkNet…SystemTrayIcon` windows enumerated; log "system tray: active" |
| Tray Open / Notifications toggle / Exit | **NOT TESTED** | elevated app + unelevated session → Windows UIPI blocks synthetic input (`PostMessage` → error 5) |
| No process remains after Exit | **NOT TESTED** | same reason — requires a human tray click |
| OS toast actually displayed | **NOT TESTED** | requires a real enforcement event plus a visible desktop session |
| Installer wizard UI | **VERIFIED** (visually) | every page opened and inspected: Welcome, Choose install location, Choose additional options, Ready, Installing, Finish, plus the dark title bar |
| Installer install + uninstall | **VERIFIED** (isolated AppId preview) | installed, launched, then silently uninstalled; directory and uninstall entry removed cleanly |
| Upgrade 3.0.0 → 3.1.0 | **NOT TESTED** | blocked by the stale-artifact issue (§B-1) |
| Windows restart behaviour | **NOT TESTED** | not performed on the user's machine |

## G. Installer notes

- Branding is derived, not invented: `make_installer_art.py` composites the real
  `assets/logo.png` over the app's own palette (values copied from
  `frontend/css/1-base.css :root`) and emits 4 DPI variants of each wizard image.
- The dark title bar uses `DwmSetWindowAttribute` — the same API `run.py` already
  uses for the app window. **Limitation:** needs Windows 10 build 17763+; older
  Windows keeps the native light caption and the wizard still works normally.
- Push buttons and the progress bar are deliberately left native: Windows visual
  styles own their painting and forcing colours there is brittle.
- "Start with Windows" is **not** offered by the installer on purpose — the app owns
  that setting (`settings.tray.start_with_windows` → HKCU Run). Exposing it in both
  places would let the two disagree.
- English only. Inno ships no official Arabic `.isl`; adding an unofficial one is the
  documented path if an Arabic setup UI is wanted.

## H. Assets still required (optional polish, non-blocking)

- `Orbitron` TTF — the app's brand font for headings. The artwork currently uses
  Segoe UI (the app's own body font) for the wordmark. Drop the TTF beside
  `make_installer_art.py` and reference it there for an exact match.
- A code-signing certificate: the app and installer are unsigned, so Windows
  SmartScreen warns on first run.

---

# V3.1 UX + NOTIFICATION PASS — 2026-09-17 (later session)

Status legend as above: **VERIFIED** (actually exercised) · **NOT TESTED**.

## A. Baseline and result

| item | value |
|---|---|
| Automated suite before | 325 passed |
| Automated suite after | **383 passed**, 6 warnings (`python -m pytest tests/ -q`) |
| New tests | +58 (`test_v31_ux.py` 28, `test_v31_notify_router.py` 30) |
| i18n keys per locale | 334 → **359** (all five locales equal) |
| Frozen exe | `dist\SharkNet\SharkNet.exe`, built 15:57:44 — **newer than every source file** |
| Installer | `installer_output\SharkNet-Setup-3.1.0.exe`, 23.6 MB, 15:57:58 |
| V3.0.0 artifact | SHA-256 `428f716c…03b2` — **still unchanged** |

**The stale-artifact blocker from the previous audit (§B-1) is RESOLVED.** Verified
by reading the frozen PYZ, not by assuming: `backend.notify_router`,
`backend.desktop_toast`, the domain URL fix and the SHARKmac Bluetooth filter are
all present in the shipped binary, and `build.ps1` now aborts rather than
packaging a stale `dist\`.

## B. What changed

### B-1 SHARKmac adapter filtering (Bluetooth removed)
`backend/engine/macadapter.py` now classifies adapters with `adapter_kind()` and
lists **Ethernet and Wi-Fi only**.

The trap this avoids: on Windows a Bluetooth PAN adapter reports
`InterfaceType = 6 (Ethernet)` and `MediaType = 802.3`, so any filter built on
those fields — or on the English display name — wrongly accepts it. The
authoritative signal is `NdisPhysicalMedium = 10`, backed by
`ComponentID = BTH\MS_BTHPAN`; the media string and the name are only fallbacks.

**VERIFIED on this machine's real hardware:** before = Wi-Fi, *Bluetooth Network
Connection*, Ethernet; after = Wi-Fi, Ethernet. Empty state added to the SHARKmac
modal (`smac.no_adapters`, all 5 locales) — it never falls back to Bluetooth.
SharkNet's **enforcement** interface list is untouched: that comes from
`netinfo.list_interfaces()` (ctypes/GetAdaptersAddresses), a different module,
and a test now pins that separation.

### B-2 Settings: drawer → centered desktop-style popup
The right-side drawer built earlier in this session was replaced by a centered
two-column popup (`frontend/js/g-settings.js`, `.sx*` rules in
`3-features.css`): fixed header, fixed left navigation (General · Notifications ·
Appearance · Language · Runtime), and a right pane that is the **only** scrolling
region. Notification categories are grouped (Device events / Network control /
Monitoring / Security & tools) instead of one long list.

**One source of truth preserved:** theme delegates to `applyTheme()`, language to
`setLang()` — the exact functions the header quick controls call — and every
persisted setting still writes through `POST /api/settings` →
`server.apply_settings_patch()`. The module holds no `localStorage` copy; a test
asserts this.

Header untouched apart from the gear: background pill, KB/s–Mbps, language,
lightning, theme, settings, heart all remain.

### B-3 Background pill restrained
New `--status-ok` token (dark `#46d09a`, light `#0f7a4a`) replaces the neon
`--success` for the running state, with a much softer halo, so it reads as a
status light instead of competing with the cyan brand accent. The pill still
follows **real runtime capability** (`/api/runtime.background`, which is
tray-gated), never the stored preference.

### B-4 ONE notification, one renderer (duplicate removed)
Root cause of the duplication: `handleEvent()` drew an in-app toast for
`new_device` **and** the NotificationManager dispatched a pystray balloon for the
same event.

New `backend/notify_router.py` — a presentation-only router:

```
NotificationManager.feed()      <- still the ONLY producer (no second engine)
          |
   NotificationRouter           <- picks exactly ONE renderer
    /              \
window visible   window hidden / minimised / tray
    |                   |
in-app toast      custom SharkNet desktop toast
(WS payload)      (native balloon ONLY if that renderer fails)
```

- Routing uses the **real** window state: `AppRuntime.set_visible()` is driven by
  show/hide plus pywebview's `minimized`/`restored`/`shown` events, and published
  on `/api/runtime.window_visible`. Never a saved preference.
- Burst grouping: `new_device` events inside ~1.2 s collapse into one notice
  ("5 new devices detected · 2 Private · 2 Unknown · 1 Router"). **Presentation
  only** — the router imports no state/enforcement module at all (test-enforced by
  AST inspection), so it structurally cannot merge or alter device events.
- Storm protection reuses the manager's existing transition diff; no second engine.
- `frontend/js/h-notify.js` is one card component shared by the in-app stack and
  the desktop window (`frontend/toast.html`), so both look identical: dark surface,
  **narrow cyan accent line** instead of the old full cyan border, icon chip, max
  **3** visible with the rest queued, hover pauses auto-dismiss and resumes the
  remaining time, × dismisses only that card.
- `backend/desktop_toast.py` is the frameless window: `WS_EX_NOACTIVATE` (never
  steals focus), `WS_EX_TOOLWINDOW` (hidden from taskbar and Alt+Tab), topmost,
  positioned in the Windows **work area**, click → `AppRuntime.show_window()`
  (restores the EXISTING instance; the single-instance guard is untouched).
  Entirely optional: if it cannot start, the router falls back to exactly one
  native balloon.

### B-5 Bug found and fixed while validating
Notification cards and the settings popup used `requestAnimationFrame` to trigger
their entry transition. rAF is throttled (or never fires) when the window is not
painting, which left cards stuck at `opacity: 0` — invisible while still occupying
one of the three visible slots. Reproduced in the browser, fixed by forcing a
reflow (`void el.offsetWidth`) instead. Both files now use the reflow.

## C. Actually verified (browser, real code)

- Settings popup opens from the gear, centered, app dimmed but recognizable;
  left nav switches sections; only the right pane scrolls. **VERIFIED**
- General / Notifications (grouped) / Appearance / Language / Runtime all render.
  **VERIFIED**
- Runtime section reports reality: with the headless demo server it showed
  *System tray: Unavailable*, *Background mode: Off*, *Application mode: Windowed*.
  **VERIFIED**
- UI mirrors the backend exactly — every category checkbox matched
  `/api/settings` (`allMatch: true`). **VERIFIED**
- **Arabic RTL**: popup mirrors (nav on the right, accent line on the correct
  edge, toggles left, text right-aligned); notification card mirrors. **VERIFIED**
- Dark and light themes. **VERIFIED**
- Notification card design, max-3 cap with queueing, and the grouped
  "5 new devices detected" body. **VERIFIED** in the browser.
- SHARKmac adapter filtering against this machine's real adapters. **VERIFIED**
- Frozen artifact contains every new module + both fixes. **VERIFIED**

## D. NOT TESTED (unchanged constraint)

Everything requiring the real elevated Windows GUI. This session's app runs
elevated while the automation session does not, so Windows UIPI blocks synthetic
input (`PostMessage` → error 5).

- the **custom desktop toast window** itself: that it appears bottom-right, does
  not steal focus, stays out of the taskbar/Alt+Tab, and that clicking it restores
  the window. The Win32 flags and positioning are unit-tested; the rendered window
  is **NOT** validated on Windows.
- tray Open / Notifications toggle / Exit; no-process-after-Exit; no orphan
  notification window after Exit.
- a real OS notification actually being displayed.
- minimize → desktop toast → restore → in-app toast routing on the real window.
- packet-level ALLOW/LIMIT/CUT/HARD CUT on live LAN devices (unchanged from the
  previous audit — it would cut a third party's connectivity).
- 3.0.0 → 3.1.0 upgrade install.

## E. Architecture constraints honoured

`policy.py`, `forwarder.py`, `spoofer.py`, `state.py` and the ARP/packet path were
not modified in this pass. ALLOW / LIMIT / CUT / HARD CUT, domain and service
blocking, Monitor semantics, interception, gateway/self protection and idempotent
cleanup are untouched. The router imports no enforcement module; notifications
remain independent of enforcement (still covered by the earlier audit tests plus
the new AST test).

Shutdown order now: notification router → desktop toast window → tray →
notification sink → `server.cleanup()` → single-instance guard release, all
idempotent.
