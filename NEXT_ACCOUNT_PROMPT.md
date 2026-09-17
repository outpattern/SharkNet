# Ready-to-paste prompt for the next Claude Code session

---

You are continuing SharkNet V3.1. Open the project at its root (`sharknet\`,
containing `run.py`, `backend/`, `frontend/`, `tests/`).

First read `README.md`, then `HANDOFF.md` in the project root. There is no
`CLAUDE.md`/`AGENTS.md`. **This project is NOT a git repository** — do not run
git status/branch/commit/reset/push; there is nothing to commit, and every file
in the tree is current work. Version history is manual folder copies under
`..\sharknet versions\`. Preserve everything; do not reset, clean, discard,
revert or overwrite existing files.

Verify before trusting the handoff: run `python -m pytest tests/ -q` and confirm
**383 passed**. Confirm each of the five `frontend/i18n/*.json` files has **359**
keys. If the files contradict the handoff, trust the files and say so.

The backend V3.1 runtime, the tray controller, the `run.py` integration, the
frontend settings UI and the pystray/Pillow packaging changes are **already
implemented** — do not rebuild them. Read `HANDOFF.md` §5 for exactly what exists.

**The remaining work is real Windows desktop validation (HANDOFF.md §7).** The
automated suite uses a fake pystray and a fake window, so it proves the logic, not
the OS integration. On a Windows machine with Administrator rights and Npcap,
run `python run.py` and validate by hand:

1. Tray icon, tooltip, and the **Open / Notifications / Exit** menu; double-click
   opens the window; the Notifications checkbox flips the setting and stays in
   sync with the same toggle in the UI.
2. **Close-to-tray** (X hides, engine keeps enforcing, the UI pill reads
   "Background on"), **restore** from the tray, and **second-instance activation**
   (a second launch must restore the first window, never start a second engine).
3. A real **OS balloon** for a real event, localized when the UI language is
   Arabic/French/etc.
4. **Coordinated shutdown** from every path (tray Exit, X with background off,
   server shutdown): ARP restored, no stray process, no orphan tray icon.
5. Dark/light themes and **Arabic RTL** in the real WebView2 window.

Two known risks to check first: pywebview's cancellable `closing` event is
version-dependent (`run.py` logs a warning and falls back to V3.0 close behavior
if unavailable), and the pystray message loop has to coexist with the pywebview
loop. Fix whatever the hardware reveals, then run `build.ps1` and confirm the
**frozen** build still gets a tray (the spec changes are untested).

Only after 1–5 and the frozen-build check pass, prepare the 3.1.0 release: bump
`AppVersion` in `installer.iss` and `version_info.txt` (and the `?v=` cache-bust
strings in `index.html`), build the installer, and record its SHA-256.

Hard constraints (do not violate):
- Preserve `ALLOW` / `LIMIT` / `CUT` / `HARD CUT` behavior and semantics.
- Keep notifications and the tray strictly separate from enforcement logic.
- Reuse the existing monitoring/state flow (`backend/state.py`,
  `backend/engine/monitor.py`, `backend/engine/policy.py`) — no parallel state engine.
- Keep cleanup/shutdown idempotent; all exit paths funnel through
  `run.AppRuntime.shutdown()` and `backend.server.cleanup()`.
- Keep `/api/settings` writes going through `backend.server.apply_settings_patch()`
  so the UI and the tray cannot drift.
- Preserve existing V3.0.0 release artifacts
  (`installer_output\SharkNet-Setup-3.0.0.exe` and `..\sharknet versions\`).
- Keep all five locales at equal key counts when adding strings.
- **Do not claim Windows tray/GUI/notification behavior is tested unless you
  actually validated it on Windows.** Record what you really ran in `HANDOFF.md`.

---
