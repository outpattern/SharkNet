# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for SharkNet -> builds dist/SharkNet/SharkNet.exe
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [("frontend", "frontend"), ("assets", "assets"),
         ("backend/data", "backend/data")]   # SHARKmac vendor OUI database
binaries = []
hiddenimports = ["backend", "backend.server", "backend.engine.services_update",
                 # V3.1 background runtime (imported lazily at startup)
                 "backend.tray", "backend.localization", "backend.single_instance"]

# V3.1 tray: pystray picks its Windows backend at import time, so the win32
# backend + the Pillow codecs that read assets/sharknet.ico must be named
# explicitly or the frozen build silently falls back to "no tray".
# NOTE: deliberately NOT PIL._tkinter_finder — tkinter is excluded below.
hiddenimports += ["pystray", "pystray._win32", "PIL", "PIL.Image",
                  "PIL.IcoImagePlugin", "PIL.PngImagePlugin", "PIL.BmpImagePlugin"]

# bundle libraries that need their data/native files collected
for pkg in ("webview", "clr_loader", "pythonnet", "pystray", "PIL"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

hiddenimports += collect_submodules("uvicorn")
hiddenimports += ["websockets", "watchfiles"]

a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SharkNet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,         # no black terminal window
    disable_windowed_traceback=False,
    uac_admin=True,        # request Administrator on launch
    icon="assets/sharknet.ico",
    version="version_info.txt",   # Windows FileVersion/ProductVersion = 3.2.0
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SharkNet",
)
