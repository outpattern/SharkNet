# Build SharkNet: PyInstaller bundle -> Inno Setup installer.
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
#
# RELEASE INTEGRITY: every step's exit code is checked. $ErrorActionPreference
# does NOT apply to native commands (python / ISCC), so without these explicit
# checks a failed PyInstaller run used to fall through and Inno would happily
# package whatever stale dist\ was left over from a previous build — producing a
# "successful" installer containing the PREVIOUS version's code. Never again:
# any failure here aborts the build.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Assert-LastExit($what) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "BUILD FAILED: $what (exit code $LASTEXITCODE)" -ForegroundColor Red
        Write-Host "No installer was produced. Existing artifacts were left untouched." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# A running SharkNet locks dist\SharkNet\SharkNet.exe, so PyInstaller's --clean
# cannot delete it and the whole bundle silently stays stale. Catch it up front
# with a clear message instead of shipping last build's code.
$running = Get-Process -Name SharkNet -ErrorAction SilentlyContinue
if ($running) {
    Write-Host ""
    Write-Host "BUILD BLOCKED: SharkNet is currently running (PID $($running.Id -join ', '))." -ForegroundColor Red
    Write-Host "It locks dist\SharkNet\SharkNet.exe, so the bundle cannot be rebuilt." -ForegroundColor Red
    Write-Host "Exit SharkNet (tray icon -> Exit), then run this script again." -ForegroundColor Yellow
    exit 1
}

Write-Host "==> Installing/updating build deps..." -ForegroundColor Cyan
python -m pip install -r requirements.txt pyinstaller | Out-Null
Assert-LastExit "pip install of build dependencies"

Write-Host "==> Building app with PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller sharknet.spec --noconfirm --clean
Assert-LastExit "PyInstaller bundle"

if (-not (Test-Path "dist\SharkNet\SharkNet.exe")) {
    Write-Host "BUILD FAILED: dist\SharkNet\SharkNet.exe was not produced." -ForegroundColor Red
    exit 1
}

# Optional: drop the official Npcap installer here to bundle it into the setup.
# NOTE: installer.iss deliberately does NOT bundle Npcap (Gate 6.6 — it is an
# external prerequisite), so this download is only for local experimentation and
# its failure is never fatal.
if (-not (Test-Path "vendor\npcap-setup.exe")) {
    Write-Host "==> Downloading Npcap installer (optional)..." -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Force "vendor" | Out-Null
        Invoke-WebRequest "https://npcap.com/dist/npcap-1.82.exe" -OutFile "vendor\npcap-setup.exe"
    } catch {
        Write-Warning "Could not download Npcap; the installer points users to it instead (expected)."
    }
}

$iscc = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { $iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" }

if (Test-Path $iscc) {
    Write-Host "==> Compiling installer with Inno Setup..." -ForegroundColor Cyan
    & $iscc installer.iss
    Assert-LastExit "Inno Setup compile"
    Write-Host "==> Done. Installer written to installer_output\ (see SharkNet-Setup-*.exe)" -ForegroundColor Green
} else {
    Write-Warning "Inno Setup not found. Install it:  winget install JRSoftware.InnoSetup"
    Write-Host "The app bundle is ready in dist\SharkNet\ (run SharkNet.exe)."
}
