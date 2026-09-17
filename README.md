# 🦈 SharkNet

A modern LAN control **and** network-security tool for Windows (NetCut / SelfishNet
style) — discover the devices on your network, then **allow / limit / cut** them,
block **domains** and **services**, or just **monitor** a device's activity — from a
clean, multi-language dark/light UI.

> ⚠️ **Use only on networks you own or administer** (your home/office router).
> Using it to disrupt, spy on, or interfere with traffic on networks you don't
> control is an attack and is illegal in most places. Use it for good.

## Features
- **Discovery** — passive + active ARP scan with vendor + hostname (DHCP / mDNS /
  NetBIOS) → friendly device names, types and icons.
- **Enforcement** — per-device **ALLOW / LIMIT (↓/↑) / CUT**, plus **Domain
  blocking** and a data-driven **Service catalog** (47 streaming / social / gaming
  services, MENA + global) with best-effort QUIC scoping.
- **Network-wide rules** — block a service or domain for *every* device (session-only).
- **Monitor (observation)** — explicitly observe one device's traffic **without**
  blocking or limiting it. Observation and enforcement are kept strictly separate:
  Monitor never means CUT/LIMIT/BLOCK.
- **Visited Sites** — the domains a device was observed reaching (observation only).
- **SharkNet Defender** — watches the gateway MAC and alerts on ARP-spoofing.
- **SharkMAC** — change / randomize / restore a network adapter's MAC address.
- **Traffic Intelligence & Network Health** — live down/up, latency, packets/s, a
  60 s chart, and a policy-aware health grade (SharkNet's own enforcement load is
  never misreported as a network fault).
- **5 languages** — English, العربية (RTL), Español, Français, 简体中文.
- **Quality of life** — dark/light theme, KB/s ⇄ Mbps, "Cut / Uncut others",
  copy IP/MAC, new-device toasts, clean ARP restore on exit.

## Architecture (engine ⟂ UI)
The network engine is fully separated from the UI, which is just a client of a
local token-authenticated API + WebSocket server:
- `run.py` — desktop app (PyWebView) that embeds the server + window.
- `engine_service.py` — the same server, headless (any UI / background service).
- `backend/engine/` — networking only, no UI imports.

The product model keeps three concepts distinct:
- **Enforcement** — ALLOW / LIMIT / CUT / domain-block / service-block.
- **Observation** — Monitor (and Visited Sites).
- **Interception** — a device is ARP-MITM'd if it is *enforced* **or** *monitored*.

```
python run.py                # desktop app (engine + window)
python engine_service.py     # headless engine at http://127.0.0.1:8734
python make_icon.py [img]    # regenerate assets/logo.png + sharknet.ico
```

## How it works
1. **Discovery** — ARP-scans the subnet and lists every device (IP, MAC, vendor, name).
2. **Interception** — ARP-spoofs a selected (enforced *or* monitored) device so its
   traffic routes through this PC (MITM). ALLOW-and-not-monitored devices are never
   intercepted.
3. **Per packet** — a single policy decides, from the *enforcement* state only:
   - **CUT** → drop everything · **LIMIT** → token-bucket rate limit per direction
   - **domain/service block** → drop only the matching requests (+ scoped IP pin for
     existing connections and QUIC) · otherwise **forward** (observe only).

Enforcement is **one** mechanism: native Npcap packet I/O driven by ARP MITM. No
kernel driver, no WinDivert, and **no Scapy at runtime** (Scapy is a test-only
golden-oracle dependency).

## Requirements
- **Windows 10 / 11**, **Administrator** (raw packets).
- **Python 3.10+**.
- **[Npcap](https://npcap.com/#download)** — install with default options
  (WinPcap is dead; Npcap is the modern replacement).

## Run from source
```bash
pip install -r requirements.txt
python run.py
```
SharkNet requests Administrator, verifies Npcap, then opens its window.
1. Pick your **network interface** (the one with your real gateway) and **Start control**.
2. Devices appear. Per device: **ALLOW / LIMIT / CUT**, block domains/services, or **Monitor**.
3. **Stop & restore** (or just close the app) returns every device to normal.

## Build the standalone installer
Produces `installer_output\SharkNet-Setup-3.0.0.exe` (bundles the app; Npcap is an
external prerequisite — the installer points to it if missing).

Requirements: `pip install pyinstaller` and
[Inno Setup 6](https://jrsoftware.org/isdl.php).

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

The installer puts SharkNet in Program Files (+ Start Menu / optional desktop
shortcut), checks for Npcap, and launches the app elevated.

## Notes
- **LIMIT throughput** is capped by the Python userspace forwarder by design; leave a
  device on **ALLOW** (and not monitored) for full native speed. On some routers with
  hardware flow-offload, download-direction interception can be incomplete — enable
  LIMIT before the download starts, or use the router's own bandwidth control.
- **Enforcement rules and Monitor are session-only** (not persisted): a restart
  starts every device at ALLOW with Monitor off. Device **names** are remembered.
- On exit SharkNet re-sends the correct ARP mappings, so no device is left offline.
- Tests: `pip install -r requirements-dev.txt && python -m pytest tests/`.
