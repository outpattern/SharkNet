# SharkNet — Post-V3.1 Competitive & Technical Benchmark

**Type:** READ-ONLY audit. No SharkNet source was modified, no build was run, no
Git operation was performed while producing this report.
**Date:** 2026-09-17.
**SharkNet baseline:** reconstructed from the actual working tree (backend 7,702
LOC Python, frontend 2,366 LOC JS, tests 5,422 LOC / **383 passing tests**).
**Competitor data:** current (2026) official docs, repos, release pages and
release artifacts, gathered by three parallel research passes; every external
claim is tagged **DOCUMENTED / OBSERVED / CLAIMED / INFERRED / UNVERIFIED** and
carries a confidence level in §29.

A note on method: SharkNet claims are **code-inspection** facts (HIGH confidence
for structure/logic). Nothing about SharkNet's *runtime behaviour on real
hardware* is asserted as verified here — see §30. Competitor claims are only as
good as their source label.

---

## 1. Executive summary

SharkNet is a **Windows-native, host-based LAN controller with an integrated
self-defense posture and a real background-app runtime**. After V3.1 it combines
four things that are almost always split across separate products:

1. **Active ARP-MITM enforcement** (ALLOW / LIMIT / CUT / HARD CUT, per device,
   plus domain and service blocking) — the NetCut/EvilLimiter/bettercap lane;
2. **Traffic observation** (per-device up/down bytes, visited domains via
   DNS/SNI/HTTP, a policy-aware health grade) — the GlassWire/Fing lane;
3. **Self-defense** (ARP-spoof detection against *this* PC, attacker
   identification, Static ARP Lock, crash-safe ARP restore) — the Fing-alert /
   TuxCut-protection lane;
4. **A polished Windows desktop utility shell** (installer, tray, close-to-tray
   background runtime, single-instance activation, custom notification system,
   5-locale UI incl. Arabic RTL, dark/light) — a lane most ARP tools ignore
   entirely.

No single competitor occupies all four lanes. The commercial products that come
closest (Fing, Firewalla) either require a persistent agent/hardware or a
dedicated appliance; the free ARP tools (NetCut, EvilLimiter, bettercap) have no
comparable app shell, no self-defense-plus-control combination, and mostly no
Windows-native background UX.

Where SharkNet is genuinely behind: **no persistent/scheduled policies**
(deliberate — §11), **no device groups**, **shallow-to-moderate device identity
depth** vs. Fing/NetAlertX, a **small 47-service catalog** vs. AdGuard Home's
~151 and Control D's claimed 400+/1000+, and — the one hard technical ceiling —
**userspace bandwidth limiting** that cannot match Linux kernel `tc`/HTB shaping.
That last gap is **Windows-inherent**, shared by every Windows-based peer, and is
not a design defect.

The single most important caveat: **almost none of SharkNet's runtime behaviour
has been verified on real hardware** (enforcement on live devices, tray/GUI,
desktop notifications). The 383 automated tests prove *logic*, not *packets on
the wire*. See §30.

---

## 2. Current SharkNet architecture (from source)

**Runtime model.** A FastAPI + WebSocket server (`backend/server.py`, 1,108 LOC,
31 HTTP endpoints) bound to `127.0.0.1`, protected by a per-process capability
token + Origin check. The UI is a PyWebView (Edge WebView2) window that is purely
a WS/REST client; `engine_service.py` runs the identical server headless. Engine
threads are fully separated from UI (README "engine ⟂ UI").

**Interception.** One mechanism: native **Npcap** userspace packet I/O driven by
**ARP spoofing/MITM** (`spoofer.py`). A device is *intercepted* (ARP-poisoned)
iff it is **enforced OR monitored** (`state.is_intercepted`). ALLOW-and-not-
monitored devices are never poisoned — no needless MITM.

**Packet path** (`forwarder.py`, 510 LOC). Capture uses a **BPF filter pushed
into the Npcap driver** (`pcap_setfilter`, `ip and ether dst <my_mac>`), so
non-transit frames are dropped in the driver, not userspace — a real efficiency
point. Per frame reaching `_handle`: parse IPv4 → `policy.select_target` →
**HARD CUT blackhole (return before any work)** → byte count → **CUT early
return** → scoped blocked-IP drop (pinned QUIC/existing-connection IPs) →
DNS-answer recording → name-based block on DNS/SNI/HTTP → `policy.action_for`
(DROP/LIMIT/FORWARD) → on FORWARD, rewrite only the 12 L2 bytes and re-inject the
original frame (no re-serialization).

**Policy engine** (`policy.py`, single classifier). Pure functions, unit-testable
without sockets. Precedence within a packet: **blocked-domain DROP > cut/hardcut
DROP > limit LIMIT > forward**. Modes are a device-only axis
(`allow < limit < cut`, plus `hardcut`); domain/service blocking is an orthogonal
axis; the effective block set is **device ∪ network** (most-restrictive wins),
precomputed at mutation time (`state.recompute_effective`) so the hot path does
no JSON/catalog work.

**State** (`state.py`). In-memory `Device` dataclass keyed by IP, with MAC as the
stable persistence key. Observation intent (`monitor`) is deliberately orthogonal
to enforcement `mode`.

**Persistence** (`db.py`, SQLite under `%LOCALAPPDATA%`). Device **names/vendor/
hostname persist**. Enforcement **rules and domain-blocks are written on every
mutation but intentionally NEVER loaded** — a fresh session always starts every
device at ALLOW/Monitor-off (documented anti-surprise-cut posture; §11).

**Identity** (`vendors.py`, `nameresolver.py`, `namer.py`, `fingerprint.py`).
Vendor via built-in 46-prefix OUI table + a curated `oui_vendors.json`;
randomized (locally-administered) MACs are **detected and labelled "Private
(randomized MAC)"**. Names from a priority-ranked multi-source resolver (DHCP
opt-12 > mDNS > NetBIOS > reverse-DNS > saved), so a weak source never clobbers a
strong one. On-demand TCP-port + TTL fingerprint for OS/type guess.

**Security/defense** (`defender.py`, `protection.py`, `recovery.py`). Defender:
active gateway-MAC probe + passive ARP sniff → detects spoofing of *this* PC,
identifies the attacker (MAC+IP+vendor), raises an event. Protection: Static ARP
Lock via `netsh` neighbors + auto-heal. Recovery: crash-safe — an
`active_spoof.json` records the live spoof set; on restart a stale file triggers
ARP re-heal of every target.

**V3.1 app shell.** Tray (`tray.py`, pystray, optional), coordinated idempotent
shutdown + single-instance guard + close-to-tray (`run.py` `AppRuntime`),
notification manager + presentation router (`notifications.py`, `notify_router.py`
— one producer → one renderer, in-app toast vs. custom frameless desktop toast,
never a duplicate OS balloon), settings store + `/api/settings` + `/api/runtime`,
localization loader, 359 i18n keys × 5 locales.

**Packaging.** PyInstaller one-folder → Inno Setup installer with a branded
wizard; `build.ps1` now guards against stale-dist packaging. Npcap is an external
prerequisite (never bundled).

### Feature implementation status

**IMPLEMENTED (code-verified):** ARP scan discovery; ARP MITM interception;
ALLOW / LIMIT / CUT / HARD CUT; per-device + bulk enforcement; ad-hoc domain
blocking; 47-service catalog blocking; network-wide (all-device, session) blocks;
scoped QUIC/IP pinning; Monitor observation; visited-domains; per-device live
up/down + packets/s + 60 s history ring; policy-aware network health grade;
Defender ARP-spoof detection + attacker ID; Static ARP Lock + auto-heal;
crash-safe ARP recovery; SharkMAC (MAC change/randomize/restore, Ethernet+Wi-Fi
only); device rename; vendor/OUI + randomized-MAC labelling; multi-source passive
naming; on-demand fingerprint; gateway/self protection (never managed); tray +
close-to-tray + single-instance + coordinated shutdown; notification manager +
router + custom desktop toast; settings persistence; 5-locale localization + RTL;
dark/light; branded installer.

**PARTIALLY IMPLEMENTED:** QUIC/HTTP3 blocking (best-effort scoped-IP pinning
only, never claimed universal — `block_signals()` reports `quic: best_effort`);
device identity (solid basics, but no identity history, no confidence score, no
cross-MAC merge); bandwidth LIMIT (works, but userspace-capped — §8).

**RESERVED (code present, deliberately inert):** persisted enforcement rules and
domain-blocks (written, never loaded — `db.py` header).

**NOT IMPLEMENTED:** device groups; schedules/time-based policies; parental-control
profiles; trusted-device automation; persistent cross-restart enforcement;
DoH/DoT/ECH visibility (see §8); catalog auto-update; IPv6 enforcement;
rogue-*device* detection (Defender protects the host, it is not a whole-LAN IDS).

**No dead placeholders inflating the count:** the only TODO-class markers in the
backend are the explicit `RESERVED` notes in `db.py`. No stubbed endpoints, no
UI-only fake features found.

---

## 3. Competitor overview (current, 2026)

| Product | Status (2026) | Class |
|---|---|---|
| **NetCut** | Active, commercial (v4.1.3 CLAIMED 2025-07) | Windows/macOS ARP cutter |
| **SelfishNet** | Legacy / stalled (C#, WinPcap) | Windows ARP cut+limit |
| **LANtern Control** | **UNVERIFIED** — no such ARP tool located (name collision) | — |
| **EvilLimiter** | Maintained, slow (v1.5.0, 2024-07) | Linux ARP + kernel tc/HTB limiter |
| **bettercap** | Active (v2.41.7, 2026-05) | Cross-platform MITM framework |
| **TuxCut** | **Abandoned** (archived 2024-11-30) | Linux ARP cut + wondershaper |
| **CSArp (CSArp-Netcut)** | **Abandoned / legacy** (~2021) | Windows ARP cut-only |
| **InSpectre** | **Category error** — CPU Spectre tool, not a network tool | — (excluded) |
| **NetAlertX** (ex-Pi.Alert) | Very active (CalVer v26.9.x, monthly) | Linux/Docker presence monitor |
| **Fing** (App/Desktop/Agent) | Active (app 12.13.4, Desktop 4.0.6, 2026-09) | Scanner + ARP block; agent-gated |
| **GlassWire** | Active (3.10.1138, 2026-09) | Windows host firewall + LAN scanner |
| **Firewalla** | Active (app 1.66 / box 1.981, 2026-01) | Dedicated Linux appliance |
| **Pi-hole** | Active (Core v6.4.3, 2026-07) | Linux DNS sinkhole |
| **AdGuard Home** | Active (v0.107.79, 2026-08) | Linux/Win/mac DNS sinkhole + DoH/DoT/DoQ |
| **NetGuard** | Active (v2.337, 2026-08) | Android on-device VPN firewall |
| **Control D** | Active commercial (ctrld OSS) | Cloud filtering resolver |

Two list-integrity findings (both HIGH confidence):
- **"LANtern Control" cannot be independently located** as an ARP cut/limit tool.
  Public "LANtern"/"Lantern" names map to a Linux packet analyzer, an SNMP
  monitoring vendor, and a censorship-circumvention VPN. Treat any LANtern row as
  **UNVERIFIED**; the confirmed Windows platform-twin is SelfishNet V3 (C#).
- **"InSpectre" is a category error.** It maps to GRC InSpectre (a 2018 Windows
  Spectre/Meltdown checker) and VUSec's "InSpectre Gadget" (a CPU-vuln symbolic
  analyzer). Neither is a network/identity tool. It is **excluded** from the
  matrices below rather than faked. If a home-network scanner was intended, the
  likely candidates are Avast Wi-Fi Inspector or Advanced IP Scanner —
  unconfirmed.

---

## 4. Feature matrix

Legend: **Y** yes · **P** partial · **N** no · **U** unknown/unverified ·
**NA** not applicable. Cells are current-2026 best evidence; SharkNet = code.
InSpectre and LANtern omitted (see §3).

| Feature | SharkNet | NetCut | SelfishNet | EvilLimiter | bettercap | TuxCut | CSArp | NetAlertX | Fing | GlassWire | Firewalla | Pi-hole | AdGuard Home | NetGuard | Control D |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Windows | Y | Y | Y | P(port) | Y | N | Y | P(Docker) | Y | Y | N | P | Y | N | P(client) |
| Linux | N | N | N | Y | Y | Y | N | Y | P(agent) | N | Y(box) | Y | Y | N | P(client) |
| macOS | N | Y | N | N | Y | N | N | P(Docker) | Y | N | N | P | Y | N | P(client) |
| Android | N | P(root) | N | N | Y | N | N | N | Y | Y | Y(app) | N | N | Y | Y |
| iOS | N | N | N | N | N | N | N | N | Y | N | Y(app) | N | N | N | Y |
| Router/appliance | N | N | N | N | N | N | N | P(import) | N(agent) | N | Y(req) | P | P | N | Y |
| Dedicated HW req'd | N | N | N | N | N | N | N | N | P(agent) | N | **Y** | N | N | N | N |
| Device discovery | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | P | P | NA | P |
| Device identity depth | P | P | P | N | P | N | U | **Y** | **Y** | P | Y | P | P | NA | P |
| Device rename | Y | U | U | N | N | U | U | Y | Y | U | Y | P | Y | NA | Y |
| Online/offline | Y | Y | Y | P | Y | Y | U | Y | Y | P | Y | P | P | NA | P |
| Groups | N | N | N | N | P(targets) | N | N | Y | P(users) | N | Y | Y | P | NA | Y(profiles) |
| Scheduling | N | N | N | N | N | N | N | P(scan) | Y | N | Y | N | Y(services) | N | Y |
| ALLOW (baseline) | Y | Y | Y | Y | Y | Y | Y | NA | Y | Y | Y | Y | Y | Y | Y |
| LIMIT (bandwidth) | Y | P(claim) | Y | **Y(tc)** | N | Y(tc) | N | N | P(legacy) | N | **Y(tc)** | N | N | N | N |
| CUT (block device) | Y | Y | Y | Y | Y(ban) | Y | Y | N | Y | N(app) | Y | P(DNS) | P(DNS) | own dev | P(DNS) |
| HARD CUT / equiv | Y | P | U | Y | Y(ban) | U | Y | N | P | N | Y | N | N | N | N |
| Traffic monitoring | Y(intercepted) | P | P | P | Y | P | N | N(presence) | P(agent) | Y(host) | Y | Y(DNS) | Y(DNS) | Y(app) | Y(DNS) |
| Domain visibility | Y(DNS/SNI/HTTP) | N | N | N | Y | N | N | N | N | P | Y(DPI) | Y(DNS) | Y(DNS) | Y | Y(DNS) |
| DNS control/sinkhole | N | N | N | N | P(spoof) | N | N | N | N | N | Y | Y | Y | Y | Y |
| Service (by-name) blocking | Y(47) | N | N | N | N | N | N | N | N | N | P(rules) | Y(~151) | Y(~151) | P(app) | Y(400+ claim) |
| Security detection | Y(ARP) | P | N | N | N | Y | N | Y(new-dev) | Y | Y | Y(IDS) | N | P(safebrowse) | Y | P(threat) |
| Security active defense | Y(host) | P | N | N | N | Y(host) | N | N | Y(ARP block) | Y(host) | **Y(IPS)** | N | N | Y(app) | N |
| Notifications | Y | P | N | N | N | U | U | Y | Y | Y | Y | P | P | Y | P |
| System tray | Y | U | U | N | N | U | U | N | U | Y | NA(app) | NA | NA | NA | P(client) |
| Background runtime | Y | Y | U | N | N | Y(daemon) | U | Y(daemon) | P(GUI-tied) | Y(service) | Y | Y | Y | Y | Y |
| Single instance | Y | U | U | NA | NA | U | U | NA | U | U | NA | NA | NA | NA | NA |
| Persistent policies | N(reserved) | P | U | N | N | U | N | NA | Y(cloud) | Y | Y | Y | Y | Y | Y |
| Self protection | Y(ARP lock) | P(defender) | N | N | N | Y | N | N | N | N | Y | N | N | N | N |
| Gateway protection | Y | P | N | N | N | Y | N | N | P(alert) | N | Y | N | N | N | N |
| ARP-based enforcement | Y | Y | Y | Y | Y | Y | Y | N | Y | N | P(simple) | N | N | N | N |
| Kernel traffic shaping | N | U | U | **Y** | N | **Y** | N | N | N | N | **Y** | N | N | N | N |
| No-router-required | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | P | P | Y | P |
| Dedicated HW required | N | N | N | N | N | N | N | N | P | N | Y | N | N | N | N |

---

## 5. Technical architecture matrix

| Product | Platform | Interception layer | Enforcement layer | Traffic shaping | Observation | DNS method | Identity model | Persistence | Security model | UI model | Runtime model |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **SharkNet** | Windows (Npcap) | ARP-MITM, userspace | userspace drop/token-bucket + scoped-IP | **userspace token bucket** | inline parse DNS/SNI/HTTP + byte counters | observe only (no sinkhole) | MAC-key, multi-source name, OUI, randomized-MAC label | names persist; **rules reserved (not loaded)** | host ARP-defense + Static ARP Lock | PyWebView local WS client | tray + bg service + single-instance |
| NetCut | Win/macOS | ARP, WinPcap/Npcap | userspace cut/limit (mech. UNVERIFIED) | UNVERIFIED | minimal | none | IP/MAC/vendor | app config | "NetCut Defender" ARP detect | native GUI | resident app |
| EvilLimiter | Linux | ARP, Scapy | **kernel tc(HTB)+iptables** | **kernel HTB** | usage analyze | none | host list | session | none (offensive) | CLI shell | foreground CLI |
| bettercap | X-platform | ARP (+more), Go | relay vs **ban (fwd off)** | **none** | sniffers/proxies | DNS spoof | net.recon MAC/OUI | session/caplets | offensive | CLI/web UI | foreground/daemon |
| TuxCut | Linux | ARP | userspace cut + **wondershaper(tc)** | **kernel HTB** | host list | none | host list | config | host ARP-protect | wxPython + daemon | daemon+GUI |
| NetAlertX | Linux/Docker | passive scan (ARP/nmap/SNMP) | **none** | none | presence only | read-only imports | **MAC-key, field-lock, (IP match) confidence** | SQLite, persistent | detection only | web UI | container daemon |
| Fing | Win/mac/agent | ARP scan; ARP-MITM to block | userspace discard (ARP) | none (legacy Fingbox only) | presence + protocols | none | **MAC-key, cloud 450k-model recog, no merge** | cloud account | ARP block + rich alerts | Electron-class + service | GUI-tied or agent daemon |
| GlassWire | Windows | **host kernel driver (WFP)** | Windows Firewall rules (**local host apps**) | none | **per-process host flows** | monitors | LAN scan MAC/OUI (shallow) | local config | host firewall + ARP-detect | native GUI + service | service + tray |
| Firewalla | Linux appliance | **inline (router mode)** / ARP (simple) | **kernel netfilter** inline | **kernel fq_codel/CAKE** | DPI/flows | DNS inspect + DoH-block | MAC-key, **AP7 binds to Wi-Fi cred** | on-box, persistent | **inline IPS (Suricata)** | mobile app + MSP | appliance |
| Pi-hole | Linux | DNS resolver | DNS answer null | none | query log | **is the resolver** | client IP/MAC/host | persistent | DNS filter | web UI | service |
| AdGuard Home | X-platform | DNS resolver | DNS answer null | none (rate-limit DoS only) | query log | **DoH/DoT/DoQ server** | per-client + ClientID | persistent | filter + safebrowse | web UI | service |
| NetGuard | Android | **local VpnService** | per-app allow/deny | none | per-app flows | domain filter/hosts | per-app UID | persistent | on-device firewall | Android app | VPN service |
| Control D | cloud + client | DNS resolver + SNI proxy | DNS block/bypass/redirect | none | query log | **DoH/DoT/DoQ** | per-endpoint profile | cloud | threat filter | dashboard + ctrld | cloud + local client |

---

## 6. Enforcement comparison (ALLOW / LIMIT / CUT / HARD CUT)

**SharkNet's model, from code.** All four are a per-device `mode` on the same
ARP-MITM path, decided by one classifier (`policy.action_for`):
- **ALLOW** → not managed unless also monitored/blocked → traffic never routed
  through SharkNet → native speed (`is_managed` false).
- **LIMIT** → managed; per-direction token bucket; over-budget frames dropped so
  TCP backs off (userspace).
- **CUT** → managed; every frame dropped after byte-counting (device still shows
  its blocked attempts).
- **HARD CUT** → managed; frame blackholed *before* any counting/observation.

**How competitors achieve equivalents:**
- **NetCut / SelfishNet / CSArp** (Windows, WinPcap/Npcap): ARP-poison → cut. Cut
  is documented; limit is CLAIMED (NetCut/SelfishNet) or absent (CSArp). No
  router or hardware. Same LAN-operable class as SharkNet, minus the app shell,
  self-defense combination, and (CSArp) minus limiting entirely.
- **EvilLimiter / TuxCut** (Linux): ARP-poison, then **kernel `tc`/HTB** (TuxCut
  via wondershaper) for real shaping, iptables for block. Genuine kernel
  enforcement — the throughput ceiling SharkNet cannot reach on Windows.
- **bettercap:** `arp.spoof` to insert, `arp.ban` (forwarding off) to blackhole —
  a close analogue of SharkNet CUT/HARD CUT, but **no shaping at all** (binary
  relay-vs-ban) and no app/observation shell.
- **Firewalla:** in **Router mode**, enforcement is an **inline kernel netfilter
  drop** — not spoofable from the LAN, strictly stronger than any ARP approach;
  in **Simple mode** it uses ARP-MITM with the same leak caveats as SharkNet.
  Requires the appliance.
- **Fing:** ARP-poison + DNS-spoof, receive-and-discard. IPv4-only, defeated by
  anti-ARP-spoof routers and by MAC rotation, per-device only, and it requires a
  persistent agent + subscription + (on some networks) Fing's manual approval.
- **GlassWire:** cannot block another device at all — Windows Firewall rules on
  **the local host's own apps** only.
- **Pi-hole / AdGuard / Control D / NetGuard:** "block" = refuse DNS resolution
  (or, NetGuard, per-app on that one phone). No per-device cut of an arbitrary
  LAN device, no bandwidth cap.

**Reading.** SharkNet's four-mode ladder is **richer than every free ARP tool**
(only EvilLimiter/TuxCut add real limiting, and only on Linux; only bettercap adds
a clean ban, without shaping) and **operates with no router and no hardware** —
unlike Firewalla, the only tool with strictly stronger (inline kernel)
enforcement. Its enforcement is functionally comparable to Fing's block, on a
sounder engineering base (single classifier, gateway/self never managed,
crash-safe restore) but without Fing's cloud recognition or persistence.

---

## 7. HARD CUT analysis (traced in code)

**What happens on HARD CUT** (`forwarder.py` `_handle`, lines ~388-398): after
`policy.select_target` matches the device, the very first branch is
`if target.mode == "hardcut": return`. That return happens **before** byte
counting, before scoped-IP checks, before DNS recording, before any SNI/Host/DNS
parse, before the policy call, and before re-injection.

- **Do packets reach userspace?** Yes — the frame is captured by Npcap and
  delivered to `_handle` (the BPF `ether dst my_mac` filter already excludes
  non-transit frames in the driver). So HARD CUT is **not** a zero-userspace
  blackhole; it is a **userspace early-return blackhole**.
- **Minimum processing remaining:** IPv4 parse (`rawpkt.parse_ipv4`) + self/GW
  guard + `select_target` (a GIL-atomic dict lookup). That is the floor; nothing
  above L3 identity runs.
- **Forwarding stops:** yes — no re-injection path is reached.
- **Observation stops:** yes — deliberately. No byte count, no domain parse, no
  visited-site record. Live traffic reads **zero** for a hard-cut device
  (`_apply_device_rule` also zeroes `down_bps/up_bps` for allow+hardcut only).
- **Accounting:** none (this is the CUT-vs-HARD-CUT difference).
- **vs CUT:** CUT returns *after* `self._count(...)` — a cut device is still
  observed (byte counters keep showing its blocked attempts); HARD CUT is
  invisible. Same on-the-wire effect (zero connectivity), different observability.
  This is asserted by `test_cut_vs_hardcut_same_network_effect_different_observation`.
- **ARP interaction:** identical to CUT — the device is `is_managed` therefore
  ARP-poisoned so its frames arrive at this host to be dropped. Because
  interception is what routes the victim's traffic here, "drop" means the traffic
  dies at this host rather than reaching the gateway.
- **Cleanup:** identical idempotent path — leaving HARD CUT unmanages the device,
  the spoofer restores its ARP, `recovery.py` heals on crash.

**Comparison to true blackhole/ban mechanisms:**
- **bettercap `arp.ban`** disables IP forwarding while spoofing, so the victim's
  frames are received and dropped by the OS/stack — conceptually the same
  "poison then drop" as SharkNet HARD CUT, at a similar (userspace) layer.
- **NetCut/CSArp cut** sever the victim↔gateway ARP mapping so the victim can't
  even reach the host — a slightly different mechanism (deny the path) vs.
  SharkNet (own the path, then drop).
- **A TRUE zero-userspace blackhole** (a kernel BPF/XDP drop, an `arp.null`
  poisoning to a non-existent MAC so frames never come to the host at all, or a
  Firewalla inline netfilter drop) would **never bring the victim's packets into
  this process**. SharkNet HARD CUT does bring them in and drops them in Python.

**Honest characterization:** SharkNet HARD CUT is a **userspace early-return
blackhole with observation suppressed** — the earliest safe drop point *given the
own-the-path ARP-MITM model*. It is **not** an ARP-null or kernel/BPF blackhole,
and the code/comments do not claim to be. For its architecture it is the correct,
minimal-work maximum-isolation branch. **No architectural change is warranted by
this comparison** — an ARP-null variant would change the interception model
(SharkNet deliberately owns the path so it can also *observe* and *selectively*
block, which a null-route forecloses). CONFIDENCE: HIGH (direct code trace, 18
dedicated hardcut tests). Runtime packet-drop on real devices: **NOT TESTED**.

---

## 8. Bandwidth limiting analysis

**SharkNet mechanism (code):** a per-(ip,direction) **token bucket** (`_Bucket`,
`rate = kbps*1024`, cap = max(rate, 8192) for burst). On each frame,
`allow(size)` refills by elapsed time and either passes or **drops** the frame;
dropped frames make TCP back off. This is **userspace, on the ARP-MITM path**,
L3/L4-agnostic, per direction, per device.

**Is it technically reasonable for Windows?** **Yes.** Windows has no unprivileged
equivalent of Linux `tc`/HTB available to a userspace Npcap app; a token bucket on
the intercepted path is the standard, correct approach for this architecture. It
gives genuine per-device up/down caps that no DNS tool (Pi-hole/AdGuard/Control D)
and no host firewall (GlassWire) offers at all.

**Real limitations (all HIGH confidence, from code + README):**
1. **Throughput ceiling.** Every limited byte round-trips through the Python
   userspace forwarder, so **LIMIT caps aggregate throughput** — the README says
   plainly "leave a device on ALLOW for full native speed." An unlimited device
   that is *also monitored* pays the same interception tax.
2. **Drop-based, not queue-based.** HTB *queues and paces*; SharkNet *drops over
   budget* and relies on TCP congestion control. That is coarser: UDP/QUIC and
   aggressive senders behave less smoothly than under a real qdisc, and there's no
   fair-queue/latency management (no CoDel/CAKE equivalent).
3. **Download-side interception can be incomplete** on routers with hardware
   flow-offload (README) — a switched-LAN ARP-MITM reality, not a code bug.
4. **Bucket is per (ip,direction)** — no group/aggregate shaping (Firewalla can
   rate-limit a whole group cumulatively).

**Which competitor capabilities are fundamentally Linux-kernel-enabled:**
EvilLimiter and TuxCut's smooth HTB shaping, and **Firewalla's fq_codel/CAKE
smart-queue** — all are **kernel qdisc** features. These are *not* "a better
implementation" of the same thing; they are a **different layer** (kernel traffic
control) unavailable to a Windows userspace Npcap app. Penalizing SharkNet for the
absence of kernel shaping would be penalizing it for running on Windows without a
custom kernel driver — a deliberate, reasonable scope choice (SharkNet explicitly
avoids a kernel driver; README/architecture). Among **Windows** peers, essentially
none offers better per-device shaping (NetCut's is CLAIMED/unverified; GlassWire
has none). CONFIDENCE HIGH (mechanism); precision/accuracy of the cap on real
traffic: **NOT MEASURED** (§30).

---

## 9. Traffic visibility analysis (what SharkNet can honestly see in 2026)

SharkNet parses **cleartext request signals on the intercepted upload path**
(`domains.py`): **DNS query names (UDP/TCP 53), TLS SNI (ClientHello, 443), HTTP
Host (80)**. Plus per-device byte counters (up/down) and packets/s for any
intercepted device. It runs observation-only parsing on an **async bounded queue**
off the hot path (`domain_observer.py`); active blocking parse stays inline.

Honest 2026 visibility ladder:
- **DNS (plaintext, 53):** VISIBLE — query name parsed. HIGH.
- **TLS SNI:** VISIBLE **today**, because most TLS ClientHellos still send SNI in
  cleartext. HIGH — but see ECH below.
- **HTTP Host (80):** VISIBLE — but port-80 web is now a small minority of traffic.
- **QUIC / HTTP3 (UDP/443):** **NOT parsed** — no cleartext name in the QUIC
  Initial here; SharkNet does not decrypt it. Handled **best-effort** by pinning
  the IPs a blocked domain resolved to (`blocked_ips`, TTL'd) and dropping UDP/443
  to those IPs only. `block_signals()` reports `quic: best_effort` — the code
  refuses to over-claim. This is a real and growing blind spot (QUIC is a large
  share of streaming/Google traffic).
- **DoH (DNS-over-HTTPS, 443):** **NOT visible** as DNS — it looks like HTTPS to a
  resolver at e.g. cloudflare-dns.com; SharkNet sees the SNI to the DoH provider,
  not the queried name. A device using DoH bypasses SharkNet's DNS-name visibility
  and DNS-based blocking. Not handled. HIGH-confidence gap.
- **DoT (853):** **NOT visible / not parsed** — encrypted, and port 853 is not in
  the parse set.
- **ECH (Encrypted ClientHello):** **defeats SNI visibility** where deployed —
  the server name moves inside an encrypted extension. Not handled. Growing but
  not yet universal in 2026; where a site+resolver support ECH, SharkNet's SNI
  read (and SNI-based blocking) silently fails for it.
- **Application-level content:** never (no TLS interception/MITM-decrypt — a
  deliberate scope and trust choice).

**Do not exaggerate:** for the **still-common** case (plaintext DNS + SNI without
ECH), SharkNet's per-device domain visibility is real and useful, and better than
every pure ARP cutter (NetCut/CSArp/bettercap show no per-device domain list) and
comparable in *kind* to what a DNS sinkhole logs — except SharkNet sees it
**per-device on the LAN with no DNS reconfiguration**. But encrypted-DNS (DoH/DoT)
and ECH are **structural erosions** that SharkNet, like every passive on-path
observer, cannot follow without becoming a decrypting proxy. CONFIDENCE HIGH (code).

---

## 10. Service catalog comparison

**SharkNet (measured):** `backend/data/services.json` — **47 services**, **132
domain entries** (avg 2.8/service), **5 categories** (streaming 36, social 5,
music 4, messaging 1, gaming 1), each with `confidence` (CONFIRMED/LIKELY/…),
`quic` flag, `regions`, and human notes. Architecture is **pure data**: a service
is a catalog entry compiling to a per-device keyword tuple
(`state.recompute_effective`); there is **no per-service engine code**, and adding
a service is a JSON edit (`services.py` docstring). `block_signals()` reports
honest per-signal coverage (dns/tls/http true, quic best_effort). MENA + global
coverage is a deliberate niche (Shahid, Watch iT, Anghami, beIN, OSN, etc.).

**Comparators:**
- **AdGuard Home:** **~151 services** (OBSERVED — counted live from the
  HostlistsRegistry `services.json`), each an Adblock-rule set with group/icon,
  schedulable per client. Larger, community-maintained, auto-updatable.
- **Control D:** **CLAIMED 400+/1000+** services (vendor figures inconsistent,
  UNVERIFIED count), with 3 actions (Block/Bypass/Redirect).
- **Pi-hole / NetGuard:** **no named-service catalog** — manual adlists/regex, or
  per-app (NetGuard).

**Verdict on SharkNet's catalog:** architecturally **competitive and extensible**
(clean data-driven design, honest coverage signalling, QUIC realism, curated MENA
niche), but **quantitatively basic** (47 vs. ~151 vs. 400+) and **not
auto-updating** (`services_update.py` exists but the catalog ships static). The
design does **not** need rebuilding — it needs *more entries and an update feed*
to close the gap. Its distinguishing strength is that it blocks a service **for a
chosen device via on-path enforcement**, not only via DNS refusal, so it can catch
some existing-connection/QUIC cases a sinkhole cannot. CONFIDENCE HIGH.

---

## 11. Device identity comparison

**SharkNet (code):** MAC-keyed identity (stable across IP changes); vendor via
built-in 46-prefix table + curated JSON (small — will return "Unknown" for many
OUIs the big DBs know); **randomized/locally-administered MACs detected and
labelled** "Private (randomized MAC)"; multi-source **priority-ranked** naming
(DHCP opt-12 > mDNS > NetBIOS > rDNS > saved) so names are stable and don't flap;
first-seen/last-seen; online/offline; user rename (persists); on-demand
port/TTL fingerprint for OS/type; device-type icon guess from vendor.

**Missing vs. the identity leaders:** no identity **history/timeline**, no
**confidence score**, no **grouping/tags**, no cross-MAC identity **merge**, and a
**shallow OUI DB** relative to Fing's cloud catalog.

**Comparators:**
- **Fing:** deepest recognition — cloud **450k-model** catalog (CLAIMED) returning
  brand/family/model/OS/release-date, crowd-corrected. But **MAC-keyed with no
  merge**: rotating MACs surface as new devices; Fing's official remedy is "turn
  private MAC off." No exposed confidence score. Mobile can't read MAC at all
  (iOS 11+/Android 13+).
- **NetAlertX:** the most transparent (open source) — MAC-key with **field
  locking**, an explicit **"(IP match)" low-confidence suffix** (the only real
  identity-confidence signal found in the field), `UI_NOT_RANDOM_MAC` exemptions,
  multi-source naming. Also does not merge rotating MACs.
- **Firewalla:** detects+flags randomized MAC by the same locally-administered-bit
  test SharkNet uses; its structural fix is **AP7 binding policy to the Wi-Fi
  credential instead of the MAC** — the only genuinely robust randomized-MAC answer
  in the field, and it needs Firewalla's own AP hardware.
- **GlassWire:** shallow (presence + MAC + OUI, no documented randomized-MAC
  stance).

**Reading.** SharkNet's identity is **solid on fundamentals** (stable MAC key,
deterministic multi-source names, randomized-MAC *labelling*, rename) and
**mid-pack overall** — clearly behind Fing (recognition depth) and NetAlertX
(confidence signal, field-locking, history), ahead of the pure cutters and
GlassWire. **Crucially, no competitor solves randomized-MAC identity at the MAC
layer** — all detect-and-tell-you-to-disable-it; the only real fix (Firewalla AP7)
requires proprietary Wi-Fi hardware. So SharkNet's randomized-MAC handling
(detect + label) is *par for a software LAN tool*, not a unique weakness. The real,
fair gaps are **OUI DB size**, **identity history**, and a **confidence signal**.
CONFIDENCE HIGH (SharkNet code; competitor docs).

---

## 12. Groups / scheduling / persistence

**SharkNet:** **no groups, no schedules, no persistent enforcement.** Bulk actions
exist (`/api/bulk/rule`, cut-all-except-me) but they are one-shot, not saved
groups. Rules/domain-blocks are **written to SQLite but never loaded** — a fresh
session starts every device at ALLOW/Monitor-off. This is a **deliberate
anti-surprise-cut safety posture** (`db.py` header, README "session-only").

**Architectural consequences of the fresh-session posture:**
- *Benefit:* SharkNet can never boot into a state where it silently cuts a
  housemate/family device from a rule the user forgot weeks ago — a real hazard
  for an ARP tool that a background/auto-start app amplifies. It also means a
  crash/relaunch never re-poisons the LAN unexpectedly (paired with `recovery.py`
  healing any interrupted spoof). For a tool that literally severs people's
  internet, "start neutral" is a defensible, arguably responsible default.
- *Cost:* it forecloses the entire **"set it and forget it"** product lane —
  parental-control schedules (Firewalla Family Time/Disturb, AdGuard per-client
  schedules, Fing bedtime/homework), trusted-device auto-policies, new-device
  auto-quarantine (Firewalla), and persistent per-device caps. Everything must be
  re-applied each session by hand.

**Competitors:** Firewalla (device groups, rule groups, scheduling, Family Time,
Disturb, New Device Quarantine, documented precedence, persisted on-box); AdGuard
(per-client groups + scheduled blocked-services); Fing (per-user schedules,
persisted cloud-side, re-applied by the agent); Pi-hole (client groups); NetAlertX
(groups/owners/locations, but monitoring only). Persistence in all of these is
enabled by either a dedicated always-on box/agent or a cloud account.

**This is NOT automatically a defect.** It is a **safety/convenience tradeoff**
SharkNet made explicitly. The honest framing: SharkNet chose *safe-by-default* over
*persistent-by-default*, and the `rules` table being **RESERVED (written, not
loaded)** shows the intended migration path — a future **opt-in** "remember rules"
that compiles to the same per-device predicates. What is genuinely missing (and
independent of the safety posture) is **grouping** and **scheduling** as concepts.
CONFIDENCE HIGH (code + docs).

---

## 13. Security / self-defense

Separating the four layers the prompt asks for:

**SharkNet:**
- **ACTIVE DEFENSE:** Static ARP Lock (`protection.py`, `netsh` static neighbor)
  to keep *this PC* from being ARP-spoofed off the gateway; **auto-heal**
  re-asserts the correct mapping on tamper. This defends the host, not the LAN.
- **DETECTION:** Defender's active gateway-MAC probe + passive ARP sniff → detects
  gateway-MAC change, multiple-MACs-per-IP, ARP floods.
- **MONITORING:** identifies the attacker (rogue MAC → device IP + vendor), raises
  a UI event.
- **ENFORCEMENT (as security):** the same ALLOW/LIMIT/CUT/HARD CUT can be turned
  on an identified rogue, manually.

**Scope honesty:** SharkNet's defense is **host-centric** (protect *me* from ARP
spoofing) — it is **not** a whole-LAN IDS/IPS and does **not** do rogue-*device*
detection, port-scan alarms, or intrusion prevention for other devices.

**Comparators:**
- **Firewalla:** the only true **inline IPS** (Suricata, multi-engine, can *drop*),
  plus New Device Quarantine (auto-block on first sight), abnormal-upload/port-scan
  alarms — but needs the appliance.
- **Fing:** rich **detection/alerting** (new device, new gateway, rogue AP/evil-
  twin/deauth via legacy Fingbox, vulnerability/open-port scans) but its only
  *active* primitive is ARP block; alerts don't prevent.
- **NetAlertX:** detection only (new device, IPAM drift), **zero enforcement**.
- **GlassWire:** ARP-spoof *detection* (reliability questioned in its own forum) +
  host firewall; local host only.
- **TuxCut:** host ARP-protection similar in spirit to SharkNet's, no detection UI.
- **NetCut Defender:** ARP-spoof protection product, comparable host-defense idea.

**Reading.** SharkNet is one of very few tools that pair **active ARP control** with
**active host self-defense + attacker identification** in the same app — Fing
alerts but its defense is thinner on the host side; Firewalla is stronger but is an
appliance; the free cutters have little or none. SharkNet's gap is **breadth**
(host-only, no whole-LAN IDS, no rogue-device detection). CONFIDENCE HIGH (code).

---

## 14. Windows UX

**Installation/startup:** branded Inno Setup wizard (dark title bar via DWM,
SharkNet artwork, Welcome→Location→Options→Ready→Installing→Finish), UAC
self-elevation, Npcap prerequisite check → download page if missing. This is
**well ahead** of the CLI/zip distribution of EvilLimiter/bettercap/SelfishNet/
CSArp and comparable to commercial Windows installers (GlassWire, NetCut).

**Background/runtime:** tray (Open/Notifications/Exit), close-to-tray honouring a
tray-gated setting, single-instance activation, `/api/runtime` truthful status,
coordinated idempotent shutdown, custom notification system (in-app vs. frameless
desktop toast, no duplicate OS balloon). This is a **proper Windows background
utility** — materially better than Fing Desktop (whose monitoring is tied to the
GUI being open) and on par with GlassWire's service+tray split.

**Settings:** centered two-column desktop-style popup (General/Notifications/
Appearance/Language/Runtime), one write path, header quick-controls synced.
Dark/light + **Arabic RTL** + 5 locales — **broader localization than most
competitors** (Fing added a handful of languages in 2026; the free tools are
English-only).

**Terminology / first-time discoverability — the honest weak spot.** ALLOW / LIMIT
/ CUT exist as chips; **HARD CUT has a tooltip and a note** ("Maximum isolation —
no forwarding, no monitoring") and the policy banners explain enforcement vs.
network-fault, and there is a warn/disclaimer. BUT there is **no onboarding, no
first-run walkthrough, and no legend** (grep confirms none). For a first-time user:
ALLOW/CUT are self-evident; **LIMIT's meaning (per-direction KB/s cap, userspace-
capped) and CUT-vs-HARD-CUT (observation suppressed, no live traffic) are not
obvious without reading tooltips**, and Monitor-vs-enforce is a subtle distinction.
The app would benefit (audit observation, not a redesign) from: a one-time legend
for the four modes, a short "what SharkNet does / use only on your own network"
first-run panel, and inline "why is this device managed?" provenance. CONFIDENCE
HIGH (code + i18n inspection). Real usability with users: **NOT TESTED**.

---

## 15. Background runtime

Event source is the **single pump tick** (`Hub.broadcast`, 1 Hz) which feeds the
NotificationManager **whether or not a UI client is connected** — so background
notifications work with the window closed, and there is **no second event
monitor**. The manager is a bounded queue + daemon worker with swallowed failures
(a failed toast can never destabilize the engine); the **presentation router**
picks exactly one renderer from **real window-visibility** (not a preference).
Single-instance guard + coordinated shutdown are idempotent and destroy the
notification window on exit.

**Does SharkNet now behave like a proper background Windows utility?** **By
code/logic, yes** — arguably better-architected than Fing (GUI-tied monitoring)
and comparable to GlassWire (service+tray). **What remains missing:** run-as-a-
Windows-Service (SharkNet backgrounds the *app*, it is not a true service that runs
before login / without a user session), and start-with-Windows exists as a setting
(HKCU Run) but wasn't validated on real hardware. CONFIDENCE MEDIUM-HIGH (logic
verified; live tray/toast/close-to-tray **NOT verified on Windows** — §30).

---

## 16. Notifications

Model: derived transitions (new/offline/online, cut/hardcut/limit, security) from
the pump snapshot → policy gate (12 categories, matching `DEFAULT_POLICY`) →
bounded queue → worker → **router** → one renderer (in-app WS toast when the window
is visible, custom frameless desktop toast when hidden, native balloon only as a
last-resort fallback). Burst grouping collapses a scan's new-device flood into one
notice **without touching the underlying events**; storm protection reuses the
manager's transition diff (no second engine). Localized via the backend loader in
the user's locale.

**vs. field:** richer and more Windows-consistent than Fing's push/email alerts,
NetAlertX's publisher plugins (Telegram/MQTT/ntfy — powerful but headless), or
GlassWire's toasts. The independence from enforcement (a failed/disabled
notification never changes ALLOW/LIMIT/CUT/HARD CUT) is explicitly test-enforced —
a maturity point most competitors don't document. CONFIDENCE HIGH (code); rendered
desktop toast on Windows **NOT verified** (§30).

---

## 17. Performance (CODE-LEVEL ASSESSMENT ONLY)

No runtime benchmark was run; this is structural.
- **Hot path is lean:** driver-side BPF filter (non-transit frames never reach
  userspace); GIL-atomic dict lookups instead of per-packet locks; effective
  block set precomputed at mutation time (no per-packet JSON/catalog); forward =
  rewrite 12 L2 bytes + re-inject original (no re-serialization); HARD CUT/CUT
  early-return before any parse. These are the right micro-decisions.
- **Userspace tax:** every *intercepted* (enforced or monitored) device's traffic
  round-trips through Python — the inherent cost of userspace ARP-MITM and the
  reason LIMIT caps throughput and ALLOW-unmonitored is left native.
- **Off-hot-path:** observation-only domain parsing is on a bounded async queue
  (drops overflow, never blocks the sniffer); history is a bounded ring; the
  visited-domains dict is capped (400); notification queue bounded (64).
- **1 Hz pump + WS:** one snapshot/sec, drains events once; cheap.
- **Likely bottlenecks (INFERRED):** CPU on the single capture/handle thread under
  heavy intercepted throughput (Python per-frame cost); the re-inject send is the
  dominant per-forwarded-packet cost by the code's own comment. **Scale limit:**
  this is a **single-host, single-subnet, modest-device-count** design — not an
  appliance for hundreds of devices at line rate.
- **Needs real-machine benchmarking:** max forwarded pps before drop, actual
  LIMIT accuracy vs. target kbps, CPU% under N intercepted devices, added latency.
CONFIDENCE MEDIUM (structure clear; numbers unmeasured).

---

## 18. Reliability / failure modes

| Scenario | SharkNet behaviour (code) | Rating |
|---|---|---|
| Startup, Npcap missing | `ensure_npcap()` refuses to start, opens download page | SAFE FAILURE |
| Server fails to start | launcher msgbox + guard release, no half-run | SAFE FAILURE |
| Engine exception on a frame | per-frame try/except-style guards; broadcaster wrapped | SAFE (skips frame) |
| Notification failure | swallowed; can't touch enforcement | SAFE |
| Gateway/interface change | re-scan; but interception targets a captured gateway MAC | PARTIAL (mid-session GW change not auto-re-homed — INFERRED) |
| Device leaves/returns | online/offline tracked; re-poisoned when managed+present | SAFE |
| MAC change (target) | identity re-keys; a blocked device with a new MAC = new device (unmanaged) → **block evadable by MAC rotation** | PARTIAL (shared with entire field) |
| ARP disruption / attack on host | Defender detects + (if Static ARP Lock) auto-heals | PARTIAL→SAFE with lock on |
| Engine crash while spoofing | `active_spoof.json` → next launch heals all targets' ARP | SAFE RECOVERY |
| UI crash | engine is a separate server; cleanup via atexit/shutdown | SAFE |
| Process duplication | single-instance guard activates existing window | SAFE |
| Shutdown | coordinated, idempotent (router→toast→tray→sink→cleanup→guard) | SAFE |
| Clean exit ARP restore | spoofer restores correct mappings; README "no device left offline" | SAFE (code) |

**Overall:** the failure design is a genuine strength — **safe-by-default,
crash-healing, idempotent**, better than the free cutters (which often leave a
victim's ARP poisoned on a hard exit) and philosophically aligned with Firewalla's
fail-open Simple mode. **The two honest PARTIALs** (mid-session gateway change;
block evasion by target MAC rotation) are shared with the whole ARP field.
Runtime validation of restore-on-crash on real hardware: **NOT TESTED** (§30).
CONFIDENCE HIGH (code paths); runtime: unverified.

---

## 19. Testing maturity

**383 automated tests, all passing** (measured), across 25 files. Breakdown:
enforcement/policy/equivalence (`test_phase7` 24, `test_hardcut` 18, `test_core`
10, `test_monitor` 14, `test_f3_hardening` 21, `test_hardening` 18,
`test_stage23_equivalence` 8); parsers/IO (`test_gate63_parsers` 17,
`test_stage1_io` 12, `test_stage2_npcap` 13, `test_gate64_scapy_removal` 6);
catalog/domains (`test_catalog` 9, `test_normalization` 12); identity/MAC
(`test_sharkmac` 14, `test_v29` 29); security (`test_defender` 3, `test_health`
5, `test_gate66_boundary` 5); V3.1 (`test_v31_runtime` 12, `test_notifications`
20, `test_v31_tray` 31, `test_v31_notify_router` 30, `test_v31_ux` 28); i18n 18;
UI-source regressions 6.

Maturity classification (as the prompt demands, no conflation):
- **AUTOMATED TESTED (logic):** policy classifier incl. all four modes and the 12
  transitions; domain normalization incl. URL/host reduction; service catalog
  compilation; token-bucket allow/deny; parser byte-equivalence to scapy oracle;
  notification manager + router (routing, grouping, storm, fallback, shutdown);
  tray controller + AppRuntime (fake pystray/window); settings API; SharkMAC
  adapter filtering; single-instance guard logic. This is **strong unit/logic
  coverage** — well above any competitor's *visible* test posture in this field.
- **BROWSER TESTED:** settings popup + notification card + SharkMAC empty state
  rendered and driven in a real browser against a demo server (dark/light/Arabic
  RTL) — per the handoff. Real DOM, not Windows.
- **STATICALLY REVIEWED:** the packet re-injection path, Npcap driver binding,
  `netsh`/registry side-effecting code.
- **MANUALLY TESTED (frozen app, real Windows):** per the handoff, only: app
  launch, `/api/runtime`, close-to-tray + single-instance via **log evidence**,
  settings persistence, tray-icon existence via window enumeration.
- **NOT TESTED (runtime):** actual packet drop/limit/forward on live LAN devices;
  ARP poisoning/restore on real hardware; tray menu clicks; rendered desktop
  toast; ALLOW/LIMIT/CUT/HARD CUT end-to-end on the wire; installer upgrade path;
  Windows-restart recovery.

**Critical honesty:** a green unit suite here proves the **decision logic**, not
that **packets move as intended** — the interception/injection/ARP layer is
inherently hardware/driver-bound and is the least runtime-verified part.
CONFIDENCE HIGH (test inventory measured).

---

## 20. Packaging / release maturity

Strong for a solo/small project: PyInstaller one-folder + Inno Setup with a
**stale-dist guard** in `build.ps1` (exit-code checks + refuses to build while the
app is running — a real release-integrity fix), preserved prior installers
(3.0.0/2.10.1/2.9.0/2.8.9 kept), version bumped consistently (server, installer,
version_info, cache-bust), SHA-256 discipline in the handoff, Npcap handled as an
external prerequisite (not bundled — correct licensing/scope). Frozen-artifact
contents were verified module-by-module (per handoff). **Gaps:** no code signing
(SmartScreen will warn), no auto-update channel, **upgrade (3.0.0→3.1.0) install
NOT tested**, no CI. vs. field: comparable to GlassWire/NetCut's installer
maturity, far ahead of the zip/CLI Linux tools, behind commercial signed/auto-
updating products. CONFIDENCE HIGH (artifacts + handoff).

---

## 21. Documentation maturity

Present: a good `README.md` (features, architecture, how-it-works, requirements,
run, build, honest Notes/limitations), a very detailed internal `HANDOFF.md`, and
the prior `COMPETITIVE_AUDIT_v3.0.md`. **Missing for a public release:** LICENSE
(none — a real blocker for distribution/trust), CHANGELOG, user guide/onboarding
docs, a written security/threat model (the ARP-MITM trust model, what SharkNet
can/can't see, encrypted-DNS limits), troubleshooting guide, and formal release
notes. The README's "use only on networks you own/administer" ethic is present and
appropriate. CONFIDENCE HIGH (file inventory).

---

## 22. White-space analysis (combinations SharkNet actually ships)

From implemented code, SharkNet occupies a combination that no single competitor
matches:

**Active ARP LAN enforcement (4-mode + domain/service)** **+** **per-device
on-LAN traffic/domain visibility** **+** **host ARP self-defense with attacker ID**
**+** **native Windows background-app UX (installer/tray/notifications/RTL i18n)**
**+** **no router, no hardware, no cloud, no DNS reconfiguration.**

- The free ARP cutters have (1) but not (2)+(3)+(4).
- Fing has a scanner + (a weaker) block + alerts, but agent/subscription-gated,
  cloud-dependent, no per-device on-LAN domain visibility, thin host self-defense.
- Firewalla has (1)-(3) strongly but **requires an appliance** and is a mobile-app
  product, not a Windows utility.
- GlassWire has (2 host-only)+(4) but **cannot control another device**.
- DNS tools (Pi-hole/AdGuard/Control D) have service catalogs + DNS control but no
  per-device cut/limit and require being the resolver.

SharkNet's real white space: **"install one Windows .exe, see and control every
device on your LAN, defend your own machine, run quietly in the tray"** — with no
box, no subscription, no router login, no cloud account.

---

## 23. SharkNet limitations (direct)

Genuinely weaker / less mature than the field:
1. **No persistence / schedules / groups / parental profiles** — the entire
   "set-and-forget" lane (Firewalla/AdGuard/Fing) is absent (partly by deliberate
   safety choice, partly simply unbuilt).
2. **Service catalog is small** (47 vs ~151 AdGuard vs 400+ Control D) and
   **static** (no auto-update feed shipped).
3. **Device identity is mid-depth** — small OUI DB, no history, no confidence
   score, no grouping.
4. **Bandwidth LIMIT is coarse** (drop-based userspace, throughput-capped, no
   fair-queue/latency management).
5. **Single-host / single-subnet / modest-scale** — not an appliance for large
   networks; CPU-bound on one capture thread.
6. **Windows-only**; no Linux/macOS/mobile/router.
7. **No code signing, no auto-update, no CI, no LICENSE**, upgrade-install
   untested.
8. **Host-centric security** — not a whole-LAN IDS/IPS; no rogue-device detection.
9. **First-run discoverability** — no onboarding/legend; LIMIT and CUT-vs-HARD-CUT
   not self-evident.
10. **Runtime largely unverified on hardware** (the biggest single caveat).

## 24. Platform / infrastructure constraints (NOT design defects)

These are inherent to Windows + userspace + ARP-MITM and are shared by Windows
peers — they should **not** be scored against SharkNet as if a better
implementation would fix them:
- **No kernel `tc`/HTB shaping** — that is a Linux-kernel capability (EvilLimiter/
  TuxCut/Firewalla). A Windows userspace Npcap app cannot match smooth qdisc
  shaping without a custom kernel driver, which SharkNet deliberately avoids.
- **Userspace throughput tax on intercepted traffic** — intrinsic to owning the
  path in userspace; the reason ALLOW-unmonitored is native-speed.
- **Encrypted-DNS (DoH/DoT) and ECH erode domain/SNI visibility** — no passive
  on-path observer can follow these without becoming a decrypting proxy; Pi-hole/
  AdGuard face the same DoH-bypass problem.
- **QUIC has no cleartext name to read** — best-effort scoped-IP pinning is the
  honest ceiling without decryption.
- **Randomized MAC breaks stable identity** — unsolved at the MAC layer by *every*
  tool in the field; the only structural fix ties identity to a Wi-Fi credential
  and needs proprietary AP hardware (Firewalla AP7).
- **ARP-MITM is defeatable** by anti-ARP-spoof routers, AP/client isolation, and
  IPv6 paths — documented for Fing and Firewalla-simple too; it is the ARP model,
  not SharkNet specifically.
- **Switched-LAN download-side interception** can be incomplete on hardware-
  offload routers — a physics/topology reality (README already discloses it).

---

## 25. What SharkNet should NOT copy

- **Router-replacement / inline-gateway architecture (Firewalla Router mode):**
  would abandon SharkNet's "install an .exe, no network changes" white space and
  demand the user re-home their network. Wrong for the product.
- **Dedicated hardware / appliance (Firewalla, legacy Fingbox):** kills the zero-
  hardware value proposition.
- **Cloud-dependent recognition/persistence (Fing):** SharkNet's local-only, no-
  account, no-cloud model is a privacy/trust asset for a tool that sees LAN
  traffic; don't trade it for a bigger device catalog.
- **Linux-only kernel mechanisms (`tc`/HTB, netfilter IPS):** not portable to the
  Windows userspace model without a kernel driver SharkNet chose to avoid.
- **A generic priority-ordered rule engine:** SharkNet's computed-predicate model
  has *zero precedence ambiguity by construction*; an ordered rule list would
  reintroduce exactly the ambiguity it avoided (the prior v3.0 audit made this
  point and it still holds).
- **Persistent-by-default enforcement:** re-loading rules on boot would break the
  deliberate anti-surprise-cut safety posture; any persistence must be **opt-in**.
- **Decrypting TLS proxy for "visibility":** would destroy the trust model and
  create a far larger attack surface than the product warrants.

## 26. Patterns worth learning (reference only — NOT an implementation plan)

Clearly separated as the prompt requires:

**Useful reference (observe, don't necessarily build):**
- **NetAlertX's "(IP match)" confidence suffix + field-locking** — a lightweight,
  honest identity-confidence signal and a way to stop auto-sources clobbering
  curated fields. A genuinely good, low-cost idea.
- **AdGuard's HostlistsRegistry `services.json`** — a *community-maintained, auto-
  updatable* service catalog format; the reference point for catalog scale/freshness.
- **Firewalla's rule provenance + New Device Quarantine** — showing *why* a device
  is in a state ("Service preset: Netflix", "new-device quarantine") rather than a
  bare rule.
- **Control D's Block/Bypass/Redirect action model** — presenting service policy as
  a small set of clear actions.
- **NetGuard/GlassWire's per-app clarity** — the UX of making "what is this and why
  is it flagged" obvious.
- **Fing's crowd-corrected recognition feedback loop** — "did we get this right?"
  as an identity-improvement input.

**Recommended implementation:** *none in this audit.* (The prompt explicitly says
do not recommend implementation unless asked.) These are reference patterns; if/when
SharkNet chooses to close its identity/catalog/persistence gaps, they are the
sources to study — and, per §11/§25, any persistence must remain **opt-in** and any
rule layer must **compile to the existing predicates**, not become an ordered
evaluator.

---

## 27. Independent capability comparison (no ranking, no winner)

Each dimension describes observable capability; there is deliberately **no overall
score and no "best."**

- **Windows-native capability:** SharkNet, GlassWire, NetCut are full Windows
  citizens (installer/service-or-tray/GUI). AdGuard/bettercap run on Windows but
  are server/CLI. Fing Desktop is Windows-native but monitoring is GUI-tied.
  Firewalla/Pi-hole/NetGuard/Control D are not Windows apps (appliance/Linux/
  Android/cloud).
- **LAN enforcement:** Firewalla (inline kernel, strongest, needs box); SharkNet /
  NetCut / bettercap / EvilLimiter / TuxCut / Fing (ARP-based, no box); GlassWire
  (local host only, cannot touch other devices); DNS tools (DNS-refusal only).
- **Traffic visibility:** GlassWire (deep per-*process*, host only); Firewalla
  (DPI, whole LAN, appliance); SharkNet (per-device DNS/SNI/HTTP + bytes on LAN,
  no cloud); DNS tools (per-query, if they're the resolver); Fing/NetAlertX
  (presence, not flows).
- **Bandwidth control:** Firewalla (kernel fq_codel/CAKE, per-device+group);
  EvilLimiter/TuxCut (kernel HTB, Linux); SharkNet (userspace token bucket,
  per-device, Windows — coarser); everyone else: none.
- **Security — detection:** Fing/Firewalla/NetAlertX/GlassWire (varied breadth);
  SharkNet (host ARP-spoof detection + attacker ID). **active defense:** Firewalla
  (inline IPS); SharkNet/TuxCut/NetCut-Defender (host ARP protection); Fing (ARP
  block); NetAlertX (none).
- **Device identity:** Fing (deepest, cloud) / NetAlertX (most transparent, open,
  confidence signal) lead; Firewalla strong (+AP7 Wi-Fi-cred binding); SharkNet
  mid (solid basics, randomized-MAC label, no history/confidence); cutters/
  GlassWire shallow.
- **Automation (groups/schedule/persistence):** Firewalla/AdGuard/Control D/Fing
  strong; Pi-hole/NetAlertX partial; **SharkNet none (by design + unbuilt)**;
  cutters none.
- **UX / onboarding:** GlassWire/Fing/Firewalla polished commercial UX; SharkNet
  polished shell but no onboarding/legend; cutters minimal.
- **Background operation:** SharkNet/GlassWire/Firewalla/Pi-hole/AdGuard/NetGuard/
  Control D all run persistently; Fing GUI-tied (agent excepted); EvilLimiter/
  bettercap foreground.
- **Testing maturity (visible):** SharkNet has an unusually large *public* logic
  suite (383); most competitors publish no test posture (commercial) or vary
  (OSS). None of this is runtime/hardware proof for any of them.
- **Release maturity:** commercial products (signed, auto-update, CI) lead;
  SharkNet has a solid installer + integrity guards but no signing/auto-update/CI/
  LICENSE; the free cutters vary from maintained to abandoned.

---

## 28. Final assessment

**A. What SharkNet already does well (code-verified):**
Single-classifier four-mode enforcement with clean CUT/HARD-CUT semantics and
gateway/self protection; a lean, correct hot path (driver BPF, precomputed blocks,
zero-copy forward); honest coverage signalling (QUIC best-effort, `block_signals`);
per-device on-LAN domain visibility without DNS reconfiguration; host ARP self-
defense + attacker ID + Static ARP Lock; crash-safe idempotent recovery/shutdown;
a genuine Windows background-app shell (installer, tray, close-to-tray, single-
instance, custom notifications, 5-locale + RTL, dark/light); a data-driven,
honestly-labelled service catalog; a large passing logic test suite; a local-only,
no-cloud, no-account, no-router, no-hardware model.

**B. What SharkNet is missing:** persistence/schedules/groups/profiles; a larger
auto-updating service catalog; deeper identity (OUI DB, history, confidence);
group/fair-queue bandwidth control; multi-subnet/scale; code signing/auto-update/
CI/LICENSE; onboarding/legend; whole-LAN IDS/rogue-device detection.

**C. What is a real technical limitation (won't be fixed by better code on
Windows):** no kernel `tc`/HTB shaping; userspace throughput tax; DoH/DoT/ECH
visibility erosion; QUIC opacity; randomized-MAC identity instability; ARP-MITM
defeatable by anti-spoof routers/isolation/IPv6; switched-LAN download-side
interception gaps.

**D. What is a product/UX gap (fixable without fighting the platform):** no
onboarding/legend/toolt-forward first-run; small/static service catalog; no
identity history/confidence surface; no opt-in persistence (the RESERVED path);
missing LICENSE/CHANGELOG/user-docs/threat-model; no code signing.

**E. What should be verified on real hardware (see §30).**

**Product positioning (§22 restated):** SharkNet is primarily a **Windows-native
LAN controller** with strong secondary identities as a **per-device traffic
monitor** and a **host network-defense utility** — a **hybrid** whose closest
architectural relatives are **SelfishNet V3 / NetCut** (same ARP-on-Windows lane,
but SharkNet adds the app shell + self-defense + observation) and, conceptually,
a **single-host, no-appliance, no-cloud Firewalla-lite** for one PC's view of its
LAN.

---

## 29. Evidence & confidence (major conclusions)

| Conclusion | Basis | Confidence |
|---|---|---|
| SharkNet feature status (§2) | SharkNet code inspection | HIGH |
| HARD CUT is a userspace early-return blackhole, obs. suppressed (§7) | direct code trace + 18 tests | HIGH |
| LIMIT is userspace token-bucket, throughput-capped (§8) | code + README | HIGH |
| Kernel `tc`/HTB is a Linux-only capability gap (§8, §24) | competitor docs (EvilLimiter/TuxCut/Firewalla) | HIGH |
| Domain visibility = DNS/SNI/HTTP; QUIC/DoH/DoT/ECH gaps (§9) | code + protocol facts | HIGH |
| Service catalog = 47 svc/132 domains vs AdGuard ~151 (§10) | measured both (AdGuard JSON OBSERVED) | HIGH |
| No competitor solves randomized MAC at MAC layer (§11) | Fing/Firewalla/NetAlertX docs DOCUMENTED | HIGH |
| Fresh-session posture is a deliberate safety tradeoff (§11/§12) | `db.py` header + README | HIGH |
| Firewalla is the only inline-kernel IPS enforcement (§6/§13) | Firewalla docs (via search extract) | MEDIUM-HIGH |
| NetCut/SelfishNet bandwidth mechanism | CLAIMED, mechanism UNVERIFIED | LOW |
| "LANtern Control" is not a locatable ARP tool (§3) | web search, multiple collisions | HIGH |
| "InSpectre" is a category error (§3) | GRC + VUSec DOCUMENTED | HIGH |
| SharkNet failure design is safe/crash-healing (§18) | code paths | HIGH (logic) / UNVERIFIED (runtime) |
| Any SharkNet on-the-wire enforcement behaviour | — | **NOT TESTED** (§30) |
| Competitor versions/dates (§3) | official release pages, 2026 | HIGH where OBSERVED, else labelled |

---

## 30. Real-hardware verification list

None of the following is verified by this audit or (per the handoff) by prior work;
they require a real Windows LAN with cooperating test devices the tester owns:

1. **ALLOW/LIMIT/CUT/HARD CUT on the wire** — that a real target device actually
   keeps full speed / is throttled to ~target kbps / loses all connectivity / is
   fully isolated, in both directions.
2. **LIMIT accuracy** — measured throughput vs. configured KB/s, up and down, incl.
   the download-side hardware-offload caveat.
3. **ARP poison + restore** — that targets are MITM'd and that clean exit / crash-
   recovery (`active_spoof.json` heal) leaves no device offline.
4. **HARD CUT vs CUT observably** — hard-cut device shows zero live traffic while a
   cut device still shows blocked attempts.
5. **Domain/service blocking end-to-end** — a real browser reaching a blocked
   service is stopped (DNS/SNI/HTTP), and the QUIC best-effort scoped-IP pin
   behaves as designed.
6. **Defender** — trigger a controlled ARP spoof of the host and confirm detection,
   attacker identification, and Static ARP Lock auto-heal.
7. **Tray/GUI** — tray Open/Notifications/Exit, close-to-tray, restore, no orphan
   process/tray icon after Exit, single-instance activation, start-with-Windows.
8. **Custom desktop notification** — appears bottom-right on the work area, does not
   steal focus, hidden from taskbar/Alt+Tab, click restores the existing window.
9. **Installer** — clean install, upgrade 3.0.0→3.1.0, uninstall, Npcap-missing
   path, on real Windows 10 and 11.
10. **Performance** — max forwarded pps before drops; CPU% under N intercepted
    devices; added latency; behaviour at higher device counts.
11. **SharkMAC** — actual MAC change/randomize/restore on real Ethernet and Wi-Fi
    adapters, and that Bluetooth is correctly excluded on varied hardware.
12. **Encrypted-DNS reality check** — confirm that a device using DoH/DoT indeed
    bypasses SharkNet's domain visibility/blocking (to keep marketing honest).

---

*End of report. This audit inspected code and current external evidence only; it
modified no SharkNet source, ran no build, and performed no Git operation.*
