# SharkNet — Competitive / GitHub Benchmark & Product-Direction Audit
**Version audited:** SharkNet v3.0.0 (released, built, frozen) · **Date:** 2026‑09‑12
**Type:** Competitive intelligence + architecture decision. **No code was changed. No v3.1 was planned. No git operations.**

Evidence is drawn from three parallel source‑level research passes over real GitHub repositories and authoritative docs (RFC editor, Cloudflare, Mozilla, Npcap). Claims that could not be verified against source/primary docs are marked **UNVERIFIED**.

---

## PHASE 1 — Current SharkNet baseline (verified against source)

**Engine.** Python + native Npcap. Exactly **one** enforcement mechanism: ARP‑MITM (spoof gateway↔device) → userspace packet forward → `policy.py` classifier → drop / limit / forward. Scapy is test‑only (removed from runtime at the gate63/64 migration).

**The invariant (state.py, policy.py) — confirmed exactly as documented:**
- `is_managed(dev)` = **ENFORCEMENT** (mode ∈ {cut,limit} OR device blocked/services OR any network‑scope rule). self/gateway never managed.
- `dev.monitor` = **OBSERVATION** (intercept + observe, never enforce).
- `is_intercepted(dev)` = `is_managed ∪ monitor` = **who we MITM**.
- `select_target()` uses interception; `action_for()` decides drop/limit/forward from **enforcement only** → a monitored‑ALLOW device is observed but FORWARDED. Per‑packet precedence is fixed: blocked‑domain → cut → limit → forward (most‑restrictive wins). Scopes device ∪ network (union, most‑restrictive), precomputed into `dev.eff_blocked`.

**Device model (`Device`).** IP‑keyed at runtime, **MAC‑keyed in the DB**. Fields: vendor (OUI), hostname (passive DHCP opt‑12 + mDNS), name (user rename), name_source, is_gateway/is_self, online, first/last_seen, dtype, mode, down/up_kbps, monitor, live down/up_bps, observed `domains`, `blocked`, `services`, `eff_blocked`, scoped‑QUIC `blocked_ips`, `recent_dns`. **Absent:** `stable_id`, `known_ips[]`/`known_macs[]` history, `trust_state`, `identity_confidence`, identity history, groups.

**Persistence (`db.py`).** Only the `devices` table is **loaded** (names survive restart). `rules` and `domain_blocks` are **written but deliberately never loaded** — "fresh session = allow, no surprise‑cut" (scanner re‑applies only *this session's* rules to reappearing devices). `traffic` table removed in V3.0; History runs off the in‑memory ring (`history.py`).

**Surface.** 28 REST routes + `/ws` + `/`. **6 event kinds:** attack, enforce_error, mac_change_failed, mac_changed, new_device, recovered. **Service catalog: 47 services**, data‑driven (`services.json`) — 36 streaming / 5 social / 4 music / 1 messaging / 1 gaming. **239 tests.**

**Security.** Per‑process `API_TOKEN` (`secrets.token_urlsafe(24)`) injected into `/`, required (+ Origin = localhost) on all `/api/*` and the WS handshake. All subprocess calls list‑form.

**Self‑defense suite.** Defender (passive ARP‑spoof/gateway‑impersonation watchdog + attacker identification), static ARP lock (`protection.py`), gateway protection, crash recovery (`recovery.py`), idempotent `cleanup()` restoring ARP on exit.

**Two findings that pre‑shape everything below:**
1. **Service Catalog + a central policy classifier already substantially exist.** `services.py` is a proper data‑driven catalog (id/name/category/regions/domains/quic/confidence); `domains_for()` *is* the service→rule compiler; `identify()` classifies observed traffic; `policy.py` is already the single source of truth. So the earlier spec's "System 2 (Rules Engine)" and "System 3 (Service Catalog)" are **largely built**.
2. **Network Lock / persisted trust / scheduling would *invert* a deliberate safety invariant.** The design refuses to load policy on startup specifically to avoid surprise‑cutting. Autonomous, persistent, "act on devices as they appear" behavior is the *opposite* of today's fail‑safe. That is the single biggest safety decision in the whole proposal.

---

## PHASE 2 — Competitors inspected (real repos / primary docs)

| Project | Repo / source | Stars · activity | Lang | Category |
|---|---|---|---|---|
| **EvilLimiter** | bitbrute/evillimiter | ~2.0k · maintained | Python | ARP limit/cut (Linux) |
| **bettercap** | bettercap/bettercap | ~20k · very active | Go | MITM/recon framework |
| **SelfishNet V3** | nov0caina/SelfishNet | ~243 · active | C# | Windows ARP limit+block |
| **elmoCut** | elmoiv/elmocut | ~353 · | Python/Qt | Windows ARP cut (+disclaimer) |
| **NetCut** | arcai.com (closed) | commercial | — | ARP cut + limit + Defender |
| **SelfishNet (classic)** | selfishnet.org (closed) | legacy | — | ARP limit/block |
| **TuxCut** | a-atalla/tuxcut | ~250 · **archived** | Python | ARP cut + tc limit (Linux) |
| **CSArp‑Netcut** | globalpolicy/CSArp‑Netcut | ~121 | C# | Windows cut‑only (blackhole) |
| **arp‑scan** | royhills/arp‑scan | ~1.3k · active | C | discovery only (OUI DB) |
| **NetAlertX** | jokob‑sk/NetAlertX | ~7.1k · very active | Python | inventory + new‑device alerts |
| **InSpectre** | thefunkygibbon/InSpectre | new · feature‑dense | Py+React | **self‑hosted NAC‑lite (twin)** |
| **Fing / Fing Desktop** | fing.com (closed) | commercial | — | device recognition + tools |
| **GlassWire** | glasswire.com (closed) | commercial | — | per‑app firewall + graph |
| **Firewalla** | firewalla.com (closed) | commercial HW | — | family/SMB security appliance |
| **Pi‑hole** | pi‑hole/pi‑hole | ~61k · very active | C/PHP | DNS sinkhole |
| **AdGuard Home** | AdguardTeam/AdGuardHome | ~37k · very active | Go | DNS filter + service catalog |
| **NetGuard** | M66B/NetGuard | ~3.9k · active | Java | per‑app firewall (Android) |

**Data gap (honest):** the "LANtern Control" the SharkNet author studied could **not** be independently located as an ARP‑based repo — the only public `lan-control` (ythx‑101) is a smart‑home actuation hub, not a cut/limit tool. Analysis of "LANtern" below relies on the author's earlier study (pcap forwarding, `LibPcapLiveDevice`+`FrameRouter`, same as SharkNet). **SelfishNet V3 (C#) is the confirmed Windows platform twin.**

**The framing fact (bandwidth *limiting*).** Graduated limiting has only two implementations: **kernel offload** (Linux `tc`/HTB — EvilLimiter, TuxCut) or **userspace token bucket** (SharkNet). **On Windows the userspace path is the only option** — Npcap itself states it "does not provide the appropriate support for … traffic shapers, QoS schedulers and personal firewalls." Every other tool (NetCut, bettercap, CSArp, elmoCut) only does a full **CUT**, not a rate limit. SharkNet's peers that *limit* on Windows must use SharkNet's exact approach.

---

## PHASE 3 — Competitive matrix (SharkNet vs the field)

Legend: ● full · ◐ partial · ○ none · ? unverified

### Network control
| | Cut | Bandwidth **Limit** | Per‑device rules | Bulk | Network‑wide | Quarantine | Scheduling | Windows native |
|---|---|---|---|---|---|---|---|---|
| **SharkNet** | ● | ● (userspace) | ● | ● | ● | ○ | ○ | ● |
| EvilLimiter | ● | ● (tc/HTB) | ● | ◐ | ○ | ○ | ○ | ○ (Linux) |
| bettercap | ● (ban) | ○ | ◐ caplets | ◐ | ◐ | ○ | ○ | ● (Npcap) |
| SelfishNet V3 | ● | ● (userspace) | ● | ? | ○ | ○ | ○ | ● |
| NetCut | ● | ● ? | ● | ? | ? | ○ | ○ | ● |
| elmoCut | ● | ○ | ◐ | ● (all) | ○ | ○ | ○ | ● |
| Firewalla | ● | ● (routed) | ● | ● groups | ● | ● | ● | ○ (appliance) |
| Pi‑hole / AdGuard | ○ | ○ | ● (DNS) | ◐ groups | ● | ○ | ◐/● | ○ (server) |

### Device management / identity
| | Discovery | Stable identity | IP/MAC history | Hostname | Vendor/model | Trust state | Groups/person | Randomized‑MAC |
|---|---|---|---|---|---|---|---|---|
| **SharkNet** | ● ARP+mDNS+DHCP | ○ (MAC‑keyed names) | ○ | ● | ◐ OUI | ○ | ○ | ○ |
| InSpectre | ● multi | ● hostname grouping + IP‑pin | ● | ● | ◐/● Fingerbank | ◐ | ● person/presence | ◐ hostname‑bridge |
| NetAlertX | ● plugins | ◐ MAC inventory | ● | ● | ◐ | ○ | ◐ node group | ○ (refuses to merge) |
| Fing | ● | ◐ | ? | ● | ● model/OS (crowd) | ○ | ◐ | ? |
| Firewalla | ● | ◐ | ◐ | ● | ● | ◐ | ● groups | ? |

### Domain / service control
| | Domain block | Visited visibility | Service presets | Catalog updatable | Categories | QUIC handling | Honest limits |
|---|---|---|---|---|---|---|---|
| **SharkNet** | ● inline (DNS+SNI+HTTP) | ● read‑only tab | ● 47, data‑driven | ○ (shipped file) | ◐ | ● scoped UDP/443 drop | ● in‑UI disclaimer |
| Pi‑hole | ● DNS only | ● query log | ◐ lists | ● gravity | ◐ | ○ | ◐ |
| AdGuard Home | ● DNS only | ● | ● blocked‑services | ● **HostlistsRegistry** | ● | ○ | ◐ |
| NetGuard | ● per‑app | ● | per‑app | n/a | ○ | n/a | ● |
| Firewalla | ● routed | ● | ● categories | ● | ◐ | ? |

### Security / safety
| | ARP‑attack detection | Self‑protection | Gateway protection | Fail‑safe shutdown | Crash recovery | Local API security |
|---|---|---|---|---|---|---|
| **SharkNet** | ● Defender | ● static ARP lock | ● | ● restore ARP | ● | ● token+Origin |
| NetCut | ● Defender | ● | ? | ? | ? | n/a |
| TuxCut | ○ | ◐ static ARP | ○ | ◐ | ○ | n/a |
| bettercap / EvilLimiter / elmoCut | ○ | ○ | ○ | ◐ | ○ | n/a |
| Firewalla | ● IDS/IPS | ● (appliance) | ● | ● | ● | ● |

**Reading of the matrix:** SharkNet is the **only tool that combines active ARP control (cut/limit/block) with a self‑defense posture, as a native install‑and‑run Windows app.** It trails the dashboards on identity/alerts and Firewalla on rules/schedules/groups, and trails EvilLimiter only on raw throughput (a Windows‑inherent gap).

---

## PHASE 4 — Critical evaluation of the previously‑proposed features

| Feature | Who has it (best) | Already in SharkNet? | Touches enforcement path? | Value | Complexity | Risk | Verdict |
|---|---|---|---|---|---|---|---|
| **A. Device Identity** | InSpectre (grouping+IP‑pin+person) | No (MAC‑keyed names only) | **No** (observation metadata) | High | Med | **Low** | **BUILD — P0** |
| **B. Central Rules Engine** | Firewalla (action+target+device+schedule) | **Yes** (policy.py + computed predicates) | Yes if you rewire it | Med | Med‑High | Med | **DON'T replace classifier; add thin provenance/persistence only** |
| **C. Service Catalog** | AdGuard (HostlistsRegistry) | **~80% built** | No (data only) | Med‑High | Low | Low | **EXTEND — P1** |
| **D. Network Lock** | Firewalla / Fing | No | **Yes (autonomous)** | High | High | **High** | **P2, observe‑first, opt‑in** |
| **E. Quarantine** | Firewalla | No | Yes (= CUT+source) | Med | Low | Med | **Fold into D** |
| **F. Scheduling** | AdGuard / Firewalla | No | Yes (autonomous) | High | Med | Med | **P1‑P2, session‑scoped only** |
| **G. Profiles / Groups** | Firewalla / InSpectre | No | No (targeting convenience) | Med‑High | Med | Low | **P1** |
| **H. Traffic Intelligence** | GlassWire | **Yes** (ring + chart + Visited) | No | Med | — | — | **Keep; persistence rejected** |
| **I. ARP attack detection** | NetCut | **Yes** (Defender) | No | High (moat) | — | — | **Keep/strengthen** |
| **J. Self‑protection** | Firewalla | **Yes** (ARP lock/gateway/token) | No | High (moat) | — | — | **Keep — untouchable** |

**Key nuances:**
- **B (Rules Engine):** the existing computed‑predicate model has **zero precedence ambiguity** by construction. A priority‑ordered rule *list* (the spec's `priority` field) would *reintroduce* ambiguity SharkNet deliberately avoided. What's genuinely missing is **rule provenance** (why is this blocked? "Service preset: Netflix" not "rule #84") and, *if/when* scheduling lands, a persisted rule store. Add those as a thin layer that **compiles down to the same per‑device predicates** — do not turn `policy.py` into an ordered evaluator.
- **D (Network Lock)** and **F (Scheduling)** are the only proposals that require policy to **survive restart and act without a human** — inverting the fail‑safe. They are valuable (they're Firewalla's core), but they are where SharkNet can hurt its own user (lock‑out) and must be **observe‑first** (detect + alert on unknown devices; enforce only on explicit, per‑device opt‑in) with **bulletproof controller/gateway protection detected, never assumed.**
- **A (Device Identity)** is the highest‑value, lowest‑risk item and is a **prerequisite** for D, F, and G — you cannot "trust a device," "group a person," or "lock the network to known devices" without stable identity first.

---

## PHASE 5 — Best ideas from other projects (with recommendation)

1. **InSpectre — stable identity by grouping.** Same‑hostname self‑healing merge (`laptop` + `laptop.lan` → one device), **primary‑IP pinning** (stops IP flapping), **protected manual grouping** (never silently undo a user split/merge), "**people, not MACs**" + At‑Home/Away presence. *Adopt.* Observation‑only, zero enforcement risk. **Randomized‑MAC caveat: bridge only via a persistent secondary signal (hostname), always user‑confirmable — never assert "same physical device" without evidence.**
2. **Firewalla — named rule = action + target + device + schedule** (targets: app/category/domain/IP/region). *Adopt the model* as the **compile‑target UI** for rules once groups/scheduling exist — but keep the computed classifier underneath.
3. **AdGuard — externalized service catalog** (`HostlistsRegistry`: one file per service, `id`=filename, `name`/`group`/`icon_svg`/`rules[]`, community‑PR, **deletions forbidden**, compiled to one `services.json`). *Adopt.* Externalize SharkNet's 47‑service catalog to a user‑droppable/updatable file with stable never‑deleted ids and category groups; consider importing AdGuard's list to expand coverage (verify license). SharkNet's edge: it can enforce the *same* catalog at **three layers (DNS + SNI + HTTP)** — defense‑in‑depth a sinkhole can't match.
4. **Control D — rule precedence + `redirect` action** (custom → service → filters; block/bypass/redirect). *Partial.* SharkNet already has fixed precedence; a "redirect a blocked domain to a warning page" is interesting for family use but = DNS injection (see item 6 tension).
5. **bettercap `ban` / NetCut / CSArp — blackhole CUT (poison‑without‑forward).** A pure CUT needs no per‑packet forward; just stop forwarding / poison the gateway. *Adopt as an opt‑in* for pure‑cut devices → frees handler throughput for LIMIT devices. Tradeoff: you lose observation of a blackholed device.
6. **Pi‑hole model → "DNS‑sinkhole for free."** Because SharkNet already forces the device's DNS through itself, it *could* answer a blocked domain's query with NXDOMAIN inline — Pi‑hole's efficiency/reliability with **no** Pi‑hole deployment requirement, and it works on the **query/upload path SharkNet reliably sees** (sidestepping the switched‑LAN download‑interception weakness). **⚠ Collides with the earlier "no SharkDNS" constraint — presented as an option requiring your decision, not a recommendation.**
7. **Fing — crowdsourced fingerprint + QR device recognition.** Identify model/OS, not just OUI vendor; QR as assisted‑ID for "unknown device." *Consider* (better identity; QR is elegant).
8. **NetAlertX / InSpectre — notification fan‑out** (ntfy/Telegram/Apprise) for **new‑device / attack** alerts. *Adopt (P1)* — a natural fit for the "defend" positioning; SharkNet already emits `new_device` and `attack` events.
9. **arp‑scan — OUI DB + probe self‑throttling.** *Minor* — SharkNet has OUI; self‑throttling the scan is cheap network politeness.
10. **lan‑control — multi‑source discovery fallback** (SSH→ARP→nmap→mDNS→UPnP). *Consider* for richer discovery, at the cost of new dependencies.

---

## PHASE 6 — SharkNet's real product position

**Category to own: "LAN Control **+ Self‑Defense** for Windows — install‑and‑run, no appliance, no Docker, no Pi."**

The competitors each own a different lane:

| Product | Owns |
|---|---|
| NetCut / SelfishNet / elmoCut | raw ARP **cut** tool |
| Firewalla | **family/SMB security appliance** (needs hardware) |
| NetAlertX / InSpectre | self‑hosted **inventory / NAC‑lite** (needs Docker/Linux) |
| Fing | universal **device recognition + troubleshooting** |
| GlassWire | per‑app **personal firewall** (host‑centric) |
| Pi‑hole / AdGuard | **DNS filtering** (needs to be the resolver) |

**SharkNet's whitespace** is the intersection nobody occupies: an **active ARP controller (cut/limit/block/observe) that also *defends itself and the LAN*** — ARP‑spoof detection, static ARP lock, gateway protection, per‑process API security — delivered as a **polished native Windows app with zero infrastructure**. Firewalla has the defense but needs hardware; the OSS dashboards need Docker/Linux and don't enforce like SharkNet; the raw cutters have none of the defense. **The self‑defense posture is SharkNet's single most differentiated, hardest‑to‑copy asset** — lead with it. Positioning tagline candidate: *"Control and defend your LAN from one Windows app."*

---

## PHASE 7 — Architectural verdict

**Primary recommendation: OPTION B — add new policy / identity / observation layers *above* the existing enforcement engine.**

Everything valuable in the roadmap (identity, groups, scheduling, richer catalog, network lock) is **metadata, targeting, and scheduling** that can **compile down to the existing per‑device predicates** (`mode`, `blocked`, `services`, `monitor`, and the network‑scope sets). None of it requires touching the packet path. The research is unanimous that SharkNet's enforcement core is **the correct and only viable Windows approach** — validated by SelfishNet V3 (same userspace path) and by Npcap's own shaper limitation.

- **Reject OPTION C (refactor enforcement).** It is the crown jewel, it works, and the alternatives are Linux‑only or require a signed WFP kernel driver.
- **Reject OPTION D (adopt another project's architecture).** InSpectre is a **feature blueprint**, not a stack to copy — it's Docker/Linux/Postgres/React, the wrong shape for a native Windows app.
- **OPTION A (incremental)** is essentially B done conservatively — acceptable, but B *names* the discipline: a clean **layered architecture**, engine frozen underneath.

### What must NOT change (extremely important)
1. **The enforcement engine** — ARP‑only MITM, the single `policy.py` classifier, the `is_managed / is_intercepted / monitor` invariant, the computed‑predicate model (no ordered rule list), the token bucket, forward‑then‑drop semantics.
2. **The fail‑safe design** — fresh session = allow, **no surprise‑cut**, ARP restored on stop/exit, crash recovery. (Persisted/autonomous policy must be strictly opt‑in and never the default.)
3. **The security model** — per‑process token + Origin guard on `/api/*` and `/ws`.
4. **The self‑defense suite** — Defender, static ARP lock, gateway protection.
5. **The honesty stance** — no faked enforcement, accurate in‑UI limitation disclaimers, "observation ≠ enforcement."

---

## PHASE 8 — Feature priority matrix

| Feature | Value | Complexity | Risk | Priority | Note |
|---|---|---|---|---|---|
| **Device Identity + grouping** (observation‑only; stable_id, trust, confidence, IP‑pin, user‑confirmable) | HIGH | MED | LOW | **P0** | prerequisite for D/F/G; no engine change |
| **Notifications** (new‑device / attack → ntfy/Telegram) | MED | LOW | LOW | **P1** | fits "defend"; events already emitted |
| **Service Catalog externalization + expansion** | MED‑HIGH | LOW | LOW | **P1** | AdGuard model; data only |
| **Groups / Profiles** | MED‑HIGH | MED | LOW | **P1** | extends bulk + identity |
| **Scheduling** (active only while app runs) | HIGH | MED | MED | **P1‑P2** | session‑scoped preserves fail‑safe |
| **Rule provenance/source layer** (+ optional persisted store) | MED | MED | MED | **P2** | support layer, NOT an ordered evaluator |
| **Network Lock** (observe‑first, opt‑in quarantine) | HIGH | HIGH | **HIGH** | **P2** | after identity+trust; protected‑set guarantees |
| **Blackhole‑cut** optimization (opt‑in) | MED | MED | MED | **P2** | throughput headroom for LIMIT |
| **Quarantine** (standalone) | — | — | — | **FOLD into Network Lock** | = CUT + source |
| **Traffic‑history persistence** | LOW‑MED | MED | MED | **REJECT/defer** | breaks session‑only design |
| **Persist rules across restart (default)** | — | — | HIGH | **REJECT** | breaks no‑surprise‑cut; opt‑in only |
| **DNS‑answer injection for blocks** | HIGH | MED | MED | **DECISION NEEDED** | best‑of‑both, but vs "no SharkDNS" |
| **Kernel/WFP shaping** (raise throughput) | MED | HIGH | HIGH | **REJECT (for now)** | signed driver; abandon Windows‑userspace simplicity |
| **ARP protection / self‑defense** | HIGH | — | — | **DONE — keep** | the moat |

---

## PHASE 9 — Recommended product blueprint

1. **Core identity.** *"Control **and defend** your LAN from one native Windows app — no appliance, no Docker, no Pi."*
2. **Core UX.** A humanized device list (identity, group/person, trust, live traffic), one device modal that unifies **Control (cut/limit/allow) + Observe (Monitor) + Policy (domains/services)**, honest empty/limitation states, and non‑intrusive **new‑device / attack alerts** (in‑app + optional push).
3. **Core architecture.** **Layered.** Enforcement engine **frozen**. Above it: an **Identity service** (correlates MAC/IP/hostname into stable, user‑confirmable identities), a **Policy/persistence layer** (rules with provenance; opt‑in persistence), a **Scheduler** that only runs while the app is controlling, and a **Notification fan‑out**. Every upper layer **compiles to the existing per‑device predicates** — the packet path never learns about "identities," "groups," or "schedules."
4. **Device model direction.** Add `stable_id` (MAC‑primary; hostname/DHCP‑fingerprint as a *secondary, confirmable* bridge), `known_ips[]`/`known_macs[]`, `trust_state` (unknown/known/trusted/blocked), `identity_confidence`, minimal identity history. **Never auto‑assert two MACs are one device** — probabilistic + user‑confirmable, matching what NetAlertX/InSpectre proved is the only honest option.
5. **Policy/rules direction.** Keep the computed classifier. Add **provenance** ("blocked by: Service preset Netflix") and an **opt‑in persisted store**; feed **schedule** and **group** as *inputs* that recompute the same predicates. Do **not** build a priority‑ordered rule list.
6. **Service‑control direction.** Externalize the catalog (updatable file, stable/never‑deleted ids, categories, icons, per‑service enable); optionally seed from AdGuard's list. Keep tri‑layer (DNS+SNI+HTTP) enforcement and honest coverage (`block_signals`).
7. **Network‑security direction.** Keep Defender / ARP lock / gateway protection. Add **Network Lock as observe‑first**: detect + alert unknown devices; enforce (quarantine) only on explicit per‑device opt‑in, with the protected set (host/gateway/infrastructure) **detected, never hard‑coded**, and full ARP restore on stop/exit.
8. **Monitoring direction.** Keep the ring + Visited Sites; add push notifications. No long‑term traffic persistence (deliberate).
9. **Persistence direction.** Identity persists. **Rules stay session‑only by default**; persistence and schedules are explicit opt‑ins, and schedules act only while the app runs — the fail‑safe is never silently traded away.
10. **Extensibility.** Data‑driven service catalog + a future notification/integration manifest model (InSpectre/NetAlertX pattern), all above the frozen engine.

---

## PHASE 10 — Executive verdict

1. **What SharkNet already does exceptionally well.** Per‑device bandwidth **LIMIT on Windows** (a rare club — userspace is the only Windows path and SharkNet is in it); the **observation / enforcement / interception separation** (cleaner than any competitor); the **self‑defense suite** (unique among controllers); **honesty** (no faked enforcement, accurate disclaimers — validated by the ECH/QUIC research); **native install‑and‑run** with **5‑language i18n**; and the **single‑classifier** policy design.
2. **Where SharkNet is weaker.** Stable device **identity/grouping** (InSpectre), **scheduling** (AdGuard/Firewalla), **notifications** (NetAlertX), **device recognition depth** (Fing), **catalog updatability** (AdGuard), and raw **throughput** (EvilLimiter's kernel shaping — but that gap is Windows‑inherent and shared by every Windows peer).
3. **Best idea per category.** Identity → **InSpectre**. Rules model → **Firewalla**. Service catalog → **AdGuard**. Scheduling → **AdGuard/Firewalla**. Cut efficiency → **bettercap `ban`**. Device recognition → **Fing**. Alerts → **NetAlertX/InSpectre**. Blocking reliability → **Pi‑hole (DNS model)**.
4. **Adopt.** InSpectre identity‑grouping + IP‑pin + trust/person; AdGuard externalized catalog; Firewalla rule *model* (as a compile‑target); bettercap blackhole‑cut (opt‑in); push notifications; groups; session‑scoped scheduling.
5. **Do NOT adopt.** Kernel/tc shaping (impossible on Windows without a signed driver); per‑app blocking (no UID signal on a LAN); persisted‑autonomous rules **by default** (breaks fail‑safe); a **priority‑ordered rule list** (reintroduces ambiguity); a full appliance/Docker/Postgres/React stack (wrong for native Windows); **auto‑merging randomized MACs** (no tool does it honestly); long‑term traffic persistence.
6. **Is the current architecture fundamentally good?** **Yes.** The enforcement core is the correct and only viable Windows approach; research validates it end‑to‑end.
7. **Is a major rewrite justified?** **No.** Emphatically not. Freeze the engine and layer above it.
8. **Is the proposed Device Identity / Rules / Service Catalog / Network Lock direction right?** **Partially — right in spirit, wrong in priority and in one framing.** Device Identity = **yes (P0)**. Service Catalog = **yes, but mostly already built (P1 extension)**. Rules Engine = **no as a replacement** — keep the classifier, add only provenance/persistence. Network Lock = **yes but P2, observe‑first, highest‑risk** — the item to be most careful with, and the one that touches the enforcement/safety path (flag before any deployment, per your standing rule).
9. **Single BEST next development objective.** **Device Identity + Grouping — observation‑only** (stable_id, trust_state, confidence, IP‑pinning, user‑confirmable, with new‑device notifications). Highest value, lowest risk, **does not touch the enforcement engine**, and is the **prerequisite** for groups, scheduling, and Network Lock. InSpectre proves the design; NetAlertX proves the honesty constraint.
10. **What to leave completely untouched.** The enforcement engine and its invariant; the fail‑safe / no‑surprise‑cut design; the security model; the self‑defense suite; the honesty stance.

### One‑line decision
**Freeze the engine; build Device Identity + Grouping (observation‑only) next; treat Network Lock/Scheduling as opt‑in, observe‑first, restart‑safe layers on top — never as changes to the packet path.** SharkNet should become **"the Windows app that controls *and* defends your LAN,"** not another cutter, dashboard, or appliance.

---
*Prepared as a read‑only competitive‑intelligence + architecture‑decision report. No SharkNet code was modified; no v3.1 branch, commit, tag, or push was created.*
