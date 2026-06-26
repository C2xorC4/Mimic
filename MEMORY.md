# Mimic Project Memory

> **Depth is split between this file and LittleJohnnyMnemonic (LJM).** This
> `MEMORY.md` is the portable operational snapshot that travels with the repo
> (queue, lab state, validation results, handoff). LJM holds durable project
> context (`Memory/Project/mimic`), byte-level vectors
> (`Memory/Knowledge/net_os_fingerprint_deception_vectors`), and protocol-bug
> write-ups (`net_impacket_*`, `net_smb_*`). Recall LJM before re-deriving;
> don't duplicate Knowledge entries here.

## ★ METHODOLOGY RULE — develop & fidelity-test against a FRESH lab VM, never ss-book

**Always run mimic and scan it on a clean proxmox VM clone (or a recently-spun-up
one), NOT on ss-book (the dev daily-driver).** Proven 2026-06-24 by the host matrix:
the SAME binary that scored a muddled "Cisco ACE load balancer / conditions
non-ideal" on ss-book scored a clean 96–98% correct-OS on every wired VM host. ss-book
is contaminated by **Wi-Fi timing jitter** (corrupts nmap's SEQ rate probes →
scattered SP/ISR → decoy matches) plus **live daily-driver traffic** + the inbound-SYN
tap seeing real connections. This is environmental, NOT a mimic bug. The fix is the
substrate: a fresh wired VM clone eliminates it entirely.

- **Spin one with:** `python infra/proxmox/lab.py deploy <tpl> <clone> --linked --start`
  → `lab.py ip` → `lab.py prep` (Windows: fw-off + WinRM) → deploy mimic → scan from
  Kali (10.0.254.70) → `lab.py destroy`. Templates: win 9010/9011/9116/9119/9122/9125;
  linux 9302/9304/9306/9310/9311/9341. Harnesses: `scratchpad/matrix_winvm.ps1`,
  `matrix_linuxvm.sh` (this session). WinRM admin sessions are already ELEVATED (no UAC
  on the VM, unlike ss-book). Linux clones need `libpcap` installed (apt/dnf/pacman).
- ss-book stays the DEV/build host (edit, `go build`, unit tests); fidelity scans go to
  a VM. If ss-book MUST be used, wire it (no Wi-Fi) + quiesce background traffic first.

## Current Status (as of 2026-06-26; HiFi driver stability bug FIXED + matrix-validated)

> **★★ CHECKPOINT — HiFi DRIVER NETWORK-BREAK FIXED + FULL CAPTURED-PROFILE MATRIX
> GREEN (2026-06-26).** Branch `feat/hifi-ndis-driver`, commit `4d9755e`. The 2026-06-25
> driver stability bug is ROOT-CAUSED, FIXED, and validated across all 3 fidelity levels.
> Ready to merge to main pending user go.
>
> **Root cause (empirical, byte-level):** the mimic-hifi LWF rewrote the IP-ID and
> recomputed the IPv4 header checksum **while leaving the NIC's TX IP-checksum-offload
> request set** → the NIC re-checksummed on top (one's-complement double-add → `0xffff`) →
> every outbound IP packet shipped a bad header checksum → all outbound TCP dropped (host +
> WinRM lost connectivity) on any host with offload on (the default). TI=Z WAS on the wire;
> the host just couldn't talk. Confirmed by an offload-toggle A/B + tcpdump on a fresh
> Server-2016 VM (`captures/ss-book/matrix-2026-06-25/PHASE0-rootcause-2026-06-26.md`).
> Earlier OOB-write / stale-profile hypotheses were REFUTED by reading the source; the
> `device present: False` log line was a false negative (`Test-Path` on a `\\.\` device).
>
> **Fix (`driver/mimichifi/{filter.c,mimichifi.h,filter.h}`):** `MimicHiFi_RewriteIpId` gains
> `recomputeChecksum` — when IP-checksum offload is requested, change only the IP-ID and
> leave the checksum to the NIC (no double-add); recompute only when in-band. Skip LSO NBLs
> (`TcpLargeSendNetBufferListInfo`). Atomic ICMP IP-ID (`InterlockedIncrement16`); VLAN bound
> 22→38. Off-target unit test `test/rewrite_test.c` 15/15. Rebuilt via EWDK (mounted E:),
> re-signed with the VM-trusted `Mimic HiFi Test` cert (79B5; CurrentUser\My, no elevation).
>
> **Connectivity safeguard (`internal/stack/connmon_windows.go`, new):** while armed, ICMP-ping
> the gateway/canary every 5s via the mutated path; 3 sustained failures (~15s) auto-disarm to
> WinDivert and do NOT re-arm until restart. Operator policy `stack.high_fidelity_watchdog`
> (*bool, default ON = connectivity-priority; false = hold the deception AND deny an attacker
> an induced-degradation oracle) + optional `stack.high_fidelity_canary`. Validated on-VM: no
> false-trip on a healthy gateway; trips+disarms on induced loss (IP-ID 0→non-zero on the wire);
> holds when disabled.
>
> **★ VALIDATION MATRIX (captured profiles only — Win10/11, Srv2016/19/22/25; Linux
> Ubuntu/Debian/Fedora/Rocky/CentOS-7/Arch/Kali). STABILITY: PASS on all 3 runs.**
> Full report `captures/ss-book/matrix-2026-06-26-validation/SUMMARY.md`:
> | Backend (host) | Windows | Linux | Stable |
> |---|---|---|---|
> | WinDivert-std (Win) | EXACT 6/6 | family ~95% (TI=I ceiling) | PASS |
> | **hifi driver (Win)** | **EXACT 6/6** | **EXACT 7/7 (TI=Z)** | **PASS** |
> | eBPF (Linux) | family (top guess correct) | EXACT 7/7 | PASS |
> The hifi tier now reaches EXACT on BOTH families WITH stability; winstd vs hifi isolates the
> driver's value (same Linux persona 95%/TI=I → exact/TI=Z). eBPF/WinDivert paths untouched by
> the fix (Windows-only code). **Harness learning:** drive the VM out-of-band via the QEMU
> guest agent (`scratchpad/ga.py`, reuses lab.py PVE auth) so a connectivity blip can't strand
> the run — this is what made the matrix robust where the old WinRM harness self-severed.
>
> **REMAINING:** merge `feat/hifi-ndis-driver`→main (pending user go); then the deferred
> cleanup (drop the now-redundant WinDivert IP-ID-0 write for Linux personas when the driver
> is present) + backend build-out. Lab clones 9523/9524 destroyed post-matrix.

> **★ CHECKPOINT — FULL TRI-BACKEND MATRIX (2026-06-25 evening) + HiFi DRIVER
> STABILITY BUG (recovered 2026-06-26).** This run was executed the evening of
> 2026-06-25 and **never got written up** — an automatic Windows restart wiped the
> live session before annotation. All durable records (git/MEMORY/LJM/`driver/README`)
> stop at the 17:47 commit. The raw run survived in the *prior* session scratchpad and
> was copied into the repo: **`captures/ss-book/matrix-2026-06-25/`** (666 files: per-run
> `run_*.log`, per-backend result dirs `linuxvm_ebpf/`, `winvm_win-std/`, `hifi/`).
> NOTE: the `CROSSTAB.txt` in that dir is the **STALE 2026-06-24 aggregate** (mtime
> 06-24 21:52), NOT this run — it predates the eBPF ECN-carve-out exact fix; ignore it
> for this checkpoint.
>
> **Three backends swept (~33–34 profiles each), from Kali against fresh VM clones:**
> | Backend | Host | Outcome |
> |---|---|---|
> | **eBPF** | Linux VM | ✅ 34/34 CLEAN. Linux personas → `Linux 4.15 - 5.19`; Windows personas → correct Windows. (`run_ebpf.log` DONE 18:18) |
> | **WinDivert (standard)** | Windows VM clone 9521 | ✅ 34/34 CLEAN, zero instability. Win10→`Windows 10 1909`, Server 2019→`Server 2019` 99%, etc. (`run_winstd.log` DONE 18:12) |
> | **HiFi driver (mimichifi NDIS LWF)** | Server 2016 SeaBIOS clone 9522 | ⚠️ **EXACT but UNSTABLE** — see below. |
>
> **★ HiFi DRIVER STABILITY BUG (the headline finding).** The driver *does* deliver
> what `driver/README.md` claims — `TI=Z` on the wire, `OS details: Linux 4.15 - 5.19`
> EXACT — but **arming it knocks the VM off the network after 1–4 profiles, and it does
> not recover.** Proven across TWO independent runs (not a one-off):
> - **Run 1** (`run_hifi.log`, 17:56–18:08): driver installed, `sc query`=RUNNING, no
>   BSOD. Profiles 1–4 (Ubuntu/Debian/Fedora/Rocky) ALL → `Linux 4.15 - 5.19` EXACT.
>   Then *"Network connectivity to 10.0.250.183 has been lost… reconnection failed."*
>   AlmaLinux (#5) squeaked through on a reconnect job, then session unrecoverable → VM
>   destroyed.
> - **Run 2** (`run_hifi2.log`, 18:11–19:52): fresh clone. Profile 1 (Ubuntu) →
>   `Linux 4.15 - 5.19` EXACT. Then profiles #2–#27 ALL → **"WinRM unrecoverable, skip"**
>   (~3.5 min timeout each), never recovered.
> - **Differential:** standard WinDivert + eBPF ran their FULL matrices clean on their
>   own hosts. The instability is **specific to the LWF send-path**, not the harness/WinRM.
> - **Hypothesis (NOT yet logged/confirmed):** the LWF rewrites IP-ID + recomputes csum
>   on *all* outbound IPv4 TCP — incl. the WinRM management session — in
>   `FilterSendNetBufferLists` via the in-place MDL map (the "key fix" in README:110).
>   Non-determinism (4 vs 1 profile before drop) smells like a race or load-dependent
>   corruption intermittently mangling management packets, or arm/disarm wedging the NIC.
>   **Next:** repro under `MIMIC_WD_DEBUG`/driver tracing; consider scoping the rewrite
>   to exclude the management flow, or test a non-WinRM (serial/agent) control channel so
>   a connectivity drop doesn't blind the harness.
>
> **NET:** driver is functionally EXACT-capable (parity with eBPF) but **NOT yet matrix-
> stable** — the "VALIDATED EXACT" in `driver/README.md` (single-profile proof) holds, but
> sustained multi-profile cycling is the open defect. This is the top driver queue item.

> **★★ CHECKPOINT — LINUX-PERSONA EXACT (eBPF) + WinDivert T-series complete +
> Server 2019 EXACT = Windows 6/6 (2026-06-25).** Branch `feat/windows-port-linux-fidelity`.
> Commits: `3c317bc` → `ee1677a` → `e6694d4` → `c02033c`. Method unchanged: diff emitted
> vector vs nmap-os-db on a FRESH wired VM, fix each diverging indicator, re-scan.
>
> **1. ★ eBPF-LINUX EXACT (the headline) — `e6694d4`.** Ubuntu, Fedora, AND Arch personas
> on a fresh ubuntu-2204 VM (eBPF) → **`OS details: Linux 4.15 - 5.19` — clean EXACT, NO
> submit prompt** (was 99% aggressive guess). First no-submit-prompt Linux fingerprint. The
> ENTIRE 99%→exact delta was ONE field: the **ECN-probe SYN-ACK window**. Real Linux
> advertises FAF0 on the ECN probe but FE88 (=WIN) on the OS probes; `fingerprint.c` stamped
> `window_size` on every TCP packet → ECN W=FE88. Fix: carve-out keyed on the **ECE bit**
> (only nmap's ECN probe elicits ECE in the SYN-ACK) → override window FE88→FAF0 (7120→7210),
> Linux/macOS only. On a Linux host **TI=Z + the whole T-series are native-correct**, so the
> WIN/ECN profile-data fixes sufficed. Regenerated bytecode committed.
>
> **2. ★ Server 2019 → EXACT — Windows tally now 6/6 (`c02033c`).** **The prior "Server 2019
> is ISN-ceiling-capped at 99%" conclusion was WRONG.** Root cause was the **T1 F=EAS** tell:
> the `ecnCC` block set ECE on EVERY SYN-ACK (incl. SEQ/T1), not just the ECN probe. Gating
> the ECE-set to the ECN-probe flow (no-timestamp SYN) → Server 2019 T1=F=AS, ECN still CC=Y
> → **`OS details: Microsoft Windows Server 2019` EXACT** (its own edition). Win11/Server-2022
> controls stayed exact (ecnCC=false, unaffected). **EXACT TALLY (WinDivert, clean VM): Win10,
> Win11, Server 2016, 2019, 2022, 2025 = 6/6.**
>
> **3. WinDivert-Linux T-series complete + WIN/ECN/IP-ID alignment (`3c317bc`+`c02033c`).**
> All 16 Linux profiles WIN→FE88 (5.x/6.x) / 7120 (centos-7), WS8, ECN-W→FAF0; IP-ID
> per-protocol; crafted-RST CI zeroed. T-series closed: T1 F=AS, T2/T3 R=N (new WinDivert drop
> handle on NULL-flag/SYN+FIN open-port probes), T4/T6 S=A (seqFromAck), T5/T7 DF=Y. WinDivert-
> Linux: 89%→**95%** (modern) / **97%** (centos-7). Validated fresh Server-2022 host.
>
> **4. ★ WinDivert TI=Z is a HARD CEILING (`ee1677a`) → two-tier architecture.** Linux persona
> writes IP-ID 0 correctly (unit-tested `TestLinuxIPIDZero`) but the Windows IP transmit path
> RE-STAMPS a 0 Identification (RFC "unassigned" sentinel) BELOW WinDivert's injection point →
> TI/CI=I not Z. Validated negative vs Impostor+checksum send flags. nmap-os-db requires TI=Z
> (hard) for modern Linux ⇒ **WinDivert-Linux caps just short of exact** (the 95%/97% above is
> the max). **Decision (w/ user): TWO-TIER.** (a) DEFAULT = WinDivert (MS-signed, no custom
> driver; max reachable). (b) OPT-IN high-fidelity = a kernel packet-mod driver (recommended
> **WFP callout**, reuses `wfp_windows.go`, edits below the re-stamp + can rewrite ISN) behind
> `stack.high_fidelity: true`. eBPF is the only exact-capable Linux backend w/o a driver.
>
> **HARNESS / LAB LEARNINGS (load-bearing):** Cross-compile a static eBPF Linux binary from
> Windows: `CGO_ENABLED=0 GOOS=linux go build -tags nopcap ./cmd/mimic` (cilium/ebpf pure-Go,
> bytecode committed via go:embed → NO clang to BUILD, only to REGEN). bpf2go regen on a FRESH
> ubuntu VM needs 3 fixes: (a) `cloud-init status --wait` before apt (fresh-boot dpkg lock);
> (b) symlink `/usr/include/asm`→`/usr/include/x86_64-linux-gnu/asm` (clang `-target bpf` skips
> multiarch → `<asm/types.h>` not found; argus has the symlink, fresh templates don't); (c)
> Go 1.25 manual install (apt golang too old). The `*_bpfel.go` scaffold go:embeds the `.o` →
> only the `.o` changes on a C edit; always commit it, pull BEFORE destroying the VM. New
> harness `scratchpad/ebpf_build_scan.sh` (fresh-VM regen+build+scan). Go filename gotcha:
> `*_linux_test.go` = implicit GOOS=linux constraint (excluded on Windows even w/ //go:build).
>
> **REMAINING QUEUE:** opt-in WFP-callout driver (the high-fidelity tier — reaches WinDivert
> TI=Z + ISN); macOS still unbuilt; full matrix re-run to certify the older Win/Linux profiles.

> **★ CHECKPOINT — FULL HOST×PROFILE MATRIX + exact-match gap analysis (2026-06-24).**
> Full report: `captures/ss-book/matrix-report-2026-06-24.md`. Swept all 34 profiles ×
> 14 hosts (ss-book, argus, 6 Windows VM templates, 6 Linux VM templates), `nmap -O` from
> Kali. Harnesses: `scratchpad/matrix_winvm.ps1` (clone→WinRM-deploy→cycle→scan→destroy;
> WinRM admin = elevated, no UAC), `matrix_linuxvm.sh` (cloud clone→scp→eBPF→scan),
> `aggregate_all.py` (cross-tab), `osdb_refs*.txt` (nmap-os-db references).
>
> **RESULTS (buildable=33; macOS excluded as unbuilt):**
> - **Family-spoofing robust + host-edition-INDEPENDENT:** every clean working host →
>   33/33 family-correct (88–99%). All **6 Windows VM editions** (Win10/11, Server
>   2016–2025) give IDENTICAL results — the WinDivert mutation doesn't depend on host
>   edition (the validation goal). eBPF (Debian-family hosts) 96–98%.
> - **EXACT matches (no submit ask) = 2:** Windows Server 2025 on **argus** AND
>   **ubuntu-2204** (both eBPF). WinDivert tops at 99% (Win11) — 1 indicator short.
> - **ss-book contaminated** (Wi-Fi jitter + live traffic): only 19/33, 14 Windows-profile
>   X (decoy "Cisco ACE"). Same binary on a wired VM = 96–99%. → the fresh-VM rule above.
>
> **EXACT-MATCH IS ITERATION, NOT IMPOSSIBLE.** Decomposition of "why no exact":
> - **Class A — profile drift vs nmap-os-db (pure-data fix):** Server 2019/2022
>   `window_size` should be 65535 (profiles say 8192); Server 2016/2019/2022
>   `tcp_timestamps` should be true (ref OPS=ST11); Server 2016 `ip_id_behavior` random
>   (ref TI=RD). Win10-1909/Win11/Server-2025 already correct.
> - **Class B — code indicators:** OPS `ST10→ST11` ✅ FIXED+VALIDATED this session
>   (Win10/11 TS-on branch TSecr echo via inbound-SYN cache; Win11 96→99%). `CI=RD→I`
>   OPEN — closed-port RST carries nmap's IP-ID, needs the stack shared-incremental
>   counter (cross-package netfilter↔stack).
> - **Class C — structural ceiling:** SEQ `SP`/`ISR` ISN rate is the host kernel's (worst
>   on WinDivert); eBPF reaches exact most readily. Document where it bites.
>
> **INFRA FINDINGS (from per-template testing):**
> - **libpcap soname portability — ✅ FIXED + VALIDATED.** Linux binary linked
>   `libpcap.so.0.8` (Debian/Ubuntu) + glibc 2.35 → failed to run on RHEL/Fedora/Arch
>   (`libpcap.so.1`). Fix: `nopcap` build tag — `capture.go` retagged `linux && !nopcap`,
>   `capture_other.go` (stub) `!linux || nopcap`; only libpcap user. Build a fully static,
>   portable binary with **`CGO_ENABLED=0 GOOS=linux go build -tags nopcap ./cmd/mimic`**
>   (drops the `capture` command — operator-only — but keeps run/serve/eBPF). Also fixed a
>   latent break: `stack.WinDivertInstalled()` was referenced in unified run.go but only
>   defined for Windows → the normal Linux build was broken too (argus ran an older
>   binary); added `internal/stack/windivert_other.go` (`!windows` → false). **VALIDATED:**
>   static binary runs on Rocky-9 (was "BINARY FAILED"), eBPF works, Ubuntu→Linux 97% /
>   Win11→Windows 98%. Ship nopcap for deployment, the libpcap build for the capture box.
> - **Kali template:** cloud clone never applied the argus_lab SSH key → deploy aborted.
> - **macOS Sonoma:** UNBUILT (no VM/template/captures) → no convincing match anywhere;
>   needs image→capture→response track. Not a matrix failure; out of scope until built.
>
> **★ EXACT-MATCH GOAL ACHIEVED on the WinDivert backend (2026-06-24).** The fix queue
> drove Windows 11 AND Windows Server 2022 (clean VM hosts) to a clean **`OS details:
> Microsoft Windows 10 1703 or Windows 11 21H2` — EXACT match, NO nmap submit prompt**
> (was 96–99% aggressive-guess). Three coordinated fixes (all committed):
> 1. ✅ **OPS ST10→ST11** (`61f3688`) — Win10/11 TS-on branch echoes the inbound-SYN
>    cache's client TSval (96→99%).
> 2. ✅ **Server profile corrections** (`7f44cd2`) — Server 2019/2022 window→65535,
>    Server 2016/2022 tcp_timestamps→true (align to nmap-os-db).
> 3. ✅ **CI=RD→I native closed-port RST** (`ed2b64a`) — Windows personas no longer
>    hand-craft the closed-port RST (which echoed nmap's IP-ID → CI=RD, SS=O); the
>    Windows stack RSTs natively + the stack handle stamps the shared incremental IP-ID
>    → CI=I, SS=S. THIS was the indicator that flipped 99%→exact.
> Plus ✅ **libpcap-free build** (`91ea4c4`) recovered the RHEL/Fedora/Arch host quadrants.
> **Proves the core thesis: "nmap stops asking for a submission" is per-config iteration,
> not impossible** — and SEQ/ISN centering was NOT needed (the CI=SS=S fix resolved it).
>
 **★ SAMPLE RE-RUN + Win10/Server-2019 pass (2026-06-25) — exact-match set now 5/6
> modern Windows editions.** A small sample run on a clean Server-2022 host confirmed the
> shared OPS+CI fixes generalized: **Win11, Server 2016, Server 2022, Server 2025 all
> EXACT**; Win10 + Server 2019 were the two laggards. Both then closed:
> - ✅ **Win10 → EXACT (`Windows 10 1909`), now host-independent** (`282c74e`). Root cause
>   was NOT a profile bug: a no-TS Windows profile inherited the HOST's SYN-ACK option
>   length — on a TS-reflecting host (Server 2019/2022/2025) the host echoes nmap's TS so
>   the SYN-ACK is 20B; mimic NOP-overwrote the TS but kept the length → padded OPS
>   (`O1=M5B4NW8NNSNNNNNNNN`, `O6=M5B4ST11`). On a TS-off host it was already exact ⇒
>   host-DEPENDENT fingerprint (the one real exception to host-independence). Fix:
>   `shrinkTCPHeader()` normalizes the no-TS Windows SYN-ACK to its real option length
>   regardless of host — O1/O2/O4/O5→12B (`M5B4NW8NNS`), **O3→8B (`M5B4NW8`, no SACK in the
>   P3 probe)**, O6→8B (`M5B4NNS`). Isolated to `!tcp_timestamps` Windows so the TS-on exact
>   matches are untouched (validated: Win11/Srv2016/Srv2022 stayed exact).
> - ⚠️ **Server 2019 → 99%, top guess "Windows Server 2019"** (`84e810a`; decoy gone, was
>   95% Longhorn). Closed the last two field-diffs: **ECN `CC=Y`** (split the conflated
>   `ecnEcho` → new `ecnCC` driven by `explicit_congestion: echo`; Linux/macOS still CC=Y,
>   Win11/Server-2022 stay CC=N so no regression) + **O6 `W6=FF70`** (65535-window no-TS
>   Server advertises FF70 on the no-WS probe, not scaled FFFF). Both now match the ref
>   exactly. **Residual = SEQ `SP`/`ISR` at the LOW EDGE of Server 2019's reference range**
>   — the host-kernel ISN-rate ceiling (Class C); a clean exact needs ISN-rate rewriting
>   (the documented WinDivert hard limit). May flicker to exact run-to-run.
> - **EXACT-MATCH TALLY (WinDivert backend, clean VM hosts): Win10, Win11, Server 2016,
>   Server 2022, Server 2025 = 5/6.** Server 2019 = 99% correct-top-guess (ISN-capped).
>
> **REMAINING QUEUE:**
> - Re-run the FULL matrix on the fixed binary to certify exact-match coverage across ALL
>   profiles incl. the untested older ones (Win7/8/XP/Vista, Server 2003–2012R2).
> - Server 2019 clean exact would need outbound ISN-rate rewriting (hard; low value — it
>   already self-identifies as Server 2019 at 99%).
> - Linux-profile exact (eBPF) chase + macOS build-out (image→capture→response) remain.

> **CHECKPOINT — Debian single-profile fingerprint (branch `feat/windows-port-linux-fidelity`, 2026-06-24).**
> **Active goal:** close Debian gaps on Windows-hosted mimic before running
> `lab/scripts/profile_matrix_scan.sh` (16 Linux profiles from Kali).
>
> **Lab topology:**
> | Role | Host | Notes |
> |------|------|-------|
> | mimic target | ss-book `10.0.253.61` | Dev laptop; repo `D:\repos\security\mimic` |
> | scanner | Kali `10.0.254.70` | SSH key `C:\Users\C2xor\.ssh\argus_lab` |
> | gold baseline | Debian 11 VM `10.0.251.3` (9521) | Native stack reference |
>
> **Config:** `dev-config.yaml` — profile **Debian**, services http/https/redis/ssh/telnet/vnc,
> `closed_ports: [9999]`, interface Wi-Fi. Standard scan:
> `nmap -Pn -O --osscan-guess -p 80,9999 -PU1,9999 -d2 10.0.253.61` (from Kali).
>
> **★ CONNECTIVITY SELF-DoS — FIXED + VALIDATED (2026-06-24, this session).** The
> recurring "mimic kills the host's network" footgun was the **U1 UDP responder filter**
> (`internal/netfilter/icmp_windows.go`). It opened a WinDivert handle on
> `"inbound and udp and !loopback"` (minus a few served ports) and the loop `continue`d
> WITHOUT re-injecting — so EVERY inbound UDP packet (DNS replies, QUIC/HTTP-3, app
> traffic) was captured and dropped → DNS dies → ss-book offline → Claude/Grok severed,
> no way to push a fix. **Fix:** inverted the filter from an EXCLUDE list to an ALLOW-LIST
> of the declared `closed_ports` — `udpUnreachableFilter()` now returns
> `inbound and udp and !loopback and (udp.DstPort == 9999 ...)` and `(string, bool)`;
> empty closed-ports ⇒ U1 UDP handle not opened at all. `ICMPResponder.Start`'s last arg
> renamed `udpExcludePorts`→`udpClosedPorts`; `run.go` now passes `appCfg.ClosedPorts`
> (was `nil`). **Validated (elevated, dev-config, time-boxed watchdog test):** with mimic
> running on ss-book, fresh uncached DNS = OK, HTTPS GET = 200, `ctl ping` = pong; log
> shows `[icmp] ... udp_closed_ports=[9999]`. Host stays fully online with mimic active —
> so the Kali-scan regression cycle can now run against ss-book directly without
> self-severing. (U1 attribution still depends on the type-3 egress issue below; this fix
> is about connectivity, not U1 fidelity.)
>
> **Regression snapshot (2026-06-24, ALL TELLS CLOSED; Kali→ss-book live, firewall ON):**
> | Probe | Reference (Linux) | ss-book mimic | Status |
> |-------|------------------|---------------|--------|
> | SEQ | TI=RD II=RI TS=A | match | ✅ |
> | T1–T7 | baseline (T2/T3 R=N) | match | ✅ |
> | WIN | 7210 | 7210 | ✅ |
> | IE | R=Y DFI=N CD=S | match | ✅ |
> | OPS | O1–O5=ST11, O3=NNT11, O6=ST11 | match | ✅ FIXED (TSecr echo) |
> | ECN | M5B4NNSNW7 | M5B4NNSNW7 | ✅ FIXED (inbound-SYN cache) |
> | **U1** | IPL=164 RIPL/RID/RIPCK/RUD=G | **exact match** | ✅ FIXED (WFP+sig+verbatim) |
>
> **Net result:** OS attribution flipped from "Apple TV / no match" → **all-Linux aggressive
> guesses (~89%)** under a plain `nmap -O`. Only the exact kernel sub-version is unpinned
> (Windows-host ISN/SEQ ceiling). Connectivity fully preserved with all responders active.
> **All four session goals delivered: connectivity self-DoS, OPS, ECN, U1.**
>
> Scans: `scratchpad/scan_ops_fix.txt`, `u1diag*.txt`, `u1_native.txt` (this session).
>
> **OPS ST10→ST11 — FIXED + VALIDATED (2026-06-24).** Tell was **TSecr=0** (nmap `T10` =
> TSval-nonzero/TSecr-zero), not "TSval zero" as previously noted. The Windows host has
> TCP timestamps DISABLED, so its SYN-ACK carries no TS to echo → `linTSecr` stayed 0.
> Fix (`internal/stack/backend_windows.go` Linux SYN-ACK template): if `linTSecr==0`,
> synthesize `uptimeMs()` so the option pair reads ST11. (Full client-TSval echo would
> need inbound-SYN flow tracking; nmap OPS only records zero/nonzero.) Validated: O1/O2/
> O4/O5=`M5B4ST11NW7`, O3=`M5B4NNT11NW7` (correct — nmap P3 omits SACK), O6=`M5B4ST11`.
>
> **★ U1 ROOT-CAUSED — it's the Windows Firewall, NOT a broken injection path (2026-06-24).**
> This OVERTURNS the prior "type-3 reinject is broken / pivot to a VM" hypothesis. Proven on
> ss-book with Kali tcpdump:
> 1. **Windows never emits an ICMP port-unreachable for a closed UDP port** — even with the
>    inbound UDP firewall-allowed and mimic stopped, 9999/udp stays open|filtered, zero
>    type-3 on the wire (`u1_native.txt`). So mimic MUST synthesize it (it does correctly).
> 2. **WFP's outbound ICMP-error layer drops mimic's *unsolicited* synthesized type-3.**
>    `WinDivertSend` returns success and the stack backend even logs `U1 diverted`, but the
>    packet never hits the wire — UNLESS the **Windows Firewall is fully OFF**. With
>    `netsh advfirewall set allprofiles state off`: type-3 egresses, 9999/udp reads
>    **closed**, and nmap then aims its U1 OS-probe at 9999 → `ICMP udp port 9999
>    unreachable, length 172` (the IPL=164 quote) on Kali (`u1diag_nofw.txt`).
>    Outbound policy is already `AllowOutbound` AND `EnsureICMPOutboundFirewallRule` installs
>    a valid `ICMPv4 Any/Any` outbound allow — neither overrides the stateful drop. The drop
>    is at `FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4` (validates ICMP errors against tracked flows;
>    our error has none because WinDivert swallowed the inbound UDP).
> 3. nmap only targets 9999 for U1 once it reads **closed**; while open|filtered, the U1
>    OS-probe (UDP len 300) goes to a random high port (33337/44626/etc.) anyway.
>
> **★ U1 — FIXED + VALIDATED (2026-06-24), exact gold match.** User chose the custom-WFP
> approach. Three coordinated pieces, all on `feat/windows-port-linux-fidelity`:
> 1. **WFP hard-permit** (`internal/netfilter/wfp_windows.go`): a dynamic WFP session adds a
>    `FWP_ACTION_PERMIT`+`CLEAR_ACTION_RIGHT` filter at `FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4`
>    `{41390100-564c-4b32-bc1d-718048354d7c}` in mimic's own max-weight (0xFFFF) sublayer,
>    overriding the firewall's stateful drop so the injected type-3 egresses with the
>    firewall ON. Dynamic session ⇒ BFE auto-removes it on engine close / process death
>    (crash-safe, no host leak). `fwpuclnt.dll` via x/sys/windows; FWPM_FILTER0 etc. are
>    hand-marshaled (FwpmFilterAdd0 is userland RPC → bad params return an error, not a BSOD).
>    Wired into `winICMPResponder.Start/Stop`.
> 2. **U1 signature responder** (`icmp_windows.go` `u1SignatureLoop`): WinDivert filter
>    `inbound and udp and !loopback and udp.PayloadLength == 300` catches nmap's U1 OS-probe
>    (300 bytes of 0x43 'C', confirmed on-wire) on ANY port — needed because a plain
>    `nmap -O` (no -sU) aims U1 at a RANDOM closed port, not the declared closed_ports. Only
>    the 0x43 signature is answered+swallowed; any other 300-byte UDP is reinjected
>    (connectivity-safe — verified: DNS/HTTPS/ctl all OK with it active).
> 3. **Verbatim full quote** (`craftPortUnreachable` + stack `applyPortUnreachable`): Linux
>    quotes the ENTIRE offending datagram unmodified, so the response IP length is
>    20+8+328 = 356 = **0x164** (nmap's `IPL=164` is HEX, NOT a 164-byte cap — the prior cap
>    was the bug) and the quoted header is byte-identical → `RIPL/RID/RIPCK/RUCK/RUD` all =G.
>    Rewriting the quote (length cap, TTL/DF) had produced `RIPL=A4` + `RIPCK=I`.
>    `applyPortUnreachable` reduced to outer-only (TTL + clear DF); quote left untouched.
>
> **VALIDATED (Kali→ss-book, firewall ON):**
> `U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)` — exact match to nmap-os-db
> `Linux 4.15-5.19`. **OS attribution flipped from "Apple TV / no match" → all-Linux aggressive
> guesses (Linux 3.3 / 4.19 / 3.2-4.14, ~89%).** Exact kernel sub-version still not pinned
> (the documented Windows-host ISN/SEQ ceiling — we don't rewrite the Windows kernel's ISN);
> OS *family* = Linux, which is what drives the deception/CVE relevance. `go test ./...` +
> `go vet ./...` all green on Windows.
>
> **ECN O=M5B4NNSNW7 — FIXED + VALIDATED (2026-06-24) via inbound-SYN flow cache.**
> `internal/stack/backend_windows.go`: the main WinDivert handle now ALSO captures inbound
> bare SYNs (`winFilter` widened to `... or (inbound and ip and tcp and tcp.Syn and
> !tcp.Ack ...)`), in the SAME loop goroutine that shapes the outbound SYN-ACK — so each
> SYN is recorded (timestamp-present + TSval, keyed by client IP:port) BEFORE the SYN-ACK
> it triggers is processed (race-free; a first attempt with a separate SNIFF goroutine
> raced and lost). SYN-ACK shaping then keys off the captured SYN: TS present (OPS probes)
> → Linux TS template ST11 with the REAL client TSval echoed as TSecr; TS absent (nmap's
> ECN probe — `Flags [SEW]`, options wscale/nop/mss/sackOK/nop/nop, no TS) → the no-TS
> template `M5B4NNSNW7`. The discriminator is **timestamp presence, not the ECE bit**
> (Windows never sets ECE; nmap's ECN probe is distinguished by lacking TS).
> **Two bugs found + fixed during impl (both via on-wire tcpdump from Kali):** (1) WinDivert
> flag constants were wrong — `RECV_ONLY`=0x4, `SEND_ONLY`=0x8; the sniff handle had been
> opened SEND_ONLY so it received nothing; (2) the SYN-ACK lookup keyed off the packet's
> SOURCE port (=service port 80) instead of the DESTINATION port (=client) → every lookup
> missed and fell back to the TS template (so the earlier "OPS ST11" was the synthetic
> fallback, not the cache). **VALIDATED (Kali→ss-book):** `ECN O=M5B4NNSNW7` (was
> M5B4ST11NW7), OPS all ST11 with real TSecr echo, no regression on SEQ/WIN/T1–T7/IE.
>
> **Remaining tell: only U1(R=N).** WFP filter for outbound ICMP type-3 is the next task
> (user chose the custom-WFP-filter approach over firewall-toggle/accept).
>
> **Ops constraints (unchanged):**
> - mimic **must** run elevated (UAC); one Admin PowerShell window — do not stack UAC prompts.
> - Start: `.\build\mimic.exe run -c dev-config.yaml -i Wi-Fi`
> - Reload binary: `.\build\mimic.exe ctl services.restart` (inherits elevation).
> - Confirm: `.\build\mimic.exe ctl ping` → `pong`
> - Console storm fixed via `internal/platform/exec_windows.go` (`CREATE_NO_WINDOW`).
>
> **Safe test loop (no VM needed now that connectivity self-DoS is fixed):** scan ss-book
> directly from Kali. Pattern that survives a connectivity blip: ONE elevated PowerShell
> (`Start-Process -Verb RunAs -Wait`) that (1) arms an independent watchdog process to
> `Stop-Process mimic` after ~180s, (2) starts mimic detached, (3) SSHes to Kali
> (`C:\Users\C2xor\.ssh\argus_lab` → `root@10.0.254.70`) to run nmap against `10.0.253.61`,
> (4) kills mimic. The watchdog guarantees the host comes back even if the test hangs.
> Reusable scripts: `scratchpad/scan_iter.ps1` (regression scan), `u1diag.ps1` (+ tcpdump),
> `u1diag_nofw.ps1` (firewall-off), `u1_native.ps1` (Windows-native baseline). Pipe Kali
> bash via `(Get-Content x.sh -Raw) -replace "\`r","" | ssh ... "bash -s"` (Kali shell = zsh;
> strip CRLF). One UAC prompt per scan iteration is expected.

> **CHECKPOINT — host restart pending (2026-06-24).** Operator reported spurious
> file-picker and other stray processes (likely stale `MimicUI` / `dotnet run` tray
> instances). **Before resuming:** end all `MimicUI.exe` and orphaned `dotnet` hosts
> via Task Manager or tray → Exit; then relaunch from a fresh build. Tray Exit fix is
> in code but **not re-validated** after the operator killed a prior UI instance
> manually.

> **ACTIVE TRACK — Windows management UI + control-plane ops (branch
> `feat/windows-port-linux-fidelity`).** Pre-MVP goal: a WinUI 3 tray app on ss-book
> wired to the local RBAC-gated control API so settings changes (profile, services)
> can be saved and applied via graceful restart. Linux honeypot + stack work from
> Phase 2 remains done; this track extends the Windows port (Phase 1) with operator
> UX, not new deception vectors.
>
> **Control plane — CODE-COMPLETE + SMOKE-VALIDATED (elevated Admin):**
> - **Transport:** Windows named pipe `\\.\pipe\mimic` (`internal/control/listen_windows.go`,
>   `dial_windows.go`, `endpoint_windows.go`). Linux unix socket unchanged.
> - **Auth:** `ImpersonateNamedPipeClient` peer creds preferred over client-PID token
>   (`listen_windows.go`); `tokenIsAdministrator()` handles UAC-linked/filtered-admin
>   tokens (deny-only `S-1-5-32-544` group). Empty RBAC config ⇒ admin bootstrap for
>   elevated peers (mirrors Linux root bootstrap).
> - **Ops wired** (`cmd/mimic/control_hooks.go` + `internal/control/`): `ping`, `status`,
>   `logs`, `logs.file`, `config.get`, `config.set` (+ `config.validate`, dry-run),
>   `profiles.list`, `services.list`, `services.restart` (canonical; `service.restart`
>   aliased via `NormalizeOp`).
> - **CLI:** `mimic ctl <op>` (`cmd/mimic/ctl.go`). Confirmed on ss-book: `ping` →
>   `ok:true, role:admin`; `status` → profile/services/pid/uptime; `services.list` →
>   17 templates; `profiles.list` → full catalog.
> - **Caveat:** `status.services` = **running** services (edition-gated); config may list
>   more than what's active (e.g. workstation profile ⇒ only `nbns` despite smb/msrpc in
>   config). `services.list` = available templates, not runtime state.
> - **Stale-process footgun:** ctl auth runs server-side — rebuild `mimic.exe` then
>   restart the `mimic run` process or pipe clients hit old auth code.
>
> **WinUI app — FUNCTIONAL SHELL (`ui/MimicUI/`, 2026-06-24):** Dashboard, **Logs**
> (renamed from Events), Settings; About removed from nav. `ControlClient.cs`
> JSON-over-named-pipe; system tray (H.NotifyIcon.WinUI, minimize-to-tray).
> Settings: profile dropdown, services checkboxes, restart banner → `services.restart`.
> **Logs page sources:** live ring buffer, `events.log`, `mimic.log`, `probes.log`
> (`EventLogFormatter.cs` — security events, mimic ops, probe match/miss telemetry).
> **UI polish (2026-06-24):** title-bar back button removed; app icon from
> `assets/icons/Mimic.ico`; `<WindowsPackageType>None</WindowsPackageType>` so
> `MimicUI.exe` launches unpackaged without CLR crash. **Tray menu fix (2026-06-24):**
> H.NotifyIcon default Win32 popup menu requires `MenuFlyoutItem.Command` (not `Click`);
> exit path = `_forceClose` + dispose tray + `Close()` (not `Application.Current.Exit()`).
> **Not yet packaged** (no MSIX/installer).
>
> **Log semantics (confirmed 2026-06-24):**
> | Source | Purpose |
> |--------|---------|
> | **live** | In-memory security event ring (same schema as `events.log`) |
> | **events.log** | Security NDJSON: honeypot, control-plane audit, cred captures, defense |
> | **mimic.log** | App/ops: startup, services, stack, warnings, errors |
> | **probes.log** | Probe match/miss per service/port/source (`component: probe`) |
>
> **Dev config (ss-book):** `dev-config.yaml` at repo root — `control.enabled: true`,
> absolute `profiles_dir`/`services_dir`/`log_dir`, profile Windows Server 2025 (user
> may edit), services smb/msrpc/netbios/nbns. **Must pass `-c` explicitly** — missing
> config file silently returns empty defaults → `no profile or services specified`.
> WinDivert.dll + WinDivert64.sys must sit beside `build\mimic.exe` for stack spoofing.
>
> **Windows runtime fixes this session (2026-06-23):**
> - **WinDivert missing:** graceful `Load()` before proc calls; `stack.WinDivertInstalled()`;
>   warn-and-continue when DLL absent (service emulation still runs).
> - **ctl access denied:** multi-iteration fix — impersonation + admin-token detection
>   (see above). Requires elevated Admin window for both `mimic run` and UI/ctl client.
>
> **Port 445 bind skip (2026-06-24):** When native `LanmanServer` holds :445, mimic
> skips `smb` with warning (`skipBindConflict` in `run.go`). Dev-config documents this.
>
> **Restart bug — FIXED, PENDING USER RE-VALIDATION:**
> UI / `ctl services.restart` stopped mimic cleanly but did **not** come back. Root cause:
> `PerformPendingRestart` checked whether the SCM service was **registered** (`sc query
> Mimic`) rather than whether the **current instance** ran under SCM. Dev pattern: `mimic
> install` registers the service, but operator runs `build\mimic.exe run -c dev-config.yaml`
> interactively → restart wrongly invoked `sc start Mimic` (wrong binary/config path).
> **Fix:** `platform.RunningUnderService()` (`svc.IsWindowsService()` / Linux
> `INVOCATION_ID`) passed through `ScheduleRestart` → `restart-pending --via-service` →
> `PerformPendingRestart`. Interactive ⇒ detach-spawn `mimic run -c <cfg>`; SCM-hosted ⇒
> `sc start` / `systemctl start`. Failures logged to `<log_dir>/restart-pending.log`.
> **Verify:** rebuild → elevated `mimic run -c dev-config.yaml` → UI restart or
> `ctl services.restart` → `ctl ping` succeeds; check `log/restart-pending.log` for
> `restart spawned (via_service=false, ...)`.
>
> **Resume checklist (post-restart):**
> 1. Kill stale `MimicUI.exe` / `dotnet` if any remain.
> 2. `go build -o build/mimic.exe ./cmd/mimic` → restart `mimic run -c dev-config.yaml -i Wi-Fi`.
> 3. `cd ui\MimicUI; dotnet build -c Debug` → launch
>    `bin\Debug\net9.0-windows10.0.26100.0\win-x64\MimicUI.exe` (prefer direct exe over
>    `dotnet run` to avoid extra host processes).
> 4. Validate: tray Exit quits fully; Logs → probes.log columns (Service/Result/Probe);
>    Settings save + `services.restart`; `ctl ping`.
>
> **Deferred (post-MVP):** MSIX/publish `MimicUI.exe`; **single-instance guard** (would
> prevent duplicate tray UIs); install path bundles UI; UI auto-reconnect after mimic
> restart; `services.stop`/`services.start` implementation; full SMB on Windows (:445);
> full matrix re-run on Windows hardware after config changes.

> **NEW MAJOR TRACK — Windows app + Linux honeypots + RBAC-ready control plane**
> (plan approved 2026-06-22). Sequence: regression harness → **Windows port
> (WinDivert)** → Linux interactive honeypots; RBAC/control seam designed-in now,
> engine later; tray UI future (uses `Mimic.ico`). Decisions + full plan in
> `~/.claude/plans/let-s-plan-our-windows-silly-kazoo.md`.
>
> **Phase 0a — cross-platform backend seam: DONE + VALIDATED (2026-06-22).** The
> packet-mutation + elevation layers are now behind interfaces so a Windows build
> compiles without the Linux-only deps (cilium/ebpf + netlink) leaking in:
> - `internal/stack` — `Backend` interface (Load/SetProfile/Enable/Disable/IsEnabled/
>   InterfaceName/Close) + `Teardown` + `TeardownResult`. `backend_linux.go` wraps the
>   existing `ebpf.FingerprintManager` (pure extraction, **zero Linux behavior change**);
>   `backend_other.go` (`//go:build !linux`) returns `ErrUnsupported` (Windows WinDivert
>   impl lands Phase 1b, will retag to `!linux && !windows`).
> - `internal/platform` — `IsElevated()` + `PrivilegeName()` (linux euid / windows
>   Admin-token via x/sys/windows / permissive default) replacing inline `os.Geteuid()`.
> - `internal/ebpf/{loader,teardown}.go` tagged `//go:build linux`; `types.go` stays
>   cross-platform. `cmd/mimic` (`main/run/stop/serve/install/capture`) rewired off
>   `internal/ebpf` onto `internal/stack`. `go mod tidy` promoted x/sys to direct.
> - **DEVIATIONS from plan (deliberate, lower-risk):** (1) `internal/netfilter` Firewall
>   interface deferred to **Phase 1c** — the nft/closed-port/T2-T3 code in
>   `internal/services` is `os/exec`-based and already compiles cross-platform, so it
>   was never a Windows blocker; the abstraction lands when there's a Windows impl to
>   put behind it. (2) `run.go` kept UNIFIED (not split into run_linux/run_windows) — it
>   compiles cross-platform via the seam today; the split + Windows-graceful nft
>   degradation happens in **Phase 1a** with the Windows service lifecycle.
> - **VALIDATED:** Windows (ss-book) `go build ./... && go vet ./... && go test ./...`
>   ALL GREEN (Npcap+cgo present, so even capture/cmd build natively). Linux (argus)
>   `make build` (incl. `make generate` — bpf2go still finds the directive under the
>   linux tag) + `go test ./cmd/... ./internal/...` GREEN; rebuilt binary restarted
>   under `/tmp/mx2.yaml` (Server 2025/all): eBPF `deceiver_fingerprint` filter
>   attaches via the seam (jited, tc egress), `mimic verify` = **COHERENT**. eBPF
>   bytes unchanged ⇒ nmap -O vector preserved (asserted mechanically in Phase 0b).
> - **argus state note:** mimic now running rebuilt binary from `/tmp/mx2.yaml`
>   (Windows Server 2025, services=all, preserve 2222). `tmp-llmnr/` is pre-existing
>   untracked scratch (two conflicting pkgs) — NOT ours; scope tests to `./cmd/... ./internal/...`.

> **Phase 0b — fingerprint/coherence regression harness: DONE + VALIDATED (2026-06-22).**
> Two tiers, both green on Windows (ss-book) AND Linux (argus):
> - **Offline (CI gate, no scanner)** in `internal/verify/`: `nmapxml.go` parses
>   `nmap -O -sV -oX` into a normalized `ScanResult`; `golden.go` (`Golden` YAML +
>   `CompareScan`) diffs a scan against a per-profile golden (OS family/gen, persona
>   port disposition open-vs-closed/filtered, service-banner substring) → `Result`/TELL.
>   Tests (`nmapxml_test.go`) run against a REAL recorded fixture
>   (`testdata/nmap_srv2025_argus.xml`): parse, golden-match (no false TELL), and
>   drift-detection (wrong golden ⇒ ≥5 TELLs). `profiles_test.go`
>   (`TestAllProfilesSelfConsistent`) loads every shipped profile and asserts the
>   version<->stack-era coherence in `go test` — the OSE tell caught at the source.
> - **Live (per-item gate)** `test/matrix/main.go` + `make matrix MATRIX_TARGET=<ip>
>   [MATRIX_GOLDEN=f.yaml | MATRIX_ALL=1]`: scans a running target, diffs every golden
>   via the SAME parser/comparator, exits non-zero on any TELL. `make test-unit` =
>   scoped unit run (skips the stray `tmp-llmnr/`).
> - **Goldens captured + live-PASS** (`test/golden/`): `windows-server-2025.yaml`
>   (server edition — 135/139/445 **open**) and `windows-11.yaml` (workstation —
>   135/139/445 **filtered**, desktop 3389/5357/5985/7680 open). Both nmap-attributed
>   "Windows 10|11". Covers BOTH edition dispositions. Remaining 4 Windows goldens
>   (Win10, Server 2016/2019/2022) + Linux goldens are captured incrementally during
>   each profile's Phase-1 validation pass (plan: "each item ends with a matrix re-run").
> - **Note:** this also re-confirmed Phase 0a preserved the stack fingerprint — the
>   live Server 2025 scan through the rebuilt seam binary = "Windows 10|11", server
>   port surface intact. Windows scanner (ss-book) nmap at
>   `C:\Program Files (x86)\Nmap\nmap.exe`; Kali (10.0.254.70) was powered off.

> **Phase 1a — service-emulation layer runs as a Windows application: CODE-COMPLETE
> (2026-06-22); over-the-wire VM validation BATCHED with 1b (user decision).** `mimic
> run` now degrades to service-only where there's no stack/host-shaping backend:
> - `stack.Available()` + `netfilter.Supported()` gates (linux true / other false) in
>   `run.go`: stack-backend goroutine and the whole nft host-shaping block (closed-port/
>   T2-T3/firewall persona) are skipped off-Linux; a profile with no stack backend logs
>   "service emulation only" instead of aborting; `-i` no longer required when no backend.
>   `stop.go` nft teardown gated by `netfilter.Supported()`. Linux behavior UNCHANGED
>   (both gates true) — re-validated on argus (build+vet+test green, restart, verify COHERENT).
> - **Windows binary is Npcap-free:** `cmd/mimic/capture.go` tagged `//go:build linux`
>   (live/pcap capture is a Linux operator workflow + links cgo libpcap); `capture_other.go`
>   stub returns "Linux-only". `go list -deps ./cmd/mimic` on windows shows NO
>   gopacket/pcap — so a deployed Windows honeypot binary needs no Npcap just to serve.
> - **Windows Service lifecycle:** `service_windows.go` (svc.IsWindowsService → svc.Run
>   handler; SCM Stop→`serviceStopCh` graceful shutdown, a new nil-by-default chan selected
>   in run.go's main loop), `service_other.go` no-op. `install.go` tagged linux (systemd);
>   `install_windows.go` registers an SCM service (mgr.CreateService, ImagePath=`run -c
>   <ProgramData\Mimic\config.yaml>`), copies binary+profiles+services to Program Files,
>   writes a windows-pathed starter config; uninstall stops+deletes. `copyFile`+starter
>   embed moved to shared `fsutil.go`.
> - **Validated:** Windows (ss-book) `go build ./... && go vet` green; `mimic list` works,
>   `mimic capture` → "Linux-only" msg, `mimic serve` non-elevated → "requires
>   administrator privileges" (platform.IsElevated works on Windows). internal/services +
>   honeypot unit tests already green on Windows. **PENDING (batched into 1b's Windows-VM
>   session):** over-the-wire `serve` on a clean Win11 clone (non-conflicting ports
>   redis/vnc/telnet — native SMB/RPC/WinRM occupy the persona ports) scanned from ss-book.
> - **Proxmox reachable** (`infra/proxmox/lab.py list`): Win templates 9010/9011/9116/9119/
>   9122/9125; existing clone `9501 mimic-lab-win11` (stopped). Use for the 1b VM session.

> **Phase 1b — WinDivert stack-mutation backend: DONE + VALIDATED ON A WINDOWS VM
> (2026-06-22).** Direct WinDivert 2.x bindings (no third-party module):
> - `internal/stack/windivert_windows.go` — `windows.NewLazyDLL("WinDivert.dll")`
>   bindings for Open/Recv/Send/Close/HelperCalcChecksums; `wdAddress` mirrors the
>   80-byte WINDIVERT_ADDRESS v2 (Outbound bit = (Bitfield>>17)&1). Network layer:
>   packets start at the IP header (no Ethernet) and CalcChecksums fixes IP/TCP/ICMP
>   csums after edits — so NONE of fingerprint.c's incremental-checksum math is ported.
> - `internal/stack/backend_windows.go` — `windowsBackend` implements `Backend` +
>   `New`/`Available()=true`/`Teardown`(no-op). Load opens filter `outbound and ip and
>   (tcp or icmp)` and runs a recv→mutate→CalcChecksums→send pump (ALWAYS re-sends, else
>   host traffic drops; mutates only when enabled). `applyEgress`/`applyTCP`/`applyICMP`
>   port fingerprint.c at IP-offset-0: TTL, DF, IP-ID (shared counter), window, the
>   20/12/16-byte SYN/SYN-ACK option templates (XP/Win7+/Win10-11-TS/Linux/macOS),
>   W6=0xFFDC, TS coherence on established 12-byte segments (uptimeMs via
>   GetTickCount64), RST window=0, ECN ECE-clear, ICMP DF-clear + echo code 0.
>   `backend_other.go` retagged `!linux && !windows`. atomic.Pointer[winProfile] +
>   atomic.Bool for live SetProfile/Enable.
> - **DEFERRED (refinement):** A=O RST ack rewrite (needs inbound SEQ seq-cache /
>   2nd handle) — refines nmap T4/T6 only; primary attribution covered.
> - **VALIDATED on a Windows VM (2026-06-22, proxmox win11 clone 9521 @ 10.0.250.228,
>   nmap -O from ss-book):** Native baseline = "Windows 10|11" TTL 128. With mimic
>   `run --profile Ubuntu` (WinDivert active), the emitted fingerprint = **TTL 64
>   (T=40), WIN W1=7210 (29200), OPS NW7 (WS 7), TI=RD/II=RI (random IP-ID), TS=A,
>   ECN CC=N (ECE cleared), U1 DF=N + IE DFI=N (ICMP DF cleared), T2/T4/T6 W=0** —
>   every Ubuntu stack field correct on the wire. Stop mimic → reverts cleanly to
>   "Windows 10|11" TTL 128 (Close unloads WinDivert). Counters: recv==outbound==
>   modified, send_err=0.
> - **KEY FINDING (pre-existing, NOT a WinDivert bug):** nmap gives "no exact match"
>   for the Ubuntu profile because the **TCP options ORDER stays Windows-style
>   (M5B4NW7ST10 = MSS,NOP,WS,SACK,TS)** while TTL/window are Linux — incoherent, so
>   nmap can't cleanly label it Linux. Root cause is in `fingerprint.c`'s template
>   logic (the `ws>0 && ts` Windows branch precedes the Linux branch), so it affects
>   BOTH backends, and `backend_windows.go` faithfully reproduces it. **Making Linux
>   profiles convincing needs a proper Linux options branch in BOTH fingerprint.c and
>   applyTCP** — tracked as a follow-up (ties into Phase 2 Linux work). The primary
>   Windows-profile path uses the well-tested Windows branches and is unaffected.
> - **Debug aid:** `MIMIC_WD_DEBUG=1` env enables per-packet + 3s counter logging in
>   the WinDivert loop (gated; off by default).
> - **Lab note:** the WinRM session-close KILLS `Start-Process` children — launch a
>   persistent run on Windows via `Invoke-CimMethod Win32_Process Create` (detached) or
>   the SCM service, NOT Start-Process. Win11 guest creds: user `root` / pass
>   `root:toor26`; transfer via `Copy-Item -ToSession`; WinDivert.dll + WinDivert64.sys
>   (v2.2.2 x64) must sit beside mimic.exe (C:\mimic). `lab.py` deploy `--linked --start`
>   (full clone may land stopped). VM 9521 KEPT WARM for 1c (mimic stopped).
>
> **1a over-the-wire (batched, VALIDATED on 9521):** `mimic serve --services
> redis,vnc,telnet` (non-conflicting ports; native SMB/RPC/WinRM occupy the persona
> ports) → nmap -sV from ss-book: 23/telnet "Cisco IOS telnetd", 5900/vnc "VNC
> (protocol 3.8)", 6379 answered (tcpwrapped). Service emulation serves correctly on
> Windows. **Phase 1a fully validated.**

> **Phase 1c — Windows closed-port firewall persona: DONE + VALIDATED ON A WINDOWS
> VM (2026-06-22).** WinDivert SYN-drop (self-contained, revertible, does NOT touch
> the host Windows Firewall config), mirroring the Linux nft default-drop:
> - `internal/netfilter/firewall.go` — `PersonaFirewall` interface (EnableDrop/
>   EnableICMPDrop/Stop). `firewall_windows.go` — `winFirewall`: each Enable opens a
>   WinDivert handle whose filter matches exactly the packets to suppress and a drain
>   goroutine recv's-and-drops them. TCP filter: `inbound and tcp and tcp.Syn and
>   !tcp.Ack and !loopback` + `and tcp.DstPort != <p>` per allow-listed port — SYN-ONLY
>   so the host's own outbound client traffic (inbound responses are SYN-ACK) is
>   unaffected, loopback exempt. ICMP filter: `inbound and icmp and icmp.Type==8`.
>   `firewall_other.go` (!windows) → nil (Linux uses the nft path). Minimal drop-only
>   WinDivert bindings duplicated in `netfilter/windivert_windows.go` to isolate from
>   the validated stack backend (future: unify into internal/windivert).
> - `run.go`: after the nft `Supported()` block, a cross-platform persona block — when
>   `!netfilter.Supported()` and `NewPersonaFirewall()!=nil`, workstation editions
>   default-drop (autoDrop unless `closed_port_behavior: reset`); allow-list derived from
>   `config.ServiceListenPorts` + `preserve_ports`; ICMP drop on workstation. Torn down
>   via `defer winFw.Stop()` on every return path.
> - **VALIDATED (proxmox win11 clone 9521, nmap from ss-book), config services
>   redis/vnc/telnet + preserve_ports [5985]:** native-listening **135/139/445/3389 →
>   FILTERED**; mimic-served **23/5900/6379 → open**; preserved **5985 (WinRM) → open**
>   (management access kept — established connections survive, only bare SYN dropped);
>   22 → filtered. Stop mimic → 135/445/3389 revert to **open** (clean teardown, no host
>   fw config touched). **preserve_ports MUST include the WinRM/management port on Windows.**
>   VM destroyed after validation.
>
> **★ PHASE 1 (Windows application) COMPLETE + VALIDATED ON REAL HARDWARE ★** 1a service
> emulation, 1b WinDivert stack mutation, 1c firewalled-client persona — all proven
> over-the-wire on a Win11 VM from a single Npcap-free Windows binary with an SCM
> service lifecycle. Remaining Windows nicety: `run` requires `-i` on Windows
> (stack.Available()=true) though WinDivert is host-wide — harmless (pass any value),
> could relax later. North-star (Windows port) achieved for the Linux benchmark set.

> **Phase 2.0 — Linux capture pass: DONE (8/9, 2026-06-23). #10 options-order fix:
> DONE + VALIDATED both backends. New gap #12 (ECN quirk gating) found.**
> - **Capture results (`captures/proxmox/<distro>/{stack,sv,ssh,http}.{xml,txt}`):**
>   ubuntu-2204/2004, debian-12/11, fedora, arch, **rocky-9** → nmap -O "Linux 4.15-5.19"
>   (osgen 4.X/5.X). **rocky-8 → "Linux 3.2-4.14"** (osgen 3.X/4.X — older 4.18 kernel,
>   the version-divergence the user predicted; TWO Linux stack classes). SSH algo lists
>   (KEX/cipher/MAC) captured for 2a. **kali GAP:** sshd not up on template 9341 (no open
>   port → "too many fingerprints"); `systemctl enable --now ssh` in setup didn't take —
>   needs openssh-server install/start or a different open port. Rocky templates' guest
>   agent lacks guest-exec ({data:null}) → fw-off skipped (non-fatal; cloud-image fw was
>   already permissive, -O worked anyway).
> - **#10 (TCP options ORDER): DONE + VALIDATED both backends.** Root cause confirmed:
>   the `ws>0 && ts` Windows branch preceded the Linux branch, AND the Linux branch left
>   TS as NOPs. Fix (fingerprint.c + backend_windows.go applyTCP): Linux branch
>   (`ts && opt[1]==SACK_PERM`) moved BEFORE the Windows-TS branch + emits a REAL TS.
>   **Validated:** win11+Ubuntu (WinDivert) AND argus+Ubuntu (eBPF) both emit
>   `OPS O1=M5B4ST11NW7` = MSS,SACK,TS,NOP,WS (Linux order; was `M5B4NW7ST10` Windows).
>   No Windows-profile regression (Server 2025 still "Windows 10|11"; Win10/11 opt[1]=nop
>   → unaffected). bpf2go compiles, go test green.
> - **#12 — ECN family-gating: DONE + VALIDATED (2026-06-23).** Plumbed `ecn_echo` into
>   OSProfileBPF (repurposed `_pad1` → `EcnEcho`; C `os_profile.ecn_echo`), set from family
>   in `profileToBPF` + `toWinProfile` (linux/macOS=1). Gated BOTH backends: ECE-clear now
>   `&& !ecn_echo` (Linux keeps ECE → CC=Y); the 12-byte Windows-ordered ECN-options rewrite
>   skipped for Linux. **VALIDATED (argus+Ubuntu eBPF):** `CC=Y` (was N), `O=M5B4NNSNW7`
>   (native Linux, was Windows `M5B4NW7NNS`), **Linux 5.10-5.15 rose to a top match (86%)**.
>   No Windows regression (Server 2025 → "Windows 10|11"). bpf2go + go test green.
> - **→ #13 (LOW PRI):** a Linux profile still isn't a *clean* Linux label — nft T2/T3
>   probe responses, A=O RST, IP-ID sharing (SS=S) are Windows-isms applied regardless of
>   family; gating needs probeMgr + eBPF family-gating. Windows-host WinDivert has a hard
>   ISN/SEQ ceiling regardless. Low value (Linux stack layer is low-use); the high-value
>   Linux work is the interactive honeypots (2a SSH), grounded by the Phase-2.0 captures.
>
> > **Original Phase 2.0 harness notes (2026-06-23):** capture REAL Linux distros first, then ground the
> #10 options fix + Phase-2 honeypots in captured data (capture-driven, not hand-authored).
> - **Harness `infra/proxmox/capture_linux.py`** (the Linux counterpart of capture.ps1):
>   per distro — deploy linked clone (lab.py) → guest-agent up + IP → guest-agent exec
>   (fw OFF across firewalld/ufw/nft/iptables) → run an nmap SUITE from ss-book → save
>   XML+txt to `captures/proxmox/<distro>/` → destroy. Fully out-of-band via the QEMU
>   guest agent (reuses lab.py `_token`/`BASE`/`NODE`; no in-guest SSH creds needed).
>   nmap suite: `stack` (-O --osscan-guess, the Linux OS vector for #10 + goldens),
>   `sv`, `ssh` (ssh2-enum-algos/hostkey/auth-methods — 2a fidelity), `http`.
> - **Distro set (user-chosen, broad incl. older where packets differ):** ubuntu-2204
>   (9302) + 2004 (9303), debian-12 (9304) + 11 (9305), rocky-9 (9306) + 8 (9307),
>   fedora (9310), arch (9311), kali (9341).
> - **Validated on ubuntu-2204:** native nmap -O = **"Linux 4.15 - 5.19"** (osgen
>   4.X/5.X) — the golden target; `ssh.xml` captured the full KEX/cipher/MAC lists.
>   Full `--all --no-pcap` batch running in background (~30 min) → per-distro
>   captures/proxmox/<distro>/{stack,sv,ssh,http}.{xml,txt}.
> - **KEY: the nmap suite is the primary, working artifact** — `nmap -O` emits the OS
>   options-order (OPS=) + the osmatch golden; ssh-enum gives the honeypot algo lists.
>   No pcap needed for #10/2a/goldens.
> - **pcap pull DEFERRED (known limitation):** guest-agent `tcpdump` + `file-read` pull
>   fails — backgrounded tcpdump is reaped when the agent `exec` returns (child-lifetime,
>   like Windows Start-Process), and file-read needs debugging. Byte-exact SERVICE
>   templates (`mimic capture pcap`, the 2c stateless-replay path) will need a `setsid`
>   detach + working file-read (or scp via the argus_lab key on cloud templates). Not a
>   blocker for the interactive-honeypot Phase-2 direction. Run harness with `--no-pcap`.

> **Phase 2a — SSH interactive Linux honeypot: DONE + VALIDATED ON ARGUS (2026-06-23).**
> `internal/honeypot/ssh/` (server.go/shell.go/vfs.go): full SSH transport via
> golang.org/x/crypto/ssh + a real terminal (golang.org/x/term) pseudo-shell.
> - **Banner/identity grounded in Phase-2.0 captures:** `distroFor(profile.Name)` →
>   per-distro OpenSSH ServerVersion + uname/os-release (ubuntu/debian/rocky/fedora/
>   arch/kali, generic fallback). Algos set to an OpenSSH-like subset x/crypto supports
>   (kex/cipher/mac) for ssh2-enum-algos fidelity (not byte-identical — no sntrup761).
> - **Auth:** seeded creds from the shared `deception.CredStore` (cross-service
>   cred-leak loop); all attempts logged as events (AuthAttempt/AuthSuccess).
> - **Pseudo-shell** over an in-memory LINUX VFS (not the Windows deception tree):
>   pwd/ls/cd/cat/whoami/id/uname/hostname/echo/sudo; /etc/{os-release,passwd,hostname},
>   /home/<user>, /var/log, and a **cred-leak breadcrumb `/root/.credentials`** that
>   surfaces a pooled cred. exec + interactive shell paths both via runCommand.
> - **Wiring:** `ssh_honeypot` registered in StatefulServiceNames + templateSupersededBy
>   (supersedes the banner-only `ssh` template) + honeypotListenPorts{22}; ShouldStartService
>   gates it to **linux family only** (won't start under Windows/macOS "all"). run.go
>   special-cases it like smb/ftp honeypots. Config: `service_options.hostname` +
>   credentials pool.
> - **VALIDATED (argus :22, real sshd on 2222 so no conflict):** nmap -sV →
>   "OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)"; Go x/crypto client
>   (test/sshclient) auth svc_backup → `uname -a` Ubuntu kernel, `id` uid=1000, `cat
>   /root/.credentials` leaks the pooled cred, `ls /etc` clean; wrong password rejected.
>   Unit tests green (shell_test.go); full argus suite green (vendor mode).
> - **OFFLINE BUILD NOTE (load-bearing for argus):** argus CANNOT reach proxy.golang.org,
>   so new modules (x/crypto/x/term/x/net + bumped x/sys) fail `go mod download`. Fix:
>   `go mod vendor` locally → deploy `vendor/` → `GOFLAGS=-mod=vendor make build-only`
>   (skip `generate`; the eBPF *_bpfel.go on argus are already current from the #10/#12
>   build). `vendor/` is gitignored (local deploy convenience, not source). Re-vendor
>   after any dep change before deploying to argus.
> - **argus state:** now running `/tmp/mimic_ssh.yaml` (Ubuntu profile + ssh_honeypot on
>   :22, cred svc_backup/Passw0rd123). Restore Server 2025 with `/tmp/mx2.yaml`.

> **Phase 2b — SFTP subsystem: DONE + VALIDATED ON ARGUS (2026-06-23).**
> `internal/honeypot/ssh/sftp.go`: an "sftp" subsystem handler over the SSH honeypot
> using `github.com/pkg/sftp` RequestServer with custom Handlers backed by the SAME
> in-memory Linux VFS (NOT the real disk — pkg/sftp's NewServer would expose it).
> READ-ONLY: Fileread (download) + Filelist (List/Stat) served from the vnode tree;
> Filewrite/Filecmd denied (os.ErrPermission, logged) like a locked-down account.
> Wired in handleSession ("subsystem" req == "sftp" → serveSFTP). **VALIDATED (argus
> :22, test/sftpclient pkg/sftp client):** auth svc_backup → `ls /etc` (hostname/issue/
> os-release/passwd w/ modes+sizes), `get /root/.credentials` downloads the cred-leak
> breadcrumb; uploads/removes denied. Unit test (sftp_test.go) + full argus suite green.
> Note: pass Unix paths with `MSYS_NO_PATHCONV=1` from Git Bash (else mangled). Re-vendored
> for pkg/sftp + kr/fs.

> **Phase 2c — deeper Linux HTTP (per-distro Server header): DONE + VALIDATED
> (2026-06-23).** `internal/services/responder.go`: new `applyServerHeader` transform
> (length-changing, runs in GetResponse after applyLeak like the leak path) rewrites the
> `Server:` value of Linux HTTP responses to a per-distro string via `serverStringFor(os_name)`
> — was hardcoded `nginx/1.18.0 (Ubuntu)` for ALL Linux. Gated `os_family==linux` + HTTP
> prefix; body/Content-Length untouched. **VALIDATED (argus, curl -I per profile):**
> Ubuntu→`nginx/1.18.0 (Ubuntu)`, Rocky→`nginx/1.20.1`, Fedora→`nginx/1.24.0 (Fedora Linux)`.
> Unit tests (serverheader_test.go) + full argus suite green. **Note:** stays nginx for all
> distros (coherent with the nginx body); RHEL-family Apache default-page bodies = follow-up
> #14 (low pri — nginx runs on all distros, and the Server header, the -sV tell, is already
> per-distro accurate). Needs `run` (sets os_name/os_family options); `serve` doesn't.

> **#9 — RBAC-ready control plane: DONE + VALIDATED ON ARGUS (2026-06-23).** The
> design-now-RBAC-later seam from the Phase-0 plan. `internal/control/`:
> - **Transport:** unix socket (`listen_linux.go`, mode 0660, SO_PEERCRED peer creds);
>   non-Linux `listen_other.go` returns ErrUnsupported (`Supported()=false`; Windows
>   named-pipe = future). `control.go` Server: read JSON Request → Authorize → dispatch
>   → JSON Response, deadline-bounded. Read-only ops now: `ping`/`status`/`logs`
>   (service-control is future). `Ring` = fixed in-memory events.Sink for `logs`.
> - **Authz from day one:** `Authorizer` iface + `RoleAuthorizer` (authorizer.go): maps
>   peer uid/gid → `config.Role` whose `allow` (op / `prefix.*` / `*`) gates the op.
>   **root (uid 0) bootstrap = admin always** (can't lock out); no roles configured ⇒
>   only root (preserves prior behaviour). Unit-tested (control_test.go) incl. gid-role
>   allow/deny, wildcard, empty-config root-only.
> - **Audit from day one:** every access → `events.Control` event (peer_uid/gid/pid, op,
>   role, allowed); Sev escalates on denial. New `events.Control` type.
> - **Config:** `control:{enabled,socket}` + `rbac:{roles:[{name,uids,gids,allow}],...}`
>   in AppConfig (opt-in; off by default). `mimic ctl <status|logs|ping> [--socket -n]`
>   client (`cmd/mimic/ctl.go`).
> - **VALIDATED (argus, /tmp/mimic_ctl.yaml):** control listening on
>   srw-rw---- /run/mimic.sock; `sudo mimic ctl ping/status/logs` → role=admin + JSON
>   (profile/services/pid/uptime + the audit-event tail); **non-root `argus` → blocked**
>   (socket-perm gate); audit events show peer creds+op+role+allowed. Full suite green.
> - **Future (when needed):** Windows named-pipe transport; service-control ops
>   (stop/reload — need run.go lifecycle hooks); the tray UI consumes this same API.

> **#13 — family-gate Windows stack quirks for clean Linux profiles: DONE + VALIDATED
> (2026-06-23). Linux profiles are HIGH-value (distro-spoofing to poison which
> distro-specific CVEs an attacker chases) — not niche.** A Linux profile must
> fingerprint as clean Linux; before #13 it read muddled (Windows-isms leaked).
> - **Fix:** new `win_quirks` byte in OSProfileBPF (repurposed `_pad2`; C
>   `os_profile.win_quirks`), set in `profileToBPF` (windows=1, linux/macOS=0). Gates
>   the Windows-only behaviors so a Linux profile keeps the host's native (Linux) ones:
>   (a) IP-ID shared-counter override → SKIPPED for Linux (native per-socket IP-ID =
>   random/SS=O); (b) A=O RST ack rewrite → Windows-only (Linux native A=Z); (c) ICMP
>   echo CD=Z forcing → Windows-only (Linux CD=S). Plus `run.go` gates the nft T2/T3
>   probe responder to Windows-family profiles. WinDivert backend mirrors (winQuirks
>   gates ICMP code; IP-ID still overridden there since the host is Windows). #12's ECN
>   gating already covered CC/ECN-options.
> - **VALIDATED (argus, nmap -O per profile, full matrix):** Windows 11 → "Windows
>   10/11 21H2 (98%)"; Server 2025 → Windows (exact); Ubuntu/Debian/Rocky/Fedora →
>   **clean Linux (97%, all-Linux guesses, ZERO Windows)** — was muddled Windows-top
>   before. Every profile gives the expected OS family. Full suite green. (Exact Linux
>   kernel sub-class varies with probe richness + host-kernel-SEQ ceiling; OS *family*
>   — what drives CVE relevance — is correct. Distro specificity lives in the service
>   layer: SSH banner / HTTP Server / os-release.)
> - **eBPF bytecode note:** the tracked `internal/ebpf/fingerprint_bpf{el,eb}.{go,o}`
>   are regenerated by bpf2go on Linux. #10/#12 commits captured STALE bytecode (I never
>   pulled the argus-regenerated artifacts back); the #13 commit pulls the cumulative
>   #10+#12+#13 bytecode from argus, so committed bytecode now matches source. ALWAYS
>   pull regenerated `*_bpf*.{go,o}` from argus after a fingerprint.c change (or run
>   `make generate` on a Linux box with clang) before committing.
>
> ⚠️ **LOCKOUT FOOTGUN (caused + recovered 2026-06-23):** running a WORKSTATION Windows
> profile (Win10/11) via bare `mimic run "Windows 11" -i ens18` with no config triggers
> the workstation auto default-drop with NO preserve_ports → **filters 2222 → SSH
> severed**. NEVER do this on argus. For any workstation-profile test use a config with
> `firewall: {closed_port_behavior: reset}` (disables auto-drop; `/tmp/safe.yaml` on argus
> has it) OR `firewall.preserve_ports: [2222]`. Server/Linux profiles are safe (no autodrop).
> **argus = proxmox VM 404** (nexus, unnamed, NIC MAC BC:24:11:A5:2C:F8 = the argus nmap
> MAC; NO qemu-guest-agent so `lab.py ip 404` is blank). Recover a lockout via ACPI
> reboot: `python -c "import lab; lab._req('POST', f'/nodes/{lab.NODE}/qemu/404/status/reboot')"`
> — mimic is started manually (not systemd) so it's gone on boot and the nft drop clears.

> **#14 — per-distro Apache/nginx HTTP (header + body), done right: DONE + VALIDATED
> (2026-06-23).** RHEL family runs httpd (Apache) by default, so those distros now serve
> an Apache Server header AND an Apache body (coherent — not the cheap header-only swap).
> - New `os_server` service option (`webServerForOS(name)`: RHEL/Fedora→apache, else nginx)
>   set by `SetProfileOptions` for Linux profiles. `serverStringFor` returns Apache version
>   strings for the RHEL family. Manifest gates the BODY-bearing Linux responses (GET / +
>   /index 200, 404) on `os_server` (nginx vs apache variant); headers-only (HEAD/OPTIONS)
>   + the cred-leak page stay shared since `applyServerHeader` fixes their Server header and
>   they have no server-branded body. New `services/http/responses/apache_200_full.bin`
>   ("It works!") + `apache_404.bin` (CRLF headers, Date placeholder, Content-Length
>   auto-recomputed). Also fixed a latent gap: Linux GET /index.html previously served the
>   IIS body.
> - **VALIDATED (argus, curl per profile):** Ubuntu → `nginx/1.18.0 (Ubuntu)` + "Welcome to
>   nginx"; Rocky → `Apache/2.4.57 (Rocky Linux)` + "It works"; Fedora → `Apache/2.4.62
>   (Fedora Linux)` + "It works". Header+body coherent per distro-family. Unit + full suite green.
>
> ⚠️ **OPS: /tmp is wiped on argus reboot.** The lockout-recovery reboot (2026-06-23) cleared
> /tmp, deleting the config files (mx2.yaml/safe.yaml/etc.). `LoadAppConfig` on a MISSING -c
> file silently returns defaults (no interface) → `run` exits "interface not specified" (not a
> crash, just no-op). Recreate configs after any argus reboot. mx2.yaml recreated; argus now
> runs Server 2025 (server edition, preserve_ports [2222]) again, detached via `setsid ... &lt;
> /dev/null &` so it survives the ssh session close.

> **Thin-decoys queue (order 3,2,4,1):** **ALL DONE + VALIDATED** (2026-06-18).
> (#3) WinRM, (#2) MSRPC ept_map, (#4) NetBIOS/139, (#1) RDP/3389 CredSSP.
> RDP live: Kali `nmap --script rdp-ntlm-info` → Product_Version **10.0.20348**
> (Server 2022 profile), NetBIOS/DNS names match `netbios_name`. `os_edition`
> gates 135/139 on workstation vs server. Lab warm on argus; Kali 9511 up.

- **nmap `-O` → exact Windows 10/11 DB match** (no `-p` needed). Full
  SEQ/OPS/WIN/ECN/T1–T7/U1/IE vector matches Windows 11 21H2. Detailed vectors
  promoted to LJM Knowledge (`net_os_fingerprint_deception_vectors`).
- **TLS:** JARM + JA3S exact match vs Windows IIS Schannel (static ServerHello;
  handshake does not complete — no key material). JA4S unvalidated.
- **SMB honeypot (`smb_honeypot` service):** full share enumeration to nmap
  (`smb-enum-shares`), netexec, and direct impacket — guest/null **and** seeded
  fake-credential logins (NTLMv2-verified). SMBv1 + SMBv2/3.1.1 negotiation.
- **Service breadth (Phase 4, 2026-06-10):** SSH/SMTP/VNC/Telnet/Redis/HTTP per-OS
  + MySQL/MSSQL (capture-driven), all `nmap -sV`-hardened. Summarized in LJM
  `Memory/Project/mimic` (Phase 4 section).
- **Proxmox Windows capture track (2026-06-11/12):** golden templates for Win10
  (9010), Win11 (9011), Server 2016/2019/2022/2025 (9116/9119/9122/9125) on node
  `nexus` (`10.0.240.8`). All 6 templatized + loop-validated; tooled with
  Wireshark+Npcap, Sysinternals, and capture helpers; `agent=1` self-reporting.
  - **Automated capture harness** `infra/proxmox/capture.ps1` (+ `lab.py`
    deploy/ip/prep/destroy). Per run: linked clone → out-of-band `prep` (guest-agent
    exec: fw-off + Enable-PSRemoting + ExecPolicy bypass, bypasses Public-profile
    WinRM block) → pktmon capture (dumpcap on Server 2016, no pktmon) → nmap probe
    from ss-book → pcapng pulled to `captures/proxmox/<os>/` → clone destroyed.
  - **Captures done (2026-06-12), 6 OSes each (46 pcaps, captures/proxmox/<os>/):**
    Pass 1 `-sV` service surface; Pass 2 `-O` stack (incl. **Server 2025 raw vector —
    not yet in nmap's DB**); Pass 3 SMB+RDP NSE (build #s 14393→26100); Pass 3c IIS
    (`http-*`, Microsoft-IIS/10.0 — NOTE http-enum bloats pcaps with 404s, drop it);
    Pass 4a discovery (NBNS node-status solid on all 6; **SSDP/mDNS thin — not
    listening by default, esp. on Server**).
  - Pass 4b SNMP done on the 4 servers (Install-WindowsFeature SNMP-Service + public
    community); Pass 4c LLMNR done 6/6 (crafted `infra/proxmox/llmnr_probe.py`).
    DEFERRED: WSD/3702 + workstation SNMP (FoD-blocked, WU disabled). `capture.ps1
    -Setup` hook handles role installs.
  - Access: guest creds servers `Administrator`/workstations `root`; drive Proxmox via
    python (PS Invoke-RestMethod to Proxmox is Schannel-flaky). **`infra/` is
    DELIBERATELY LOCAL-ONLY — gitignored and SCRUBBED from git history after a PVE
    token leak (remediated 2026-06-15, force-pushed clean; token since rotated). DO
    NOT re-commit `infra/` — it holds the API token + autounattend creds.** Fuller
    resume state in LJM `Memory/Project/mimic` (Proxmox capture track section).
- **systemd daemon lifecycle (2026-06-15, committed `9ed9935`, validated on argus):**
  `mimic stop [--purge]` / `install` / `uninstall [--purge]` + clean-on-start.
  Stateless content-diff TC teardown (`internal/ebpf/teardown.go`): removes only
  `deceiver_fingerprint*` filters by BPF name; `--purge` removes the clsact qdisc
  ONLY if no foreign filters remain (co-tenant-safe). nft tables (mimic_reject/
  mimic_block) safe by name-isolation. systemd unit: ExecStart=run, ExecStopPost=stop
  (crash safety net), Restart=on-failure, bounded caps. Validated: restart clean (no
  dup filter), nmap -O through daemon = Win10|11, co-tenancy keeps qdisc. Files:
  `cmd/mimic/{stop.go,install.go,run.go,assets/*}`, `internal/ebpf/teardown.go`.
- **Capture→template pipeline (Track 1, 2026-06-16, COMPLETE 2026-06-18):** `mimic capture
  pcap <f> --server-ip <ip> --service <svc> --ports <p> --os <name>` -> manifest.yaml
  + response .bin + rewrite rules. **FIX (`internal/capture/session.go`, committed `9ed9935`):**
  ExtractExchanges now dedups duplicate packets by PAYLOAD CONTENT per direction —
  pktmon records each packet N× (per NIC/WFP/Npcap/QoS component) which was
  concatenating probes/responses N× (inflating lengths so signatures never matched a
  real probe). Content-key works for TCP+UDP (UDP has no seq). Batch-generated on
  argus `/tmp/gen/<os>/<svc>` from the 34 per-service pcaps (NOT pulled to repo):
  smb 8-9, rdp 12-15, nbns 3-4 = clean; **snmp 236→3** (system MIB curation,
  2026-06-18), **http 1071→6** (http-enum filter), **llmnr 0→1** (multicast +
  sidecar target IP, 2026-06-18). Regen `/tmp/gen` only when promoting artifacts
  into `services/` — not Proxmox VM templates.
  - **ARCHITECTURE (load-bearing):** `services/<name>/` = stateless template-replay
    (svcMgr.LoadService); `smb_honeypot`/`ftp_honeypot`/`rdp` = interactive hand-coded
    (`internal/honeypot/*`, special-cased in run.go). For SMB the **honeypot is the
    serving path** (does multi-step SESSION_SETUP/TREE_CONNECT/enum/auth that replay
    can't); captured `services/smb` template = REFERENCE/validation only. **`rdp` in
    `services:` starts the stateful honeypot** (X.224→TLS→CredSSP), not the template;
    `services/rdp/responses/*.bin` supplies nego + JARM static hello only. Editing
    captured templates can NOT regress the honeypots (separate code+data+selector).

## Track-1 refinement queue (priority order, handle after restart)
1. ✅ **RDP & SMB enhancements — DONE (2026-06-17, live-validated on argus).**
   **SMB:** NTLM CHALLENGE Version field now derives major/minor/build from the
   profile (`Server.osVersionTriple()` parses `cfg.OSVersion`, same source as
   `nativeOSString()`); fallback stays 10.0.19041 when OSVersion unset (tests).
   Closes gap #2. Files: `internal/honeypot/smb/{ntlm.go,server.go,ntlm_test.go}`.
   **Live-validated:** raw SMB2 NEGOTIATE→SESSION_SETUP probe vs the running Win11
   honeypot returns NTLM Version **10.0 build 22000** (was 19041).
   **RDP (`services/rdp/manifest.yaml`, replay path via `serve`):** two fixes.
   (a) TLS ServerHello random typing — it's a TLS **1.3** hello
   (supported_versions→0x0304), so the first-4-bytes `timestamp_unix` typing was
   wrong (no gmt_unix_time in 1.3); changed to full 32-byte `random`. (b) Added
   `legacy_session_id` echo (offset 44, len 32, type `echo`) — a 1.3 server MUST
   echo the client's session_id; the static value was a tell. **Live-validated:**
   ServerHello random[:4] is now per-connection random (not wall-clock), and a
   ClientHello with session_id=0xAB×32 gets that value echoed back (was static
   `ad526b9d…`).
   **KEY FINDING — generated RDP templates NOT integrated (deliberate).** Inspected
   `/tmp/gen/<os>/rdp` on argus: the 1232-byte "ServerHello+Certificate" responses
   are a 127-byte cleartext ServerHello followed by **TLS 1.3 encrypted handshake
   records** (`\x17\x03\x03…` — Certificate/CertVerify/Finished are encrypted under
   handshake keys in 1.3). Those bytes are session-bound to keys we don't have;
   replaying them to a new client is useless AND a tell. The generated set also
   contains 0-byte responses and encrypted app-data records. So the hand-crafted
   127-byte ServerHello is the max useful cleartext — integrating the generated
   templates would be a **regression**, not an upgrade. nmap can't extract an RDP
   cert from TLS 1.3 anyway (encrypted on the wire). RDP item is closed.
2. ✅ **http re-capture de-noise — DONE (2026-06-18).** Capture pipeline now
   filters http-enum path noise in `internal/capture/http_filter.go`: non-root
   GET/HEAD paths dropped; OPTIONS/POST/TRACE/etc. kept. `classifyHTTPProbe`
   buckets surviving probes (`http_get`, `http_options`, …) instead of
   per-path SHA256 hashes. **Validated on argus:** same Win11 IIS pcap
   (`iis_20260612_103947`, 10.0.250.31) **1071→6** manifest probes; clean
   hmdxin pcap **5** probes; unit tests in `http_filter_test.go` +
   `http_capture_test.go`. Re-capture without `http-enum` still recommended for
   smaller pcaps; `infra/proxmox/capture.ps1` drop remains best practice.
3. ✅ **llmnr — DONE (2026-06-18).** Multicast queries to `224.0.0.252:5355`
   attributed to configured server IP; UDP/5355 sessions aggregate by client IP
   (ignore ephemeral port); sidecar `.nmap.txt` `target=<ip>` auto-selected for
   `capture pcap --service llmnr`; manifest protocol infers `udp`. **Validated on
   argus:** Win11 proxmox pcap with wrong `--server-ip` still extracts **1** probe
   (sidecar override 10.0.251.64), was 0 exchanges.
4. ✅ **snmp — DONE (2026-06-18).** Pipeline keeps **system MIB only**
   (`1.3.6.1.2.1.1.*` — sysDescr/sysUpTime/sysName); drops snmp-interfaces
   ifTable GET-NEXT walk (~233/236 exchanges). Live proxmox analysis + nmap
   sidecar: `-sV`/`snmp-sysdescr` need the 3 system OIDs; full walk is
   enumeration noise (http-enum parallel). **Validated:** srv2022 pcap **236→3**
   probes. `snmp-interfaces` deep fidelity deferred (needs stateful handler or
   opt-in full capture).

  Generic rewrite-rule typing limitation: capture generator marks all dynamic fields
  `type: random` (functional non-static, but SMB2 FILETIME should be `timestamp`,
  GUID `guid`). Relevant to replay-served protocols (RDP/tail), not SMB.

## Milestones

- **Stack fingerprint (2026-05-11/12):** TCP timestamps (TS=A), SACK
  negotiation, ECN probe, IP-ID sharing (SS=S), RST T5/T7, ICMP DF/code,
  T4/T6 A=O via `seq_cache` LRU_HASH map, W6=FFDC, T2/T3 global nftables
  RST+ACK rules (all ports).
- **SMB share enum (2026-06-05):** SMBv1 dispatch (LOGOFF/DELETE/TRANSACTION
  handlers, dataOffset=60), srvsvc NetShareEnum (level-0 for nmap, level-1 for
  impacket) + NetrShareGetInfo (opnum 16), unknown-share rejection, SMBv2
  multi-dialect negotiation w/ fallback.
- **impacket/netexec compatibility (2026-06-05/06, signing extended 2026-06-17):**
  see LJM Knowledge `net_impacket_smb3_processcontextlist_bug` and
  `net_smb_honeypot_signing_encryption_constraint`. Net: send **one**
  NegotiateContext (PreauthIntegrity only — no Encryption); guest/null sessions
  use `IS_GUEST` so clients skip signing; **seeded creds get full 3.1.1 signing**
  (`signing.go`, SP800-108 KDF + AES-128-CMAC) and file download works.
- **Seeded credential auth (2026-06-06):** `credentials.go` — NTLMv2 response
  verification against config-seeded fake accounts. Intent: other services
  "leak" creds an attacker reuses against SMB. Verified: `netexec` seeded cred →
  `[+] WORKGROUP\backupadmin:...`.
- **Phase 1 deception depth (2026-06-10):** neutral `internal/deception` core
  (content tree, maze, shared credential store, config) extracted from the SMB
  VFS — reusable by future stateful services. Config-driven shares/dirs/seeded
  files (inline `{{cred:…}}` + on-disk `seed_file`), random-but-plausible
  `generate`, runtime infinite `maze`; cross-service credential-leak loop
  (`{{leak:<id>}}` in any text service → same cred authenticates SMB). Live-
  validated on argus-lab (impacket SMB2: shares, seeded-file download, maze
  determinism, cred auth; curl HTTP leak; nmap fingerprint preserved). Caught +
  fixed a dir-listing bug — see LJM `net_smb2_query_directory_filename_offsets`
  (impacket `listPath` uses FileFullDirectoryInformation, FileName@68).

## OSE-2026-001 red-team exercise — validated impact + gaps (2026-06-17)

Controller ran 6 AI operators (3 Claude / 3 Grok) vs 3 targets. Clean A/B for Mimic:
**same Ubuntu 22.04.5 base image + same backdoored vsftpd 2.3.4**, one bare
(`mimic-lab-linux-bare`, Op-3) vs one Mimic'd (`mimic-lab-linux-mimic`, Op-5). Op-1
hit a *real* Win11 22H2 (22621) box = fidelity reference. Logs in `../MTest/`.

**Impact (Op-3 bare vs Op-5 Mimic):** both rooted via the vsftpd backdoor — Mimic
is a deception/cost layer, NOT a vuln shield (can't patch a real service it doesn't
front). Effect: time-to-root 8m36s → ~23m (~2.7×); open-port surface 1 → 6 (5
decoys); OS attribution flipped to "Windows 11" until shell. SMB honeypot WIN:
svc_backup authenticated + enumerated IPC$/ADMIN$/C$ (cred-leak loop fired). Caveat:
a skilled operator flagged deception indicators *pre-shell* (would burn it in a real
op), and much of the "cost" was a self-inflicted bug (TS incoherence, below).

**Tells / gaps surfaced (canonical tracker; statuses updated as fixed):**
> Status legend: ⏳ open · 🔨 code-complete, pending argus validation · ✅ validated.
> **Validation run 2026-06-17 on argus (10.0.254.45):** built (bpf2go), unit tests
> green incl. RFC-4493 AES-CMAC vectors. SMB signing, coherence linter, firewall
> drop all VALIDATED live (below). eBPF loads/attaches/non-breaking; the byte-level
> TSval-coherence capture needs a *Linux* client (Windows doesn't negotiate TCP TS;
> strx was down) — the one remaining check.
- ✅ P0 **TS incoherence (BUG):** eBPF overrode TSval only on SYN/SYN-ACK (stripping
  the kernel's per-connection random offset) but left data segments with the offset
  → SYN-ACK 7.88M vs data 3.3B TSval discontinuity → standard clients PAWS-drop the
  payload. Broke real vsftpd delivery AND Mimic's own SMB negotiation (Op-5 had to
  `sysctl tcp_timestamps=0` locally to proceed). **FIX (`internal/ebpf/fingerprint.c`,
  2026-06-17):** new data/pure-ACK block overrides TSval on established segments
  (opt_len==12, NOP,NOP,TS) to the same `bpf_ktime` ms clock as the SYN-ACK template,
  gated on the Win11 branch (window_scale>0 && tcp_timestamps). Coherent, keeps TS=A.
  **VALIDATED (argus + Kali Linux client, 2026-06-17):** bpf2go-rebuilt; eBPF loads
  (jited, id 311). With a Kali client (tcp_timestamps=1) hitting the Win11 honeypot,
  tcpdump of argus egress on 445 shows every data-segment TS val ≈ uptime_ms
  (201,659,115→201,661,406 at uptime_ms=201,652,100) — the clean bpf_ktime clock,
  monotonic, NOT the kernel's ~3.3B random-offset value (Op-5). Functional proof: the
  Linux client completed NEGOTIATE+SESSION_SETUP+TREE_CONNECT (no PAWS drop; pre-fix
  this failed). Windows clients don't negotiate TS so the fix is a no-op for them.
- ✅ P0 **OS↔service coherence:** vsftpd (Linux daemon) on a "Windows 11" host = the
  single strongest tell (Op-5 FINDING-006). Extends gap #5. **FIX (`internal/coherence`,
  wired in run.go):** background startup self-audit parses /proc/net/tcp[6] for FOREIGN
  LISTEN ports (skips Mimic's own via /proc/self/fd socket inodes — so the deliberate
  vsftpd FTP honeypot isn't flagged), banner-grabs them, and WARNs when a Unix/Linux
  tell (vsftpd/ubuntu/debian/postfix/…) contradicts a Windows profile. Advisory only.
  **VALIDATED (argus):** flagged a planted vsftpd (2121) AND the real Ubuntu sshd
  (2222) under a Win11 profile; correctly did NOT flag Mimic's own SMB listener.
- ✅ **Closed-port disposition = RST (Linux), not DROP:** Op-5 closed ports RST'd;
  real firewalled Win11 (Op-1) dropped 997+. RST betrays unfirewalled Linux under a
  client persona. **FIX (`internal/services/firewall.go`, opt-in
  `firewall.closed_port_behavior: drop`):** default-drop catch-all in the mimic_reject
  table, added AFTER T2/T3+closed rules; accepts established/related FIRST (live SSH
  survives) + open_ports/preserve_ports allow-list. Default stays `reset` (keeps the
  nmap closed-port probe for high-confidence -O). preserve_ports MUST list SSH.
  TRADEOFF: drop loses nmap's closed-port probes (lower -O confidence, like real Op-1).
  **VALIDATED (argus):** closed 9999→filtered/timeout (not RST), open 445 + preserve
  2222→reachable, live SSH survived, nft order correct (T2/T3→estab→allow→drop).
- ✅ **SMB serves no file content:** auth + share-enum OK but READ → ACCESS_DENIED /
  "Bad SMB2 signature" (Op-5 FINDING-011). Extends gap #1. **FIX — full SMB2/3 signing
  (`internal/honeypot/smb/signing.go` + session/server/ntlm/credentials, 2026-06-17):**
  on a verified seeded cred, derive SessionBaseKey (HMAC-MD5 ntowfv2/NTProofStr) →
  ExportedSessionKey (RC4 if KEY_EXCH) → SigningKey (SP800-108 KDF; 3.1.1 uses the
  running preauth SHA-512 hash accumulated over NEG+SESSION_SETUP) → sign responses
  (AES-128-CMAC for 3.x, HMAC-SHA256 for 2.x). Guest fallback if no preauth chain.
  Also added FileAllInformation (QueryInfo class 18) so smbclient `get` works (its
  "getattrib" precheck returned NT_STATUS_NOT_SUPPORTED, blocking downloads).
  **VALIDATED (argus, live smbclient):** svc_backup authenticates over a SIGNED SMB
  **3.1.1** session (dialect 0x0311), enumerates the full C$ tree, AND downloads a
  332-byte bait file (passwords.txt) — the exact Op-5 failure, now working. AES-CMAC
  also RFC-4493-vector-validated (signing_test.go).
- ✅ **Port persona wrong for edition — DONE + VALIDATED (argus + ss-book nmap, 2026-06-22).**
  Was: Mimic "Win11" exposed 135/139/443/445/3389 (server-shaped); real Win11 client
  (Op-1) exposed 3389/5040/5357/5985/7680 with 135/139/445 FILTERED. Two-part fix:
  - **Disposition — auto firewalled-client drop for workstation editions** (`run.go`):
    a workstation profile now DEFAULTS to default-drop (unserved ports incl. 135/139/445
    → **filtered**, matching a real firewalled client; closed-not-filtered on the server
    ports was the tell). Allow-list **derived from actually-served ports** via
    `config.ServiceListenPorts` (honeypot ports known statically, template ports read
    from manifest) + `mergeUint16`. Opt out with `closed_port_behavior: reset` (keeps
    nmap closed-port probe for higher -O confidence). Established-accept + `preserve_ports`
    keep SSH alive — **preserve_ports MUST list the SSH port** under this mode.
  - **Exposure — desktop-persona ports** (`EditionExposesPort` extended: 5357/7680
    = workstation-only, mirror of 135/139/445 = server/dc-only). Templates
    `services/{wsd,deliveryopt}`: wsd/5357 + deliveryopt/7680 = HTTP.sys 404
    (`Server: Microsoft-HTTPAPI/2.0`, byte-identical to the captured WinRM 404, live
    `http_date`). `ShouldStartService` gates both to workstation. 5985/WinRM left
    ungated (real Op-1 client had it).
  - **Live proof (ss-book nmap → argus Win11/workstation):** 135/139/445 → **filtered**
    (no-response, not RST); 3389/5357/5985/7680 → **open**; 2222 (SSH) preserved; TTL 128.
    `-sV`: 5357/5985/7680 → "Microsoft HTTPAPI httpd 2.0". rdp-ntlm-info still returns
    Product_Version 10.0.26200 (no regression).
- ✅ **cdpsvc/5040 REMOVED after capture-validation (Item 1, 2026-06-22).** Two `capture.ps1`
  runs against a fresh Win11 23H2 clone (9011, fw off) confirmed **5040 is CLOSED/RST — CDPSvc
  does NOT listen by default** (Op-1's box was an outlier). The full default-listening set was
  135/139/445/3389/5357/5985/7680 OPEN, 5040 the *only* closed port. So opening 5040 (→
  tcpwrapped) was LESS faithful than leaving it filtered. Removed the `cdpsvc` template +
  5040 from `EditionExposesPort`/`ShouldStartService`; 5040 now falls under workstation
  default-drop → **filtered** (matches a firewalled client w/o CDPSvc). Validated: ss-book
  nmap shows 5040 filtered, desktop ports still open, `-O` still Win10/11 (98%). Reference
  pcaps in `captures/proxmox/win11/` (gitignored) — incl. `deskports_*` (real 5357/5985/7680
  bytes for future fidelity checks).
- ✅ **Firewall loopback-exemption bug FIXED (Item 1 regression gate, 2026-06-22).** The
  workstation default-drop (`internal/services/firewall.go` `EnableDrop`) dropped ALL non-
  allowlisted inbound TCP **including loopback** — surfaced by `go test ./...` on argus
  (rdp `TestCredSSPNTLMChallengeIntegration` dial to 127.0.0.1 *timed out* while the persona
  firewall was active). A real Windows firewall never blocks 127.0.0.1, and as-is mimic would
  break the host's own local services. Added `iifname "lo" accept` after established-accept.
  Validated: cache-bypassed rdp test passes with the firewall active; doesn't weaken the
  external persona (a remote scanner can't reach lo).
  - **argus state note:** argus mimic is NOW running the **workstation test config**
    `/tmp/mimic_ws.yaml` (Win11), NOT the prior Server 2022 `/tmp/mimic_all.yaml`.
    Restart with the all-services Server config to restore the earlier state.
- ✅ **Thin decoys → interactive services (COMPLETE, 2026-06-18).** Root cause:
  `listener.go` did `return` (silent FIN) on any probe-miss, and TLS services only
  static-replayed JARM probes — so real clients "ACK the ClientHello, get nothing."
  Direction chosen by user: make decoys interactive like SMB (banners/responses/
  workflows), **Phase A (plaintext breadth) + Phase B (TLS) together**, per-service
  miss behavior.
  - **DONE + validated (argus):** dual-path TLS (`internal/services/tlsterm.go` +
    listener): a ClientHello matching a manifest probe (JARM/scanner) still gets the
    static Schannel ServerHello (fingerprint PRESERVED); any other ClientHello is
    terminated with crypto/tls (self-signed cert, CN=computer name) and served a
    backend. `services/https` now `tls: true, tls_backend: http` → `openssl s_client`
    completes TLSv1.3 + cert, `curl -sk https://` returns an IIS page. **Tradeoff
    (load-bearing):** can't have stock-Go termination AND the Schannel JARM/JA3S on
    the *same* handshake — dual-path keeps JARM for scanners, real TLS for clients; a
    deep analyst probing both could see Go-vs-Schannel divergence (accepted).
  - **DONE + validated (argus + Kali Linux client, 2026-06-17):**
    - **TLS cert CN mechanism:** cert subject = computer name (netbios_name → hostname
      → "WORKSTATION"), coherent with SMB ComputerName / NBNS. `openssl s_client` →
      `subject=CN=WIN11LAB`. (`listener.go` tlsConfig, `tlsterm.go`.)
    - **MSRPC/135 bind_ack:** BIND (ptype 0x0b) → bind_ack (0x0c) accepting ctx 0 / NDR
      (was bind_nack = "rejects all RPC", a tell). Validated: a crafted bind from Kali
      → ptype 0x0c + call_id echo. Non-bind RPC ptypes still get bind_nack (not silence).
      `services/msrpc/{manifest.yaml,responses/bind_ack.bin}`.
  - **Silent-FIN assessed:** http (404 catch-all) + netbios (negative-session catch-all)
    already answer any probe; speaks-first services banner on connect; 443 fixed via TLS
    termination. `default_response` mechanism is available for any future gap.
  - **Work order set by user (2026-06-18): WinRM → MSRPC ept_map → NetBIOS/139 → RDP.**
    Foundational: **`os_edition` primitive** added — `OSProfile.ResolvedEdition()`
    (`internal/config/types.go`) returns workstation/server/dc (explicit `edition:`
    field, else inferred from family+name; "" for non-Windows), surfaced as the
    `os_edition` service option in `SetProfileOptions` (`internal/services/manager.go`).
    This is the config-derived switch that gates edition-dependent behaviour
    (135/139 open-vs-filtered, WinRM presence, SMB signing/computer-name defaults) so
    manifests can `requires: {os_edition: server}`. Unit-tested (types_test.go). The
    17 name-only profiles work unchanged via name inference. **Wired (2026-06-18):**
    `EditionExposesPort` + `shouldStartService` gate msrpc/139; SMB honeypot binds 139
    on server/dc only.
  - ✅ **WinRM/5985 — DONE + VALIDATED (argus + Kali, 2026-06-18).**
    `services/winrm/manifest.yaml` rewritten: a captured template existed (April, real
    Win11 HMDXIN) but had two tells — fixed both. (a) **POST /wsman → 401** Negotiate+
    Kerberos challenge (was 404 — a real WinRM challenges, never 404s its own endpoint;
    new `responses/winrm_401.bin`). (b) **live `Date:`** via `http_date` on every
    response (was frozen 2026-02-18 capture date). GET /wsman → 405 (Allow: POST), other
    → HTTP.sys 404; `default_response` set. All advertise `Server: Microsoft-HTTPAPI/2.0`.
    **Live (Kali→argus:5985):** GET → 404 + Date=today; POST /wsman → 401 Negotiate/
    Kerberos; `nmap -sV` → "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)". Edition note:
    belongs in `services:` for server profiles (client SKUs don't run it by default).
  - ✅ **MSRPC/135 ept_map — DONE + VALIDATED (argus + Kali, 2026-06-18).** Captured a
    real `impacket-rpcdump` exchange from a proxmox Win11 25H2 box (9512, 10.0.254.67):
    single ept_lookup (opnum 2) whose response = 11 DCE/RPC fragments (10×4280+2916 =
    **45,716 B**, 138 endpoints). `services/msrpc` now `stateful: true`: BIND→bind_ack
    (captured, real 4280 max-frag), then ept_lookup→`responses/epm_lookup.bin`. Two new
    rewrite types (`internal/services/responder.go`): **`dcerpc_callid`** walks PDUs by
    frag_len and echoes the client's call_id into EVERY fragment header (so the multi-
    frag reply correlates regardless of client call_id); **`host_ip`** (token=capture IP)
    replaces the capture IP in ncacn_ip_tcp tower floors with the host's egress IPv4
    (`hostEgressIPv4()` via inert UDP dial + InterfaceAddrs fallback). Unit-tested
    (`msrpc_epm_test.go`: 11 frags, call_id echo, IP gone). **Live (Kali→argus:135):**
    rpcdump enumerates all 138 endpoints; ncacn_ip_tcp bindings show **10.0.254.45**
    (argus), zero leak of capture .67; np towers show DESKTOP-G6JUGNO (matched via
    `netbios_name` — the documented coherence mitigation). Was "bind ok, no enum"; now
    full self-consistent endpoint map. **Dynamic RPC ports (2026-06-18):** tower-floor
    parser (`epm_ports.go`) extracts 8 ncacn_ip_tcp bindings from `epm_lookup.bin`
    (was 364 false positives from naive IP+port scan); `startDynamicRPCPool` opens
    BIND→bind_ack listeners. **Live (Kali→argus):** nmap all 8 open; rpcdump shows
    10.0.254.45 bindings. Commits: `a7c0e37`, `8a20ad3` (tower parse), `5922b89` (SMB1).
  - ✅ **NetBIOS/139 — DONE (2026-06-18).** `smb_honeypot` binds TCP 139 on Server/DC
    editions (`Config.NetBIOSPort`): NBSS 0x81→0x82 handshake then full SMB2/3 state
    machine (same as 445). `config.EditionExposesPort` gates 135/139/msrpc/netbios
    template on workstation (filtered, like real Win11 client). Template `netbios`
    skipped when honeypot owns 139. Files: `internal/honeypot/smb/nbss.go`,
    `internal/config/edition_ports.go`, `cmd/mimic/run.go`.
  - ✅ **RDP/3389 — DONE + VALIDATED (argus + Kali, 2026-06-18).** Stateful
    honeypot `internal/honeypot/rdp/`: X.224 nego (`rdp_neg_tls.bin`) →
    **dual-path TLS** (JARM-only ClientHellos → static `tls_server_hello.bin`;
    real clients → `crypto/tls`) → CredSSP TSRequest NTLM Type 1→Type 2 with
    **Product_Version from `profile.Version`** + live MsvAvTimestamp. Handles
    **raw ASN.1 CredSSP** (nmap `rdp-ntlm-info` sends no TPKT over TLS) and
    TPKT-wrapped TSRequest (mstsc path). `run.go` intercepts `rdp` in `services:`.
    **Live (Kali→argus:3389, Server 2022 profile):** `nmap --script rdp-ntlm-info`
    → Product_Version **10.0.20348**, Target_Name/NetBIOS/DNS = WORKGROUP /
    DESKTOP-G6JUGNO. Closes OSE tell "3389 no-NTLM". `services/rdp/manifest.yaml`
    = JARM template reference only.
- ⏸️ **Process self-ID (DEPRIORITIZED 2026-06-18):** `ss -tlnp` → `mimic` is a
  post-compromise tell only — irrelevant at network-scan OSE layer; revisit only if
  a concrete need emerges.

## Strategic roadmap (2026-06-18, parallel tracks)

**Scope:** OSE = network confusion + interactive service depth; not post-shell host
telemetry. **North star:** Windows reverse-client (WFP/Npcap hooks, same capture
pipeline inverted) after Linux benchmarks pass.

| Track | Focus | Current |
|-------|-------|---------|
| **A — OSE** | Cred-leak loop, JA4S measure, dynamic RPC ports (49664+) | **DONE** — 8 ports listening, Kali-validated |
| **B — Breadth** | `--services all`, edition gating, deeper SMB scripts | **DONE** — full smb-* enumeration suite Kali-validated |
| **C — Hygiene** | argus sync, packet-template regen on promote only | Ongoing |

## Known Gaps / Next Priority

1. ✅ **smbmap parity (RESOLVED 2026-06-18, post-signing retest).** SMB 3.1.1
   signing implemented (`signing.go`, `fa194f7`). **Retest (Kali smbmap v1.10.7 →
   argus):** authenticated share enumeration OK — IPC$/ADMIN$/C$ listed READ ONLY;
   banner still prints "0 authenticated session(s)" (smbmap accounting quirk, not a
   functional failure). Pre-fix v1.10.4 no-enum is closed.
2. ✅ **Build-number / cross-layer OS-identity coherence (RESOLVED 2026-06-17;
   roadmap Mimic_R_C.md item #7 "self-consistency is the entire value prop").**
   NTLM CHALLENGE Version derived from the profile via `Server.osVersionTriple()`;
   fallback 10.0.19041 only when OSVersion unset. All 17 Windows profiles carry a
   correct `version:` (each emits its own build), so "hardcoded 19041 regardless of
   profile" is closed. **Cross-layer audit + fixes:**
   - **Win11 profile was self-contradictory:** `version` said 10.0.22000 (21H2) but
     the stack block + RDP template were captured from 25H2. Set to **10.0.26200**
     (25H2) so eBPF stack, SMB/NTLM build, NativeOS, and RDP all agree. Faithful (a
     real 25H2 box behaves identically, incl. nmap mislabeling it 21H2). Win11 stack
     has window=65535 + timestamps-ON, vs Win10/2022 8192+off — a real 25H2 change.
   - **MsvAvTimestamp (0x0007) added** to NTLM TargetInfo (live FILETIME). Modern
     Windows always includes it; absence was a tell. Safe — NTLMv2 verify uses the
     client's blob, not our TargetInfo. AV order now 0x2,0x1,0x4,0x3,0x7,0x0.
   - **Server 2025 profile added** (`profiles/windows/server-2025.yaml`, 10.0.26100)
     from a real nmap -O capture (proxmox, captures/proxmox/srv2025): WIN=FFFF,
     OPS M5B4NW8ST11, TS=A — i.e. 25H2-class stack. Closes a captured-but-unprofiled OS.
   - **Audit clean:** Win10@19041 and all server profiles@RTM builds match their
     stacks; no other version/capture contradiction found.
   **Validated live on argus:** raw SMB2 probe reads NTLM Version **10.0 build 26200**
   from the Win11 honeypot; MsvAvTimestamp present and live (FILETIME delta 0s);
   Server 2025 profile loads + applies eBPF cleanly. Files:
   `internal/honeypot/smb/{ntlm.go,ntlm_test.go}`, `profiles/windows/{11.yaml,server-2025.yaml}`.
3. ✅ **JA4S validation (MEASURED 2026-06-18).** FoxIO `ja4.py` on JARM-captured
   pcap (Kali→argus:443): TLS 1.2 static Schannel path → **`t1203h2_c030_*`**
   (cipher c030 = ECDHE-RSA-AES256-GCM-SHA384); TLS 1.1 probe 6 →
   **`t1103h1_c014_*`**. Suffix hash varies per probe (server-random rewrite —
   live-server behavior). TLS 1.3 JARM probes hit Go `crypto/tls` path
   (`t130200_1303_*`) — expected dual-path divergence. Reference Win11 pcap
   TLS 1.3 Schannel: `t130200_1302_*`. Version+cipher components validated;
   promote full hash to Knowledge entry.
4. ✅ **Cross-service credential leak (CLOSED 2026-06-18).** `GET
   /backup_credentials.txt` emits `{{leak:backup_svc}}` → `svc_backup:…`;
   **live-validated:** `curl` leak → `nxc smb` auth OK on argus.
5. ✅ **Deeper SMB nmap scripts (VALIDATED 2026-06-18, Kali→argus:445).**
   Interactive honeypot forces `SMB1Enabled=true` (`run.go`). SRVSVC stubs:
   `NetrNetSessEnum` (op 0x0C, empty level-10), `NetrPathCompare` (op 0x20,
   ERROR_INVALID_NAME → PATCHED). LANMAN RAP: `NetServerEnum2` (op 0x68, status 71
   → "Not a master or backup browser"). **Passing:** smb-os-discovery, smb-enum-shares,
   smb2-security-mode, smb2-capabilities, smb2-time, smb-protocols, smb-security-mode,
   smb-mbenum, smb-enum-sessions (empty), smb-vuln-ms08-067 (PATCHED). Commits:
   `5b276a5`, `562421e`, `76ab37e`.
   - ✅ **SAMR + LSARPC named-pipe RPC (WRAPPED + VALIDATED 2026-06-22, impacket
     v0.11.0 → argus 127.0.0.1:445).** New `\samr` + `\lsarpc` pipe handlers
     (`internal/honeypot/smb/{samr.go,lsarpc.go,ndr_rpc.go,rpcenv.go}`, dispatched in
     `pipe.go`) with hand-rolled NDR. SAMR: Connect/2/4/5, **LookupDomain (opnum 5)**,
     EnumDomains, OpenDomain, EnumUsers, Close. LSARPC: OpenPolicy/2, QueryInfoPolicy
     (Primary/Account/DNS domain), Close. Domain SID is the shared standalone-
     workstation machine SID — self-consistent across SAMR & LSA. **Live gap found +
     fixed:** the user-enum chain broke because `SamrLookupDomainInSamServer` (opnum 5)
     returned STATUS_NOT_SUPPORTED → impacket `Error unpacking 'DomainId | PRPC_SID'`
     (a broken-server tell); added opnum-5 SID reply. **Validated:** `impacket-samrdump`
     (authenticated svc_backup AND `-no-pass` null session) now completes the full
     Connect→EnumDomains→LookupDomain→OpenDomain→EnumUsers chain with ZERO unpack
     errors → domain `DESKTOP-G6JUGNO`, "No entries received" (realistic hardened-box
     anon-enum-restricted result, no tell). Unit tests assert NDR layout incl. opnum 5
     (`samr_lsarpc_test.go`).
   - ✅ **SAMR bait-user population (Item 2, DONE + VALIDATED 2026-06-22, impacket-samrdump
     → argus).** `SamrEnumerateUsersInDomain` now returns a populated SAMPR_RID_ENUMERATION
     array — Windows built-ins (Administrator 500, Guest 501, DefaultAccount 503,
     WDAGUtilityAccount 504) + seeded creds at RID 1000+ (`baitUsers()`, threaded via
     `PipeRPCEnv.Users` from `s.cfg.Credentials` at `server.go` pipeContext). Plus the
     per-user walk samrdump requires: `SamrOpenUser` (34, RID echoed in the 20-byte handle)
     + `SamrQueryInformationUser2` (47, level 21). **The level-21 SAMPR_USER_ALL_INFORMATION
     stub is a byte-exact template GENERATED BY impacket's own getData() (380 B, UserId
     patched per-RID at offset 168)** — guarantees impacket parses it verbatim (samrdump
     prints the name from EnumUsers, not the struct). **Auth gate (realism + deception):**
     anonymous/guest EnumUsers → STATUS_ACCESS_DENIED (RestrictAnonymousSAM); only an
     AUTHENTICATED session (`!sess.isGuest()`, threaded through all 4 SMB2/SMB1 pipe sites)
     gets the list — so an attacker must reuse a leaked cred to enumerate. **Validated:**
     authenticated samrdump lists all 5 users incl. **svc_backup uid=1000** (cred-leak loop),
     zero unpack errors; null session ACCESS_DENIED; `go test ./...` green; nmap -O still
     Windows. Files: `internal/honeypot/smb/{samr.go,rpcenv.go,server.go,server_smb1.go,
     samr_lsarpc_test.go,testhelpers_test.go}`.
   - ✅ **SAMR QueryInformationDomain (Item 3, DONE + VALIDATED 2026-06-22).** opnum 8
     returns the domain policy nmap smb-enum-domains reads: class 1 Password
     (MinPasswordLength 7, complexity ON), class 12 Lockout (threshold 10), class 8
     Modified; unsupported classes → STATUS_INVALID_INFO_CLASS. Each reply is a byte-exact
     impacket-getData() template (static policy, no per-request patching). **Validated:**
     impacket `hSamrQueryInformationDomain` on the live honeypot parses all three classes
     (MinLen=7/Props=1, Threshold=10, Modified OK); unit test asserts NTSTATUS+scalars;
     go test ./... green; nmap -O still Windows. Files: `internal/honeypot/smb/{samr.go,
     samr_lsarpc_test.go}`.
   - ✅ **LSA LsarLookupSids + QueryInformationPolicy2 (Item 4, DONE + VALIDATED 2026-06-22,
     impacket-lookupsid → argus).** lookupsid's flow now fully works: `LsarOpenPolicy2` →
     `LsarQueryInformationPolicy2` (opnum 46, reuses the opnum-7 policy encoder for the
     account-domain SID) → `LsarLookupSids` (opnum 15) RID-cycling. `parseLookupSidRIDs`
     scans the request for our domain-SID prefix + RID; `encodeLsarLookupSids` builds the
     ReferencedDomains + TranslatedNames arrays dynamically (SidTypeUser+name+DomainIndex 0
     for bait RIDs, SidTypeUnknown otherwise; NTSTATUS SUCCESS/SOME_NOT_MAPPED/NONE_MAPPED).
     **Validated:** lookupsid resolves 500 Administrator / 501 Guest / 503 DefaultAccount /
     504 WDAGUtilityAccount / **1000 svc_backup** at correct RIDs (consistent with SAMR).
     **Two real bugs found + fixed via the live oracle:** (1) `parsePolicyInformationClass`
     required a 4-byte class but the real client sends a 2-byte enum (was returning 0 →
     NOT_SUPPORTED; opnum-7 was unit-test-only so latent) — now reads the USHORT at [20:22];
     (2) **DCE/RPC request reassembly** (`pipe.go`) — a large request (lookupsid's ~18KB
     LookupSids) fragments into max-xmit-frag PDUs, and the handler processed only the LAST
     fragment → mis-aligned reply (names at wrong RIDs). Now buffers stub bytes across
     fragments (PFC_FIRST/LAST flags) and dispatches the concatenated stub — a general
     robustness fix for any large RPC request. Files: `internal/honeypot/smb/{lsarpc.go,
     ndr_rpc.go,pipe.go,samr_lsarpc_test.go}`. **SAMR/LSA enumeration queue (Items 2–4) COMPLETE.**
   - ✅ **`mimic verify` cross-layer coherence oracle (Item 5, DONE + VALIDATED 2026-06-22).**
     New `cmd/mimic/verify.go` + `internal/verify/` — the codified OSE-2026-001 threat model
     (a skilled operator caught the deception pre-shell by cross-correlating layers). Probes
     a live instance and FLAGS self-contradiction, exit non-zero for CI. Checks: (1) profile
     self-consistency — declared version vs declared stack era (Win11 build ≥22000 ⇒
     window 65535 + TS-on; the documented "21H2 vs 25H2" tell, caught at the source, no
     probe); (2) TLS cert CN == computer name (live crypto/tls; the static Schannel JARM
     path reports NOTE = accepted dual-path divergence, not a tell); (3) HTTP.sys banner
     (Microsoft-HTTPAPI/2.0) on winrm/wsd. **Validated on argus:** coherent Win11 instance →
     all OK ("COHERENT"); a config with the wrong netbios_name → TLS TELL + exit 1. Unit
     tests cover the profile/version/header logic. **Prober structure is extensible** — the
     next probers (live SMB-NTLM build via the lenient NTLMSSP scan, RDP Product_Version,
     nmap -O stack) drop in as `Result`-returning funcs; SMB/RDP build-coherence is already
     construction-guaranteed (derived from profile.Version) + unit-tested, so deferring the
     live re-check is low-risk. Files: `cmd/mimic/verify.go`, `internal/verify/{verify.go,verify_test.go}`.
   - ✅ **Cross-profile coverage matrix (Item 6, VALIDATED 2026-06-22, argus + ss-book).**
     All 6 Windows profiles deployed with `--services all` and audited; **every one COHERENT
     (`mimic verify`) with correct edition gating:**
     | Profile | verify | Listening (TCP) |
     |---|---|---|
     | Windows 10 / 11 (workstation) | COHERENT | 443,3389,**5357,5985,7680** — 135/139/445 FILTERED, 5040 absent |
     | Server 2016/2019/2022/2025 | COHERENT | **135,139,445**,443,3389,5985 — desktop 5357/7680 gated off |
     Live spot-checks (ss-book nmap): **Win11** `-O`→Win10/11 (98%), rdp-ntlm-info
     Product_Version **10.0.26200**; **Server 2025** `-O`→"Windows 10|11", Product_Version
     **10.0.26100** — per-profile build propagation correct. **Near-term queue (Items 1–6)
     COMPLETE.** No new code (validation only); coverage table recorded here.
6. ⏸️ **eBPF / host-telemetry stealth (DEPRIORITIZED 2026-06-18):** post-shell
   Linux-host tells (`ss`, BPF audit) out of OSE scope unless a concrete need emerges.
   Network-layer OSE remains the priority.
6. **TLS handshake completion** — ✅ 443 dual-path TLS (2026-06-17); ✅ 3389
   CredSSP honeypot (2026-06-18, validated `rdp-ntlm-info`).
   *(OSE-2026-001: 443 FIN-after-ClientHello and 3389 no-NTLM were the tells.)*
7. **Service expansion** — ✅ MSRPC/135 ept_map (2026-06-18). ✅ `--services all`
   (2026-06-18): expands to honeypots + all templates, edition-gates 135/139,
   drops smb/rdp/netbios replay superseded by honeypots. **Validated argus Server
   2022:** 15 services (ftp+http+https+msrpc+mssql+mysql+nbns+redis+smtp+ssh+telnet+
   vnc+winrm + smb/rdp honeypots). SMB enumeration scripts closed (item #5).

## Operational

### ⚠ Lab guest credentials (corrected 2026-06-23 — DO NOT mis-parse)
- **Username:** `root` (workstations) / `Administrator` (Windows servers).
- **Password:** the LITERAL string **`root:toor26`** — the colon IS part of the
  password. It is **NOT** a `user:password` pair; the whole thing incl. `:` is the
  password. (capture.ps1 proves it: `ConvertTo-SecureString 'root:toor26'` is passed
  as the *password* arg.) Security-question answer: `root`. This has been mis-read
  repeatedly — when SSHing/WinRM-ing to any lab clone, the password is `root:toor26`.
- create-cloud Linux templates also carry the `~/.ssh/argus_lab.pub` key (key auth);
  the Kali (9341)/older templates may NOT — fall back to the password or the QEMU
  guest-agent exec (out-of-band, no SSH needed).

### argus-lab (test target)
- IP `10.0.254.45`, iface `ens18`, SSH key `~/.ssh/argus_lab` (port 2222), Go
  1.25.6 at `/usr/local/go/bin`, repo at `~/mimic/`.
- Boot persistence: `/etc/modules-load.d/mimic.conf` loads `nft_reject` +
  `nft_reject_inet`.
- **As of 2026-06-22: mimic RUNNING** on argus from `/tmp/mimic_ws.yaml` (profile
  **Windows 11 / workstation**; services rdp+winrm+wsd+deliveryopt+cdpsvc; netbios_name
  `DESKTOP-G6JUGNO`; firewalled-client default-drop, preserve_ports 2222; log →
  `/tmp/mimic_ws.log`) — switched from the prior Server 2022 `/tmp/mimic_all.yaml` for
  the port-persona validation. Restore Server 2022 by restarting with `/tmp/mimic_all.yaml`.
  Deploy: `tar xzf` → `make build` → `sudo pkill -x mimic` → restart. **Verify:**
  `grep opNetrPathCompare pipe.go` and `grep -iE "persona|Dynamic" /tmp/mimic*.log`.

### Kali attack client (for stateful-protocol validation — #4/#1)
- **VM 9511 `kali-mimic-client` @ 10.0.254.70** (proxmox node nexus, linked clone of
  template 9341 kali-2026). Reach: `ssh -o BatchMode=yes -o PreferredAuthentications=publickey
  -i ~/.ssh/argus_lab root@10.0.254.70` (Windows: `C:\Windows\System32\OpenSSH\ssh.exe`).
- Provisioned this session: argus_lab pubkey injected into root's authorized_keys (the
  9341 template did NOT carry it); sshd `UseDNS no` + `GSSAPIAuthentication no` set
  (`/etc/ssh/sshd_config.d/99-fast.conf`) — without these SSH hangs ~30s/connect. sshd
  is NOT enabled on boot by default — if the clone is reset, re-enable via the QEMU
  guest agent (`systemctl enable --now ssh`) before key-based SSH works.
- Tools: nmap, **impacket-rpcdump** (the rpcdump.py binary), nxc, tcpdump, tshark, python3.
- Drive proxmox from ss-book via `infra/proxmox/lab.py` (python; token auto-loaded).
  Capture target for re-capture: `python lab.py deploy 9011 <vmid> --linked --start`
  → `lab.py ip <vmid>` → `lab.py prep <vmid>` (fw off) → capture → `lab.py destroy <vmid>`.
- **Kept running** at handoff (do not destroy — needed for RDP argus validation).

### Resume testing
```bash
# Deploy + build
tar czf - . | ssh -i ~/.ssh/argus_lab argus-lab 'cd ~/mimic && tar xzf - && PATH=/usr/local/go/bin:$PATH make build'

# Restart (config: smb_honeypot, msrpc, netbios, nbns, rdp, https; closed 80,8080)
ssh -i ~/.ssh/argus_lab argus-lab '
  sudo modprobe nft_reject nft_reject_inet
  sudo pkill mimic; sudo nft delete table inet mimic_reject 2>/dev/null
  sudo tc filter del dev ens18 egress 2>/dev/null; sudo tc qdisc del dev ens18 clsact 2>/dev/null
  cd ~/mimic && sudo ./build/mimic run -c /tmp/mimic_full.yaml > /tmp/mimic.log 2>&1 &'

# nmap
nmap -O --osscan-guess -p 135,139,445,3389,80 10.0.254.45
& "C:\Program Files (x86)\Nmap\nmap.exe" --datadir "$env:TEMP\nmap_patched" -p 445 --script smb-enum-shares 10.0.254.45
```

### nmap smbauth.lua patch (OpenSSL 3.0 legacy-provider workaround)
nmap 7.98 on Windows can't do DES/MD4 without the OpenSSL 3.0 legacy provider.
Copy `nselib\smbauth.lua` to `$env:TEMP\nmap_patched\nselib\`, add empty-password
early returns in `lm_create_hash`/`ntlm_create_hash` + a null-session early
return in `get_password_response`, run with `--datadir "$env:TEMP\nmap_patched"`.
