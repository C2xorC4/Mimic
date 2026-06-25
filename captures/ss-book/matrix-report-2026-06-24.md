# Mimic fingerprint matrix — full host×profile sweep (2026-06-24)

**Scope:** every supported profile (16 Linux + 17 Windows + macOS = 34) cycled on
each backend/host and scanned with `nmap -Pn -O --osscan-guess -p 80,9999` from Kali
(10.0.254.70). Minimal config per cell: `services:[http]` (80 open) + `closed_ports:[9999]`
+ `closed_port_behavior: reset` for a consistent 1-open/1-closed stack read.

Hosts: **ss-book** (Win11 daily-driver, WinDivert) · **argus** (Ubuntu eBPF) ·
6 Windows VM templates (Win10/11, Server 2016/2019/2022/2025, WinDivert) ·
6 Linux VM templates (ubuntu-2204, debian-12, rocky-9, fedora, arch, kali, eBPF).

Cell code: **E**=exact match (no submit ask) · **F**=family-correct top guess ·
**X**=wrong family · **?**=no/ambiguous match · **.**=host failed to produce data.

## Per-host result (buildable profiles = 33; macOS excluded as unbuilt)

| Host (backend) | Exact | Family-correct | Wrong | Ambiguous | Verdict |
|---|---|---|---|---|---|
| **argus** (eBPF) | 1 | 32 | — | — | ✅ strongest — 1 exact (Server 2025) |
| **H:Ubuntu-2204** (eBPF) | 1 | 30 | — | 2 | ✅ 1 exact (Server 2025) |
| **H:Debian-12** (eBPF) | 0 | 33 | — | — | ✅ clean |
| **H:Win10/11/S2016/S2019/S2022/S2025** (WinDivert) | 0 | 33 each | — | — | ✅ identical across all 6 editions |
| ss-book (WinDivert, Wi-Fi) | 0 | 19 | 14 | 1 | ⚠️ environmental contamination |
| H:Rocky-9 / Fedora / Arch (eBPF) | 0 | 0 | 0 | 34 each | ❌ binary won't run (libpcap soname) |
| H:Kali (eBPF) | — | — | — | — | ❌ clone SSH key never applied |

## Headline conclusions

1. **Family-spoofing is robust and host-independent.** On every *clean working* host,
   all 33 buildable profiles read as the correct OS family at 88–99%. The WinDivert
   backend produces **identical** results across all 6 Windows host editions
   (Win10/11 + Server 2016–2025) — proving the mutation is host-edition-independent,
   the core validation goal.
2. **eBPF (Linux host) is the stronger backend** — 96–98% matches, and the only **exact
   matches** in the whole sweep: **Windows Server 2025** on argus AND ubuntu-2204
   (no submit ask). WinDivert tops out at 99% (Win11) — one indicator short of exact.
3. **Exact-version match is rare but ACHIEVABLE, not structurally blocked** — it is the
   per-indicator iteration we already did for Server 2025. The matrix + nmap-os-db diff
   tells us which cells are closest and exactly which fields to fix.
4. **ss-book is unfit as a fidelity-test host** (Wi-Fi timing jitter + live traffic →
   decoy matches). Same binary on a wired VM → 96–99%. **Always test on a fresh VM.**

## Why "no exact match" — decomposed (the actionable part)

### Class A — profile-field drift vs nmap-os-db (FIXABLE, the main lever)
Hand-authored profiles carry approximate stack values that differ from the nmap DB
reference per version. Diff of mimic-emitted vs `nmap-os-db`:

| Profile | nmap ref window | nmap ref TS | nmap ref TI | mimic profile | Fix |
|---|---|---|---|---|---|
| Server 2019 | **FFFF** | NNS (off, TS=U) | I | win=8192, ts=false | window→65535 |
| Server 2022 | **FFFF** | **ST11** (on) | I | win=8192, ts=false | window→65535, **tcp_timestamps→true** |
| Server 2016 | 2000 (8192) | **ST11** (on) | **RD** | win=8192, ts=false, TI=I | tcp_timestamps→true, ip_id→random |
| Win10 1909 | 2000 | NNS (off, TS=U) | I | matches | ✅ correct as-is |
| Win11 / Server 2025 | FFFF | ST11 | I | matches | ✅ (after OPS fix below) |

### Class B — systematic mutation indicators (FIXABLE in code)
- **OPS `ST10→ST11`** — ✅ **FIXED THIS SESSION + VALIDATED** (96→99% on Win11/Server2025).
  TSecr was 0 because the Windows host has TS disabled; now echoes the inbound-SYN
  cache's client TSval (extends the Linux fix to the Win10/11 TS-on branch).
- **`CI=RD→I`** — closed-port RST carries nmap's IP-ID instead of mimic's incremental
  shared counter. Fix: stamp the shared IP-ID on closed-port RSTs (cross-package:
  netfilter closed responder must read the stack IP-ID counter).

### Class C — structural ceilings (HARD / document-and-accept)
- **SEQ `SP`/`ISR` rate** — ISN generation rate/predictability is the HOST kernel's,
  not mimic's. Usually within nmap's range tolerance; full control would need ISN
  rewriting (a documented hard ceiling, esp. on the Windows host).
- **macOS** — no convincing match anywhere because the profile is **UNBUILT**: no macOS
  VM/template, no captures, hand-guessed stack. Needs the image→capture→response track
  before it can be tuned. Not a matrix failure; out of scope until built.

## Infrastructure findings (from testing each template)
- **libpcap soname portability** — the Linux binary links `libpcap.so.0.8` (Debian/Ubuntu)
  + glibc 2.35, so it **fails to execute on RHEL/Fedora/Arch** (which ship `libpcap.so.1`).
  → 3 host quadrants produced no data. **Fix options:** build `run` without libpcap
  (capture.go is the only libpcap user and is already a separate Linux-only file — a
  build tag could drop it from the serve/run binary), OR static-link libpcap, OR
  per-distro builds. This blocks RHEL/Arch-family eBPF validation until resolved.
- **Kali template** — cloud clone never applied the argus_lab SSH key (sshd/cloud-init
  gap, consistent with the 9341 template notes). Needs key-injection in the template.
- **macOS** — no template exists yet (see Class C).

## Prioritized fix queue (cheapest-leverage first)
1. ✅ **OPS ST10→ST11** (done) — every TS-on Windows profile, validated.
2. **Server 2019/2022 window→65535 + Server 2016/2019/2022 tcp_timestamps** (profile YAML
   edits) — pure data, no code; moves the whole Server line toward its nmap reference.
3. **CI=RD→I** (closed-RST shared IP-ID) — one code change, lifts every Windows profile.
4. **libpcap-free `run` build** — unlocks RHEL/Fedora/Arch host validation.
5. Then iterate residual SEQ centering per high-value profile to chase exact (Server-2025
   style), accepting the ISN ceiling where it bites.

## Can we make nmap stop asking for a submission?
**Yes, per-config — it is iteration, not an impossibility.** Proof: 2 cells already hit
exact (Server 2025 on both eBPF hosts). The recipe is the Class-A profile correction +
Class-B code fixes above, iterated indicator-by-indicator against the nmap-os-db
reference (exactly the Server-2025 method). The residual that may resist on the Windows
backend is the SEQ ISN rate (Class C, host-kernel ceiling); where it does, that's the
documented reason. eBPF (Linux host) reaches exact most readily.
