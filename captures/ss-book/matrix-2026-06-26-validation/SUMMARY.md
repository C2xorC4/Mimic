# Post-fix regression matrix — captured profiles, all 3 fidelity levels (2026-06-26)

Validates the mimic-hifi offload/LSO fix + connectivity watchdog (commit `4d9755e`): the
driver-armed network break is gone AND exact-match fidelity is preserved. Run on fresh
proxmox clones, scanned with `nmap -O` from Kali (10.0.254.70), driven out-of-band via the
guest agent (Windows) / SSH (Linux).

**Profile set = captured + integrated only** (per operator scope): Windows 10/11, Server
2016/2019/2022/2025; Linux Ubuntu, Debian, Fedora, Rocky, CentOS 7, Arch, Kali. Excluded
(no capture backing): macOS; Windows XP/Vista/7/8/8.1/Server 2003–2012R2; uncaptured Linux
(Alma/RHEL/CentOS-Stream/openSUSE/Manjaro/Mint/Gentoo/Alpine).

## Result — STABILITY: PASS on all three runs (no host taken offline)

| Backend (host) | Windows personas | Linux personas | Stability |
|---|---|---|---|
| WinDivert-standard (Win VM 9523) | **EXACT 6/6** | family-correct ~95% (TI=I ceiling) | PASS |
| **mimic-hifi driver (Win VM 9523)** | **EXACT 6/6** | **EXACT 7/7 (TI=Z)** | **PASS** |
| eBPF (Linux VM 9524) | family-correct (top guess correct) | **EXACT 7/7 (TI=Z)** | PASS |

### Headline
- **hifi tier now reaches EXACT on BOTH families with full network stability** — the
  bug that broke all outbound TCP under NIC offload is fixed; all 7 armed Linux personas
  cycled with the VM reachable throughout.
- **winstd vs hifi** isolates the driver's value: the same Linux persona is `Linux
  4.15-5.19 (95%)` / TI=I under plain WinDivert and `OS details: Linux 4.15-5.19` EXACT /
  TI=Z with the driver. The driver flips 95%→exact.
- eBPF and WinDivert-standard behave at their documented native-family strengths
  (eBPF→Linux exact; WinDivert→Windows exact). Unchanged by this fix (Windows-only code).

### Per-persona highlights
- Windows (hifi & winstd): Win10→`Windows 10 1909`; Win11/Srv2022/2025→`Windows 10 1703 or
  Windows 11 21H2`; Srv2016→`Windows 10 1507-1607`; Srv2019→`Windows Server 2019` — all EXACT.
- Linux (hifi & eBPF): modern→`Linux 4.15-5.19` EXACT; CentOS 7→`Linux 3.2-4.14` EXACT
  (correct older-kernel class).

Raw logs: `matrix_hifi_fixed.log`, `matrix_winstd.log`, `matrix_ebpf.log`.
Harness: `matrix_run.py` (Windows, guest-agent), `ebpf_matrix.py` (Linux, SSH), `ga.py`.

---

## eBPF Windows-persona EXACT chase — diagnosis (2026-06-26)

NOT the SEQ/ISN ceiling and NOT a sampling artifact. eBPF Windows personas split 3 exact
(Srv 2016/2022/2025) / 3 not (Win10/11/Srv2019) on edition-specific indicators that the
WinDivert backend received but were never back-ported to the Linux paths. SEQ SP/ISR for
all of them land IN the nmap-os-db reference range (ISR marginally high = flicker, not the
blocker).

| Persona | Primary divergence vs nmap-os-db | Fix |
|---|---|---|
| **Windows 11** | ICMP echo dropped in `reset` mode (`run.go` gated on bare `isWorkstation`, not `autoDrop`) → `IE(R=N)` + lost `II`/`SS` | **FIXED `6fdb34b` (Go) → now `Win10 1703/Win11 21H2` EXACT** |
| Windows 10 | TS-off OPS not normalized on a Linux host: `O1..O5` padded with trailing NOPs, `O6=M5B4ST11` (stray TS) vs ref `M5B4NW8NNS`/`M5B4NNS` | fingerprint.c TS-strip + option-length shrink (eBPF `shrinkTCPHeader` equiv) + bytecode regen |
| Server 2019 | `ECN CC=N` vs ref `CC=Y` — the `ecnCC`/`explicit_congestion: echo` split was never ported to fingerprint.c | fingerprint.c ecnCC + bytecode regen |

The two remaining fixes are eBPF C (fingerprint.c) + a bpf2go bytecode regen (clang on a
Linux box) — well-scoped, no ISN-rewriting required.
