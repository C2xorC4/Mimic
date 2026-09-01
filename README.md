# Mimic

Makes a host present as a different operating system to network fingerprinting
tools (nmap, p0f, JARM, JA3S, Shodan). A Linux box can pass as Windows or as a
different Linux distro; a Windows box can pass as a different OS — defeating OS
attribution at the recon stage and standing up convincing, interactive decoy
services that cost an attacker time and surface fake credentials.

Two concurrent layers, both **OS-family aware** (the same binary emulates a
Windows *or* a Linux persona based on the selected profile):

1. **Stack fingerprinting** — kernel/userland packet rewriting so the TCP/IP
   stack matches the target OS.
2. **Service emulation** — interactive honeypots and captured-response listeners
   so application-layer probes (SMB enum, RDP NTLM, SSH, HTTP, …) answer like the
   target OS.

## Platforms

Mimic runs as both a Linux and a Windows application from a single codebase
behind a platform-agnostic backend seam:

| Host | Stack backend | Lifecycle | Notes |
|------|---------------|-----------|-------|
| **Linux** | eBPF at the TC egress/ingress hooks (`clsact`) | systemd unit | Primary platform; full capture pipeline |
| **Windows** | WinDivert (userland, signed driver) | Windows Service (SCM) | Npcap-free binary; ships `WinDivert.dll` + `WinDivert64.sys` |

Where a platform has no stack backend, `mimic run` degrades to service emulation
only rather than failing.

## How It Works

**Layer 1 — stack fingerprinting** rewrites outgoing packet characteristics to
match the profile: TTL, DF bit, IP-ID behavior, TCP window / scale / MSS, TCP
options ordering and content (timestamps, SACK, window scale), TCP timestamp
values (TSval on an ~1 kHz clock, TSecr echoed), RST window/ACK behavior, ECN
response, and ICMP echo behavior. Checksums are fixed in place.

The mutations are **family-gated** so each profile is internally coherent:

- **Windows profiles** get the Windows traits — Windows-ordered TCP options
  (`MSS,NOP,WS,SACK,TS`), shared IP-ID counter across TCP+ICMP (nmap `SS=S`),
  A=O RST ack, ICMP `CD=Z`, ECN `CC=N`, and nft-based T2/T3 probe responses.
- **Linux profiles** emit the Linux order (`MSS,SACK,TS,NOP,WS`) and keep the
  host's native behavior (per-socket IP-ID/`SS=O`, A=Z RST, `CD=S`, ECN `CC=Y`),
  so a Linux box fingerprints cleanly as the chosen distro — the basis for
  distro-spoofing (poisoning which distro-specific CVEs an attacker pursues).

**Layer 2 — service emulation** runs two kinds of listeners concurrently:

- **Interactive honeypots** (hand-coded state machines): SMB2/3, RDP, SSH (+SFTP),
  FTP — real protocol flows, seeded-credential auth, and a shared deception
  filesystem with a cross-service **credential-leak loop** (a cred surfaced by one
  service authenticates against another).
- **Template-replay services** (captured probe→response pairs with dynamic field
  rewriting): HTTP/HTTPS, MSRPC/EPM, NetBIOS/NBNS, WinRM, WSD, Delivery
  Optimization, SMTP, Redis, VNC, MySQL, MSSQL, Telnet. Responses are OS/distro-
  aware (IIS vs nginx vs Apache; per-distro SSH/HTTP identity).

Services are edition- and family-gated (e.g. 135/139/445 exposed on Windows
Server but filtered on a workstation persona; SSH honeypot only under a Linux
profile). `--services all` expands to the full set with gating applied.

Both layers run under `mimic run`.

## Profiles

34 profiles across three families. Capture-backed depth is concentrated where it
matters:

| Tier | Profiles |
|------|----------|
| **Validated (capture-backed)** | Windows 10, Windows 11, Windows Server 2016 / 2019 / 2022 / 2025; Ubuntu, Debian, Rocky, AlmaLinux, RHEL, Fedora, CentOS Stream / 7, Arch, Kali, Mint, Manjaro, openSUSE, Gentoo, Alpine, Slackware |
| **Legacy (stack-only, unvalidated)** | Windows 7 / 8 / 8.1 / Vista / XP SP2 / SP3, Server 2003 / 2008 / 2008 R2 / 2012 / 2012 R2 |
| **Experimental** | macOS Sonoma (stack only) |

The legacy pre-10 Windows profiles exist as stack templates but have **no captured
service responses and are not validated** — pre-10 support was dropped (high
overhead, minimal return). Use the validated set in production.

Linux distro differences live mostly at the service layer (SSH version, HTTP
server, `os-release`) rather than the stack; Mimic carries per-distro identity for
the validated distros.

## Services

| Service | Port | Kind | Notes |
|---------|------|------|-------|
| `smb_honeypot` | 445 (+139 server/DC) | interactive | SMB1 + SMB2/3.1.1; share enum, NTLMv2 auth, SMB3 signing, file read; SAMR/LSARPC/SRVSVC named pipes |
| `rdp` | 3389 | interactive | X.224 → dual-path TLS → CredSSP NTLM; `rdp-ntlm-info` returns the profile's Product_Version |
| `ssh_honeypot` | 22 | interactive | Full SSH transport (golang.org/x/crypto/ssh); seeded-cred auth; pseudo-shell + **SFTP** over a per-distro Linux VFS (Linux profiles only) |
| `ftp_honeypot` | 21 | interactive | Stateful FTP over the shared deception filesystem |
| `https` | 443 | template | Dual-path TLS — static Schannel ServerHello for JARM/JA3S scanner probes; real `crypto/tls` for genuine clients |
| `http` | 80 | template | OS/distro-aware: IIS (Windows) / nginx (Debian-family) / Apache (RHEL-family), live `Date` |
| `msrpc` | 135 | template | DCE/RPC endpoint mapper — `bind_ack` + `ept_lookup` (full endpoint enum via rpcdump) |
| `nbns` | 137/UDP | template | NetBIOS Name Service node status |
| `netbios` | 139 | template | NetBIOS session (bridged by `smb_honeypot` on Server/DC) |
| `winrm` | 5985 | template | WinRM over HTTP.sys — `POST /wsman` → 401 Negotiate/Kerberos |
| `wsd` | 5357 | template | WSDAPI (workstation persona) |
| `deliveryopt` | 7680 | template | Delivery Optimization (workstation persona) |
| `smtp` `redis` `vnc` `mysql` `mssql` `telnet` | 25 / 6379 / 5900 / 3306 / 1433 / 23 | template | `-sV`-hardened banners/handshakes, OS-gated where relevant |

## Validation

Tested against real fingerprinting tools on live lab hardware.

**Windows persona — `nmap -O`** (Windows 11 / Server 2025 profiles), Linux host
*and* Windows host:
```
Running: Microsoft Windows 10|11
OS details: Microsoft Windows 10 1703 or Windows 11 21H2
```
Full vector correct across nmap probe classes (SEQ/OPS/WIN/ECN/T1–T7/U1/IE).

**Linux persona — `nmap -O`** (Ubuntu/Debian/Rocky/Fedora profiles): top match is
the correct **Linux** class with zero Windows contamination — the family-gating
above is what makes this clean.

**Per-distro HTTP** (`curl -I`): Ubuntu → `nginx/1.18.0 (Ubuntu)` + nginx page;
Rocky → `Apache/2.4.57 (Rocky Linux)` + Apache page; header and body coherent.

**SSH honeypot**: `nmap -sV` reports the real per-distro OpenSSH banner; a client
authenticates with a seeded credential and gets a pseudo-shell (`uname`, `cat
/etc/os-release`, …) and working SFTP downloads, including the cred-leak breadcrumb.

**JARM** (TLS stack): `2ad2ad00000000022c0000000000000daf8512f1afb4642b76b4dfdb33f354`
— matches Windows IIS/Schannel. **JA3S**: `6c2811f7ba8e88604ea41a2bf9fa5ad7`
(TLS 1.3 Schannel).

## Control plane & RBAC

`mimic run` can expose a local control endpoint (unix socket, peer-credential
authenticated) for status, logs, and (future) service control:

```bash
sudo mimic ctl status      # profile, services, pid, uptime, event count
sudo mimic ctl logs -n 50  # recent security events
sudo mimic ctl ping
```

Access is gated by an `Authorizer` that maps the connecting peer's uid/gid to a
role and its allowed operations; every access is audited onto the event bus.
Root is always admin; with no roles configured only root may connect (so RBAC is
opt-in without breaking existing deployments). Configure roles under `rbac:` (see
Configuration). Enable with `control.enabled: true`.

## Fingerprint regression harness

Mimic ships a two-tier harness so "no fingerprint regression" is mechanically
checkable, not eyeballed:

- **Offline (CI):** `make test-unit` parses recorded `nmap -oX` fixtures and diffs
  them against per-profile goldens (`test/golden/*.yaml`), plus an all-profiles
  self-consistency check (version ↔ stack era). No scanner required.
- **Live:** `make matrix MATRIX_TARGET=<ip> MATRIX_ALL=1` scans a running target
  and diffs every golden via the same parser; exits non-zero on any drift.

`mimic verify -c <config>` is a fast local cross-layer coherence oracle (profile
self-consistency, TLS cert CN ↔ computer name, HTTP.sys banner).

## Requirements

**Linux (eBPF backend):**
- Kernel 5.15+ (TC `clsact` hooks)
- Go 1.25+, clang, libbpf headers (`/usr/include/bpf`)
- libpcap-dev (capture subcommand)
- Root (eBPF load, low-port bind)
- For T2/T3 probe responses + closed-port shaping: `sudo modprobe nft_reject
  nft_reject_inet` (persist via `/etc/modules-load.d/mimic.conf`)

**Windows (WinDivert backend):**
- Windows 10/11 or Server 2016+; Administrator
- `WinDivert.dll` + `WinDivert64.sys` (v2.x) alongside the binary

## Build

```bash
# Linux: install the eBPF code generator, then build (generate + compile)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
make build

# Windows (cross-platform Go; no eBPF/clang needed):
GOOS=windows go build -o mimic.exe ./cmd/mimic

# Install system-wide (Linux systemd; Windows registers an SCM service)
sudo make install        # Linux
mimic install            # Windows (Administrator)
```

The binary lands at `build/mimic`. Profiles install to `/etc/mimic/profiles/`
(Linux) or `C:\Program Files\Mimic` (Windows).

**Offline builds** (lab hosts without module-proxy access): `bpf2go` is pinned via
`tools.go`, so `go mod vendor` then `GOFLAGS=-mod=vendor make build-only` builds
without network access. Regenerate eBPF bindings on a Linux host with clang
(`make generate`) after changing `internal/ebpf/fingerprint.c`.

## Usage

```bash
# List / inspect profiles
./build/mimic list
./build/mimic show "Windows 11"

# Full deception (recommended): stack + services concurrently
sudo ./build/mimic run "Windows 11" -i eth0 --services all
sudo ./build/mimic run "Ubuntu"     -i eth0 --services ssh_honeypot,http

# Config file
sudo ./build/mimic run -c /etc/mimic/config.yaml

# Stack only / services only
sudo ./build/mimic apply "Windows 11" -i eth0
sudo ./build/mimic serve --services smb_honeypot,rdp,https

# Teardown (idempotent; removes TC filters + nft tables)
sudo ./build/mimic stop
```

> **Workstation-persona safety:** a Windows *workstation* profile (Windows 10/11)
> defaults to a firewalled-client posture that **drops** unserved ports (they read
> `filtered`). Set `firewall.preserve_ports: [22]` (or your SSH port) — or
> `firewall.closed_port_behavior: reset` — so you don't lock yourself out over SSH.
> Server and Linux profiles don't auto-drop.

### Capture probe/response pairs (Linux)

```bash
# From a live interface on a reference host
sudo ./build/mimic capture live -i eth0 --server-ip <host-ip> --service smb --os "Windows 11"

# From an existing pcap
./build/mimic capture pcap capture.pcapng --server-ip <host-ip> --service smb --os "Windows 11"
```

Output: `services/<name>/manifest.yaml` + binary response files under
`services/<name>/responses/`.

## Configuration

```yaml
profile: "Windows 11"
interface: eth0                 # Linux only; unused on Windows (WinDivert is host-wide)

services:
  - all                         # or an explicit list (smb_honeypot, rdp, ssh_honeypot, https, ...)

closed_ports: [8080, 8443]      # respond RST (gives nmap -O a closed port)

firewall:
  closed_port_behavior: reset   # reset (RST) | drop/filtered (firewalled-client persona)
  preserve_ports: [22]          # always reachable under drop mode (MUST include SSH)
  open_ports: []                # extra ports answered under drop mode

service_options:
  netbios_name: "DESKTOP-G6JUGNO"
  domain: "WORKGROUP"
  hostname: "web01"
  mac_address: ""               # empty = random locally-administered MAC
  jitter_min_ms: 5
  jitter_max_ms: 50

# Shared fake-credential pool (honeypot auth + cross-service leak loop)
credentials:
  - { id: backup_svc, username: svc_backup, password: "Passw0rd123", domain: "WORKGROUP" }

# Local control plane (off by default)
control:
  enabled: false
  socket: /run/mimic.sock
rbac:
  roles:
    - { name: auditor, gids: [2000], allow: [status, logs, ping] }
    - { name: ops,     uids: [1001], allow: ["*"] }

logging:
  level: info                   # debug | info | warn | error
  log_dir: /var/log/mimic
  json_mode: true               # JSON file logs (SIEM-friendly)
  to_stdout: true

profiles_dir: ./profiles
services_dir: ./services
```

CLI flags override config values; the profile can also be a positional argument.

## Profile Format

```yaml
name: "Windows 11"
family: windows                 # windows | linux | macos  (drives family-gating)
version: "10.0.26200"

stack:
  ttl: 128
  df_bit: true
  ip_id_behavior: incremental   # incremental | random | zero
  window_size: 65535
  window_scale: 8
  mss: 1460
  tcp_timestamps: true
  sack_permitted: true
  tcp_options_order: [mss, nop, window_scale, sack_permitted, timestamp]
  ecn_support: true
  ack_in_rst: zero
  window_in_rst: 0
  icmp_quote_size: 8
  icmp_df_in_quote: true
  icmp_ttl_in_quote: 128
  udp_closed_port_response: true

smb:                            # protocol behavior for the SMB honeypot
  dialect: "3.1.1"
  smb1_enabled: false
  signing_required: false
```

## Operational Notes

Mimic's network-outward deception is transparent on the wire, but its mechanism is
visible to **host** telemetry: the eBPF TC attachment / WinDivert handle, the nft
tables, and the service listener ports are observable to auditd+BPF, Falco,
Tetragon, `ss -lp`, etc. Mimic is effective against adversaries with network-side
visibility; a host with EDR/SIEM pulling kernel-audit events is a separate
detection surface. There is a deliberate dual-path tradeoff on TLS (static
Schannel JARM/JA3S for scanners vs. a real Go handshake for clients) that a deep
analyst probing both paths could distinguish.

## License

Source is licensed under the [PolyForm Shield License 1.0.0](LICENSE).
Source-available, not OSI open source.

You may use, modify, and share it — including individual professional
use. You may not provide a product that competes with this software, or
with any product the copyright holder provides using it.

eBPF kernel programs under `internal/ebpf/` remain GPLv2-compatible —
see [LICENSE-GPL](LICENSE-GPL). Binaries the copyright holder distributes
may also be governed by [EULA.txt](EULA.txt). Other legal templates:
[docs/legal/](docs/legal/).
