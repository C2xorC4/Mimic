# Mimic

Makes a Linux system appear as a different operating system to network fingerprinting tools. Defeats nmap OS detection, JARM TLS fingerprinting, and JA3S analysis through two concurrent mechanisms: kernel-level TCP/IP stack modification via eBPF and application-layer service emulation with captured Windows responses.

## How It Works

**Layer 1 — eBPF stack fingerprinting** attaches to the TC egress and ingress hooks and rewrites outgoing packet characteristics in-kernel:
- TTL, DF bit, IP ID behavior (incremental/random/zero)
- TCP window size, window scale, MSS
- TCP options ordering and content (timestamps, SACK, WS — Windows-style templates)
- TCP timestamp values (TSval at 1kHz, TSecr echoed from peer)
- RST packet behavior (ACK field set from ingress-cached probe sequence numbers)
- ICMP echo reply behavior (DF bit, code field)
- Shared IP ID counter across TCP and ICMP for stack coherence

**Layer 2 — Service emulation** binds TCP/UDP listeners that respond to scanner probes with captured Windows application-layer responses:
- Probe matching via byte-pattern signatures with positional wildcards
- Per-response field rewriting (Windows FILETIME timestamps, GUIDs, random session data)
- Response jitter for timing fingerprint evasion

Both layers run concurrently under `mimic run`.

## Validation

Tested against real fingerprinting tools on live hardware. With the Windows 11 profile active:

**nmap -O** returns an exact database match:
```
Device type: general purpose
Running: Microsoft Windows 10|11
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_11
OS details: Microsoft Windows 10 1703 or Windows 11 21H2
Network Distance: 1 hop
```

Full fingerprint confirmed correct across all nmap probe classes: SEQ (TI=I, SS=S, TS=A), OPS, WIN, ECN, T1–T7, U1, IE.

**JARM** (TLS stack fingerprint): `2ad2ad00000000022c0000000000000daf8512f1afb4642b76b4dfdb33f354`  
Matches Windows IIS/Schannel. Achieved by serving TLS 1.2 (c030) for JARM probes 1–2 and TLS 1.1 (c014) for probe 6, with no response to the remaining probes — matching Windows Server behavior exactly.

**JA3S**: `6c2811f7ba8e88604ea41a2bf9fa5ad7` (TLS 1.3 Schannel, port 443)

Works with SSH visible on port 22 — `nmap -O` without `-p` still returns an exact Windows 11 match.

## Profiles

33 OS profiles across three families:

| Family | Profiles |
|--------|----------|
| **Windows** | XP SP2/SP3, Vista, 7, 8, 8.1, 10, 11, Server 2003/2008/2008 R2/2012/2012 R2/2016/2019/2022 |
| **Linux** | Arch, Alpine, Alma, CentOS 7/Stream, Debian, Fedora, Gentoo, Kali, Manjaro, Mint, openSUSE, RHEL, Rocky, Slackware, Ubuntu |
| **macOS** | Sonoma |

## Services

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| `smb` | TCP | 445 | SMB2 negotiate — captured Windows 11 responses with dynamic GUID/timestamp rewriting |
| `msrpc` | TCP | 135 | DCE/RPC endpoint mapper bind_nack |
| `netbios` | TCP | 139 | NetBIOS session service |
| `nbns` | UDP | 137 | NetBIOS Name Service node status |
| `rdp` | TCP | 3389 | RDP connection banner |
| `https` | TCP | 443 | TLS ServerHello (JARM + JA3S fingerprint) |
| `http` | TCP | 80 | HTTP banner |
| `ssh` | TCP | 22 | SSH banner |
| `winrm` | TCP | 5985 | WinRM HTTP banner |

---

## Requirements

- Linux kernel 5.15+ (eBPF TC hooks with `clsact` qdisc)
- Go 1.21+
- clang (eBPF compilation)
- libbpf headers (`/usr/include/bpf`)
- libpcap-dev (capture subcommand)
- Root privileges (eBPF loading, low port binding)

For T2/T3 nmap probe responses:
```
sudo modprobe nft_reject nft_reject_inet
```

To persist across reboots, add both modules to `/etc/modules-load.d/mimic.conf`.

## Build

```bash
# Install bpf2go code generator
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Build (generates eBPF Go bindings, then compiles)
make build

# Or step by step
make generate
make build-only

# Install system-wide
sudo make install
```

The binary lands at `build/mimic`. Profiles install to `/etc/mimic/profiles/`.

---

## Usage

### List available profiles

```bash
./build/mimic list
./build/mimic show "Windows 11"
```

### Run full deception (recommended)

Starts eBPF fingerprinting and service emulation concurrently:

```bash
sudo ./build/mimic run "Windows 11" -i eth0 --services smb,msrpc,netbios,nbns,rdp,https --closed-ports 8080,8443
```

`--closed-ports` ports respond with RST. nmap OS detection requires at least one open and one closed port — include at least two ports that aren't already bound by a running service.

### Run with a config file

```bash
sudo ./build/mimic run -c /etc/mimic/config.yaml
```

### eBPF fingerprint only (no service emulation)

```bash
sudo ./build/mimic apply "Windows 11" -i eth0
```

### Service emulation only

```bash
sudo ./build/mimic serve --services smb,msrpc,netbios,nbns,rdp,https
```

### Capture probe/response pairs from a real host

```bash
# From a live interface on the reference host
sudo ./build/mimic capture live -i eth0 --server-ip <reference-host-ip> --service smb --os "Windows 11"

# From an existing pcap
./build/mimic capture pcap capture.pcapng --server-ip <reference-host-ip> --service smb --os "Windows 11"
```

Capture output: `services/<name>/manifest.yaml` and binary response files under `services/<name>/responses/`.

---

## Configuration

Full reference (`config.yaml.example`):

```yaml
# OS profile to emulate
profile: "Windows 11"

# Network interface
interface: eth0

# Services to emulate
services:
  - smb
  - msrpc
  - netbios
  - nbns
  - rdp
  - https

# Ports that appear closed (RST on connect)
closed_ports:
  - 8080
  - 8443

# Per-service options
service_options:
  netbios_name: "WORKSTATION"   # 15 chars max, auto-uppercased
  domain: "WORKGROUP"
  hostname: "workstation"
  mac_address: ""               # empty = random locally-administered MAC
  jitter_min_ms: 5              # response timing jitter (0 to disable)
  jitter_max_ms: 50

# Logging
logging:
  level: info                   # debug, info, warn, error
  log_dir: /var/log/mimic
  json_mode: true               # JSON for file logs (SIEM-friendly)
  to_stdout: true

# Override default paths
profiles_dir: ./profiles
services_dir: ./services
```

CLI flags override config file values. The profile name can also be passed as a positional argument:

```bash
sudo ./build/mimic run "Windows 11" -i eth0 --services smb,msrpc
```

## Profile Format

```yaml
name: "Windows 11"
family: windows
version: "10.0.22000"

stack:
  ttl: 128
  df_bit: true
  ip_id_behavior: incremental   # incremental | random | zero

  window_size: 65535
  window_scale: 8
  mss: 1460
  tcp_timestamps: true
  sack_permitted: true
  tcp_options_order:
    - mss
    - nop
    - window_scale
    - sack_permitted
    - timestamp

  ecn_support: true
  ack_in_rst: zero              # zero | echoed | incremented
  window_in_rst: 0

  icmp_quote_size: 8
  icmp_df_in_quote: true
  icmp_ttl_in_quote: 128
  icmp_rate_limit: false

  udp_closed_port_response: true
```

## Operational Notes

Mimic's network-outward deception is transparent on the host. The eBPF TC attachment (`BPF_PROG_LOAD` + `RTM_NEWTFILTER` netlink messages) and service listener ports are visible to host telemetry — auditd with BPF rules, Falco, Tetragon, and `ss -lp`. Mimic is effective against adversaries with purely network-side visibility; environments with host-based EDR or SIEM pulling auditd events present a separate detection surface.

## License

See [LICENSE](LICENSE).
