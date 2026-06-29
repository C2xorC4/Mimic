# CLAUDE.md

@./MEMORY.md

Project context for Mimic - OS fingerprint deception tool.

## Vision

> Eventually I would like both a Windows AND Linux application, but we'll start with Linux. The intent is to alter outgoing responses to mimic the packet structure of a chosen OS as closely as possible. We want Window sizes, TTL, all of it to be able to be selected by the user, and applied to the machine as a whole. This is the first piece of the puzzle.
>
> The second is user selectable 'services.' These aren't actually services, but are instead listeners designed to capture packets from software such as nmap - and more specifically its scripts used for enumeration. In my prior manual testing, SMB was a perfect example. If you replay a SMB response captured from a windows machine, it causes issues with what nmap expects. We want to be able to manually capture each individual response to an nmap script on other platforms, alter them so they appear as if they are the current response, then replay them to the machine performing the scan.
>
> This will give the appearance of a linux machine running Windows services, etc. Likewise, it could (later) act as a honeypot, or at least a trap causing attackers to burn time trying to explore non-existent services and directories during their recon phase.

**Capture automation requirement:**
> For service emulation, we will need a way to be able to extract both the received packet from a scan, and match that with the response sent back out. It will be very difficult to account for every rx/tx packet for each potential service added without an automated way to process them.

This drove the `mimic capture` subsystem — live capture or pcap processing extracts probe/response pairs, generates signature patterns, and creates replayable templates with dynamic field rewriting.

## Project Overview

**Mimic** makes a Linux system appear as a different OS (Windows, macOS, other Linux distros) to network fingerprinting tools like nmap, p0f, and Shodan.

Two-layer approach:
1. **eBPF stack fingerprinting** — Modifies outgoing packets at TC egress to spoof TCP/IP stack characteristics
2. **Service emulation** — Replays captured application-layer responses (SMB, RDP, etc.)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    mimic run                          │
│  Unified command: eBPF + Services in concurrent threads  │
├─────────────────────────────────────────────────────────┤
│  [Thread 1] eBPF TC egress: TTL, DF, IP ID, Window      │
│  [Thread 2] Service listeners: SMB, MSRPC, NetBIOS      │
└─────────────────────────────────────────────────────────┘
```

## Directory Structure

```
cmd/mimic/          # CLI commands (main, capture, serve, run)
internal/
  ebpf/                # eBPF loader, types, fingerprint.c
  config/              # Profile and config loading
  services/            # Service emulation (listener, responder, matcher)
  capture/             # Pcap processing, template generation
profiles/              # OS fingerprint profiles (YAML)
  windows/             # Windows XP through Server 2025
  linux/               # Major distros
  macos/               # Sonoma
services/
  smb/                 # SMB (TCP 445) - negotiate responses
  msrpc/               # MSRPC (TCP 135) - DCE/RPC bind_nack
  netbios/             # NetBIOS Session (TCP 139)
  nbns/                # NetBIOS Name Service (UDP 137) - node status
```

## Build & Run

```bash
# Build
make build

# List profiles
./build/mimic list

# RECOMMENDED: Unified run command (eBPF + services in parallel)
sudo ./build/mimic run -i eth0 --profile "Windows 11" --services smb,msrpc,netbios,nbns

# Or with config file
sudo ./build/mimic run -c ./config.yaml

# Individual commands (for debugging):
# Apply stack fingerprint only
sudo ./build/mimic apply "Windows 11" -i eth0

# Run service emulation only
sudo ./build/mimic serve --services smb,msrpc,netbios,nbns
```

## Configuration File

See `config.yaml.example` for full options:

```yaml
profile: "Windows 11"
interface: eth0
services:
  - smb
  - msrpc
  - netbios
  - nbns
service_options:
  netbios_name: "WORKSTATION"
  domain: "WORKGROUP"
```

## eBPF Implementation Status

**Fully Implemented (verified with nmap):**
- TTL modification with incremental checksum update
- DF bit manipulation
- IP ID behavior (incremental/random/zero)
- TCP window size modification
- TCP options reordering (template-based for Windows XP, Windows 7+, Linux, macOS styles)
- TCP timestamp removal (replaced with NOPs)
- TCP window scale (present or removed based on profile)
- SACK permitted option handling

**Template-Based Options Patterns:**
- **Windows XP style**: MSS, NOP, NOP, SACK (no window scale, no timestamps)
- **Windows 7+ style**: MSS, NOP, WS, NOP, NOP, SACK (window scale present, no timestamps)
- **Linux style**: MSS, SACK, [TS placeholder], NOP, WS (timestamps present)
- **macOS/default**: MSS, NOP, WS, SACK, NOPs

**Not yet implemented:**
- TCP timestamp value modification (currently just removed)
- ECN flag handling (CWR/ECE response behavior)
- ICMP quote handling (quote size, DF preservation, TTL in quoted header)
- UDP closed port ICMP response behavior
- ACK sequence number in RST packets

## eBPF Technical Notes

**Checksum Updates:**
- IP checksum: Use `bpf_l3_csum_replace()` with 16-bit word values
- TCP checksum: Use `bpf_l4_csum_replace()` for window and options changes
- Byte order: On little-endian, packet bytes [A][B] load as `(B<<8)|A` for checksum purposes

**Verifier Constraints:**
- Dynamic array indexing causes "pointer prohibited" errors
- Loops must be unrollable with fixed bounds
- Packet pointers invalidated after `bpf_skb_store_bytes()` - read all values first
- TCP options modification limited to packets with exactly 20 bytes of options (SYN/SYN-ACK) to avoid corrupting TCP payload on data packets

**Loopback Limitation:**
- TC egress hook works correctly on real interfaces
- On loopback, kernel-generated response packets may bypass TC egress for some packet types
- Always test on real interface for accurate results

## Profile Format

```yaml
name: "Windows 11"
family: windows
version: "10.0.22000"

stack:
  # IP Layer
  ttl: 128
  df_bit: true
  ip_id_behavior: incremental  # incremental, random, zero

  # TCP Layer
  window_size: 8192
  window_scale: 8
  mss: 1460
  tcp_timestamps: false
  sack_permitted: true
  tcp_options_order: [mss, nop, window_scale, nop, nop, sack_permitted]

  # TCP Quirks
  ecn_support: true
  ack_in_rst: zero             # zero, echoed, incremented
  window_in_rst: 0

  # ICMP
  icmp_quote_size: 8
  icmp_df_in_quote: true
  icmp_ttl_in_quote: 128
  icmp_rate_limit: false

  # UDP
  udp_closed_port_response: true
```

## Service Emulation Details

### Probe Matching
Signatures use hex patterns with:
- `\xNN` hex escapes: `\x00\xfeSMB` matches SMB2 magic
- `.` single-byte wildcard: `\x00...\xfeSMB` matches NetBIOS header + SMB2
- Length constraints: `min_length`, `max_length`
- Offset: start matching at byte N

### Rewrite Rules
Dynamic field replacement in responses:
- `timestamp` — Windows FILETIME (100ns since 1601)
- `timestamp_unix` — Unix epoch (4 or 8 bytes)
- `guid` — Random 16-byte GUID with proper version/variant bits
- `random` — Random bytes
- `echo` — Copy bytes from probe at same offset
- `seq`, `ip`, `port` — Placeholders for future implementation

### SMB Emulation
Captured Windows 11 SMB2 negotiate responses (14+ probe/response pairs):
- Timestamps updated to current time (Windows FILETIME format)
- GUIDs regenerated per connection
- Supports both SMB1 and SMB2 negotiate probes
- SPNEGO/NTLM auth blobs preserved from captures

## Testing Notes

**nmap OS Detection:**
- Requires at least 1 open + 1 closed port for reliable fingerprinting
- Use real interface (not loopback) for accurate TC egress testing
- Example: `sudo nmap -O -sV -p 445,8080,8081 <target-ip>`

**Verified Working (nmap fingerprint results):**
- `T=80` → TTL 128 (Windows)
- `WIN(W1=2000)` → Window 8192 (Windows 11)
- `OPS(O1=M5B4NW8NNSNNNNNNNN)` → MSS, NOP, WS(8), NOP, NOP, SACK
- `TS=U` → Timestamps unsupported/removed
- `DF=Y` → DF bit set
- SMB service responding with proper NetBIOS/SMB2 headers

**Combined Testing:**
```bash
# Terminal 1: Apply stack fingerprint
sudo ./build/mimic apply "Windows 11" -i eth0

# Terminal 2: Start SMB emulation
sudo ./build/mimic serve --services smb

# Terminal 3: Scan from another machine
sudo nmap -O -sV -p 445,8080,8081 <target-ip>
```

## Capture Workflow

```bash
# Capture from live interface on target Windows system
sudo mimic capture live -i eth0 --server-ip 192.168.1.100 --service smb --os "Windows 11"

# Or process existing pcap
mimic capture pcap capture.pcap --server-ip 192.168.1.100 --service smb --os "Windows 11"
```

## Available Captures

**Location:** `captures/`

| File | Description |
|------|-------------|
| `Win11-DefaultPorts-NoFirewall.pcapng` | Windows 11 with firewall OFF, ports 135/445 open |
| `Win11-DefaultPorts-FirewallON.pcapng` | Windows 11 with firewall ON, all ports filtered |
| `win11_nmap` | nmap scan results showing detected services |
| `win11_smb/smb_win11.pcapng` | SMB-specific captures with negotiate responses |
| `win11_smb/scan[1-3].txt` | nmap SMB script output showing capabilities |

**Windows 11 Default Ports (Firewall OFF):**
- Port 135 (MSRPC) - Open, needs service template
- Port 445 (SMB) - Open, template exists

## Dependencies

- Go 1.25+
- clang (for eBPF compilation)
- libbpf headers (`/usr/include/bpf`)
- libpcap-dev (for capture functionality)
- Root privileges for eBPF loading and low port binding

## Key Libraries

- `github.com/cilium/ebpf` — eBPF program loading and map management
- `github.com/google/gopacket` — Packet capture and parsing
- `github.com/vishvananda/netlink` — TC qdisc/filter attachment
- `github.com/spf13/cobra` — CLI framework

## Implementation Gaps (Tactical Priority)

Core stack fingerprinting and service emulation are largely complete. Remaining
work is profile validation depth and a few structural gaps.

**eBPF / stack — remaining edge cases:**
1. **XP/Server 2003 T00 timestamp** — TS option present but TSval=0; distinct from T11
   and from timestamps-off. Profiles exist but won't fingerprint correctly without a
   separate backend code path.
2. **IPv6 stack fingerprinting** — nmap has a separate IPv6 OS engine; not addressed.
3. **DHCP option fingerprinting** — Linux DHCP clients emit a different option-55
   parameter request list than Windows. NAC (Cisco ISE, PacketFence, Fingerbank)
   fingerprints at L2/DHCP time, before any TCP scan — Mimic "Windows" would still
   read as Linux there. Fixable config-side: dhcpcd/systemd-networkd option-55 ordering.

**Profile validation — remaining:**
- Win7 / Win8 / Server 2008 R2 / Server 2012 R2: **EXACT** (eBPF, 2026-06-29 commit `cfe0280`).
  Key fix: ts_slow=1 (100Hz TS → TS=7) via loader ordering fix + new TsSlow field.
  Server2012R2 also needed explicit_congestion: echo (CC=Y).
- Vista / Win8.1 / Server 2008 / Server 2012: profile corrected from nmap-os-db;
  no real VM captures; no Proxmox templates.
- XP SP2/SP3 / Server 2003: T00 behavior unimplemented; profiles exist.
- Linux distros without real VM: Alpine, Gentoo, Mint, Manjaro, openSUSE, Slackware,
  AlmaLinux, CentOS Stream. All profile-only, grounded in the same 5.x/6.x nmap band.
- Amazon Linux 2023, Parrot OS 7: VM templates exist (9309, 9342) but no profiles.

**Services — remaining:**
- DHCP option-55 spoofing (see above)
- LDAP (389), DNS (53), Kerberos (88), NFS (2049) — no templates
- POP3/IMAP — no templates
- SNMP full walk (only system MIB currently; full ifTable = 233 exchanges)
- macOS-specific: AFP/netatalk, Bonjour/mDNS (UDP 5353), Time Machine
- Service hot-reload without restart

**Done (was "future"):**
- **Windows port** — WinDivert + WFP hard-permit, Npcap-free binary. 6/6 Windows
  editions EXACT (Win10/11, Server 2016–2025). See MEMORY.md checkpoints.
- **HiFi NDIS driver** — reaches TI=Z for Linux personas on Windows host (EXACT 7/7).
- **Linux eBPF EXACT** — 7/7 Linux profiles EXACT on Linux host. `Linux 4.15-5.19`
  no submit prompt. 7/7 Linux + 6/6 Windows + 3/3 macOS all EXACT on Linux eBPF host.
- **macOS personas** — Sequoia, Tahoe, Sonoma EXACT (`Apple macOS 10.13-10.15`).
- **Service honeypots** — SSH (shell+SFTP), SMB (3.1.1 signing, SAMR/LSARPC, file
  download), RDP (CredSSP/NTLM Type2), MSRPC EPM (138-endpoint map, dynamic ports),
  FTP, HTTP/HTTPS (per-distro nginx/Apache, dual-path TLS for JARM+real clients).
- **Capture automation** — `mimic capture pcap` → manifest + response templates.
- **Interactive honeypot mode** — SSH/SMB/RDP with credential-leak loop; security
  event logging; RBAC-gated control plane; Windows tray UI.
- **Legacy Windows captures + EXACT** (2026-06-29) — Win7 SP1 (9007), Win8 Pro N (9008),
  Server 2008 R2 SP1 (9108), Server 2012 R2 (9112) real VM captures + templatized.
  Profile era-wide audit: tcp_timestamps, window_scale, explicit_congestion fixed
  across Vista through Server 2012 R2 based on nmap-os-db + real captures.
  All four profiles now EXACT on eBPF (commit `cfe0280`): TS=7 (100Hz via ts_slow),
  correct CC per band (Win7/Win8/2008R2=CC=N, Server2012R2=CC=Y).

**Future:**
- EXACT-chase for remaining legacy Windows (Vista, Win8.1, Server2008, Server2003, XP) —
  no real VM captures; profile-only (nmap-os-db grounded). T00 (XP/Server2003) requires
  a separate eBPF code path (TS option present, TSval=0).
- XP/Server 2003 T00 timestamp implementation.
- DHCP option-55 spoofing (config-side; no kernel work required).
- macOS as a HOST platform (running Mimic on macOS itself) — KVM/OpenCore instability;
  no implementation path yet.
- Profile auto-detection from pcap.
- Amazon Linux 2023, Parrot OS 7 profiles.
