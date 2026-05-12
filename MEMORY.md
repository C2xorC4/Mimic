# Mimic Project Memory

## Last Session: 2026-05-12

### Current Status: 98% Windows 10/11 nmap OS Match — W6 Fixed, HTTPS/JA3S Live

**nmap -O result:**
```
Aggressive OS guesses: Microsoft Windows 10 1703 or Windows 11 21H2 (98%),
                       Microsoft Windows 11 21H2 (98%)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Full fingerprint match:**
```
SEQ: TI=I, CI=I, II=I, SS=S, TS=A     ✓ all correct
OPS: O1=M5B4NW8ST11 ... O3=M5B4NW8NNT11 ... O6=M5B4ST11  ✓
WIN: W1-W5=FFFF, W6=FFDC              ✓ FIXED (was FFFF)
ECN: CC=N, O=M5B4NW8NNS              ✓
T1:  F=AS, A=S+                        ✓
T2:  R=Y, F=AR, S=Z, A=S             ✓
T3:  R=Y, F=AR, S=Z, A=O             ✓
T4:  F=R, A=Z                          A should be O (minor)
T5:  F=AR, A=S+                        ✓
T6:  F=R, A=Z                          A should be O (minor)
T7:  F=AR, A=S+                        ✓
U1:  DF=N                              ✓
IE:  DFI=N, CD=Z                       ✓
```

### What Was Fixed This Session (2026-05-11)

1. **TCP Timestamps** → TS=A
   - Enable `tcp_timestamps: true` in profile
   - Extract TSecr from kernel's layout before overwriting
   - TSval = bpf_ktime_get_ns()/1000000 (1kHz)
   - Write Windows order: MSS+NOP+WS+SACK+TS = 20 bytes

2. **SACK Negotiation** → O3=M5B4NW8NNT11
   - `use_sack = profile->sack_permitted && had_sack`
   - Only reflect SACK when peer's SYN included SACK_PERM

3. **ECN Probe** → O(ECN)=M5B4NW8NNS, CC=N
   - opt_len=12 handler for ECN SYN: Windows-ordered 12-byte options
   - Strip ECE flag from SYN-ACK packets

4. **opt_len=16 probe** → TS=A (not TS=1F)
   - Override TSval in 16-byte options path (no-WS probe)
   - Prevents Linux per-conn tsoffset from leaking through

5. **IP ID sharing** → SS=S
   - Apply shared counter to ALL protocols (TCP + ICMP)
   - Previously only applied when old_id==0 (TCP only)

6. **RST fix** → T5/T7 F=AR
   - Remove incorrect ACK flag stripping from RST handler
   - Linux already handles T4/T6 (no ACK) correctly without it

7. **ICMP fixes** → IE DFI=N, CD=Z; U1 DF=N
   - Add ICMP section that clears DF bit on all ICMP packets
   - Force ICMP echo reply code=0 (was echoing probe code)

8. **T2/T3 probes** → R=Y (both now matching exactly)
   - ClosedPortManager rewritten to use native `nft` (was iptables-nft)
   - ProbeResponseManager adds nftables rules for NULL-flag and
     SYN+FIN+PSH+URG TCP packets → RST+ACK responses
   - nft_reject_inet module provides TCP reset capability

### What Was Fixed This Session (2026-05-12)

1. **W6=FFDC** — In opt_len==16 block: if window_size==0xFFFF, override to 0xFFDC for
   Windows probe-6 match (no WS negotiated path). Verified in nmap output.

2. **HTTPS/JA3S service** — Captured Windows Schannel TLS 1.3 ServerHello from HMDXIN IIS,
   created `services/https/manifest.yaml` + `services/https/responses/iis_server_hello.bin`
   (127 bytes). JA3S: `6c2811f7ba8e88604ea41a2bf9fa5ad7` ("772,4866,43-51").
   Port 443 now responds to TLS ClientHello with Windows Schannel fingerprint.
   Note: Handshake won't complete (static response, no key material) but JA3S scanners
   work at packet level — fingerprint is correct.

3. **Boot persistence** — `/etc/modules-load.d/mimic.conf` on argus-lab:
   `nft_reject` and `nft_reject_inet` load at boot automatically.

4. **T4/T6 A=Z → A=O** — Per-connection seq_cache BPF map (LRU_HASH):
   - Ingress hook `fingerprint_ingress` stores {saddr,sport,dport} → {seq,ack_num}
   - Egress RST handler looks up probe's ACK value and sets RST ack_seq = probe's ACK
   - A=O confirmed in nmap fingerprint output (crosses final exact DB match threshold)

5. **JARM fingerprint** — Full JARM match with HMDXIN Schannel:
   `2ad2ad00000000022c0000000000000daf8512f1afb4642b76b4dfdb33f354`
   - services/https/responses/tls12_server_hello.bin (99 bytes, c030 TLS 1.2)
   - services/https/responses/tls11_server_hello.bin (105 bytes, c014 TLS 1.1)
   - Probe 1-2 pattern: 78-byte wildcard matching cipher_suites_len=0x008a (ALL 69 ciphers)
     `\x16\x03\x03..\x01...\x03\x03` + 32 wildcards + `\x20` + 32 wildcards + `\x00\x8a`
   - Probe 6 pattern: `\x16\x03\x02` (TLS 1.1 record, uniquely identifies probe 6)
   - Probes 3-5 (HALF/GREASE, different len) and probes 7-10 (0x0301) → no response ✓

6. **T2/T3 global probe response** — Removed port scope from nftables rules.
   Previously scoped to Mimic's service ports; nmap -O (no -p) selects its own
   open port (e.g. SSH:22) for T2/T3, missing the rules → "No exact OS matches".
   Rules now match all TCP ports. `nmap -O 10.0.254.45` returns exact Windows 11
   match unconditionally.

### Known Remaining Gaps

1. **TLS handshake completion** — https service sends static ServerHello
   - Handshake won't complete (no key material, session ID not echoed)
   - JA3S/JARM fingerprint is correct; full TLS would require TLS proxy or per-conn state

### Commands to Resume Testing

```bash
# Build and deploy to argus-lab
cd "D:\Repos\Security\Mimic"
tar czf - . | ssh -i ~/.ssh/argus_lab argus-lab 'cd ~/mimic && tar xzf - && PATH=/usr/local/go/bin:$PATH make build'

# Restart on argus-lab (ensure nft_reject_inet loaded first)
ssh -i ~/.ssh/argus_lab argus-lab '
  sudo modprobe nft_reject nft_reject_inet
  sudo pkill mimic 2>/dev/null
  sudo nft delete table inet mimic_reject 2>/dev/null  
  sudo tc filter del dev ens18 egress 2>/dev/null
  sudo tc qdisc del dev ens18 clsact 2>/dev/null
  sleep 1
  cd ~/mimic
  sudo ./build/mimic run "Windows 11" -i ens18 \
    --services smb,msrpc,netbios,nbns,rdp \
    --closed-ports 80,443,8080 > /tmp/mimic.log 2>&1 &
'

# Test from Windows dev machine  
nmap -O --osscan-guess -p 135,139,445,3389,80 10.0.254.45
nmap -A -p 135,139,445,3389 10.0.254.45
```

### argus-lab Details
- IP: 10.0.254.45
- Interface: ens18
- SSH key: ~/.ssh/argus_lab
- Go: /usr/local/go/bin/go (1.25.6)
- Mimic dir: ~/mimic/

### Files Modified This Session

- `internal/ebpf/fingerprint.c` — major: timestamps, SACK negotiation, ECN,
  ICMP section, RST fix, IP ID sharing, opt_len=12/16 handlers
- `profiles/windows/11.yaml` — tcp_timestamps: true, updated options order
- `internal/services/closed.go` — rewrote to use native nftables; added
  ProbeResponseManager for T2/T3 probe responses
- `cmd/mimic/run.go` — wire ProbeResponseManager, serviceOpenPorts() helper

### Next Priority

1. **TLS full handshake**: Implement TLS proxy or per-conn key exchange for port 443
   (needed for deeper TLS scanner compatibility beyond JA3S/JARM)
2. **Deeper service honeypot**: SMB/RDP sessions that absorb scanner time (state machine
   responding to enumeration scripts with plausible but endless data)
