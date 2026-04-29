# Mimic Project Memory

## Last Session: 2026-02-18

### Current Status: Functional with Known Limitations

**Working:**
- eBPF stack fingerprinting (TTL, DF, Window, IP ID, TCP options)
- Service emulation: SMB, MSRPC, NetBIOS, NBNS, RDP, SSH, HTTP, WinRM
- Windows 11 profile produces Windows-like fingerprint
- nmap identifies services as "Microsoft Windows" with `Service Info: OS: Windows`

**TCP/IP Fingerprint Achieved:**
```
TTL: 128 (T=80)           ✓ Windows
Window: 65535 (W=FFFF)    ✓ Windows 11
DF bit: Yes               ✓ Windows
IP ID: Incremental        ✓ Windows
TCP Options: MSS,NOP,WS8,NOP,NOP,SACK  ✓ Windows pattern
```

**Known Limitation - Timestamps:**
- Real Windows 11: `TS=A` (timestamps active)
- Mimic: `TS=U` (timestamps unsupported/removed)
- nmap says "No OS matches" because exact combination not in database
- Services still correctly identified as Windows

### Why Timestamps Are Hard

TCP timestamps require per-connection state:
1. **TSval**: Our monotonic counter (easy)
2. **TSecr**: Must echo peer's TSval from their last packet (hard)

Requires:
- BPF map keyed by 4-tuple (src_ip, src_port, dst_ip, dst_port)
- Ingress hook to capture peer's TSval
- Egress hook to set our TSval and echo TSecr
- State cleanup on connection close

Attempted implementation broke connectivity - reverted to safe version.

### Service Templates Created This Session

From HMDXIN (Windows 11) captures on 2026-02-18:

| Service | Port | Response Files |
|---------|------|----------------|
| SSH | 22 | ssh_banner.bin (OpenSSH_for_Windows_9.5) |
| HTTP | 80 | iis_200_full.bin, iis_200_headers.bin, iis_404_not_found.bin |
| WinRM | 5985 | winrm_404_not_found.bin, winrm_405_method_not_allowed.bin |

Captures stored in: `captures/hmdxin-services-20260218-084543/`

### Commands to Resume Testing

```bash
# Build
make build

# Run with Windows 11 profile
sudo ./build/mimic run -i enp73s0f1 --profile "Windows 11" --services smb,msrpc,netbios,rdp

# Test from remote machine
nmap -O --osscan-guess -p 135,139,445,3389,8081 <target-ip>
nmap -A -p 135,139,445,3389 <target-ip>

# Cleanup TC if needed
sudo tc filter del dev enp73s0f1 egress 2>/dev/null
sudo tc qdisc del dev enp73s0f1 clsact 2>/dev/null
```

### Next Steps (Priority Order)

1. **Timestamp Implementation** - Add per-connection state tracking:
   - Create BPF_MAP_TYPE_LRU_HASH for connection state
   - Hook TC ingress to capture incoming TSval
   - Modify egress to echo TSecr correctly
   - This would change TS=U to TS=A and likely enable OS matching

2. **T2/T3 Probes** - nmap sends unusual TCP flag combinations:
   - T2: SYN to closed port
   - T3: Other TCP probes
   - Real Windows responds (R=Y), we don't (R=N)
   - Lower priority than timestamps

3. **Service Expansion** - Add more captured responses:
   - LLMNR (UDP 5355) - has capture data
   - More SMB script responses (smb-os-discovery, etc.)

4. **HMDXIN Cleanup** - Run revert script when done:
   ```bash
   ssh C2xorC4@hmdxin.blackic.systems -i ~/.ssh/mcp-binja \
     "powershell -ExecutionPolicy Bypass -File C:\Users\C2xorC4\hmdxin-revert-services.ps1"
   ```

### Files Modified This Session

- `profiles/windows/11.yaml` - Updated window_size to 65535
- `internal/ebpf/fingerprint.c` - Added TODO comments for timestamp handling
- `services/ssh/manifest.yaml` - New from captures
- `services/http/manifest.yaml` - Updated with IIS responses
- `services/winrm/manifest.yaml` - Updated with HTTPAPI responses
- `services/*/responses/*.bin` - New binary response files
