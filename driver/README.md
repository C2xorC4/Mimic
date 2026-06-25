# mimic-hifi — high-fidelity IP-ID corrector (NDIS Lightweight Filter)

Opt-in Windows kernel driver that lets a **Linux persona** emit a literal **IP-ID 0**
on the wire (nmap `TI=Z` / `CI=Z`) — the one indicator WinDivert structurally cannot
produce, because the Windows IP transmit path re-stamps a 0 Identification *below*
WinDivert's network-layer injection point.

## Why an NDIS LWF (and not WFP)

The re-stamp happens in `tcpip.sys`'s IP send path. WinDivert injects at the WFP
network layer, and a **WFP callout operates at/above that layer too** — so it can't
reach below the re-stamp. The only layer **guaranteed below** the ID assignment is the
**NDIS miniport edge**. An NDIS Lightweight Filter sees the final packet in
`FilterSendNetBufferLists` right before the NIC and rewrites it there.

**Mechanism proven (Phase 0, 2026-06-25):** Npcap (itself an NDIS LWF) emitting
`IP(id=0)` frames was captured downstream with `id 0` intact (16/16) — an NDIS-layer
send preserves IP-ID 0; the proxmox virtio NIC does not offload/re-stamp the field.

## Architecture (thin corrector under WinDivert)

WinDivert keeps doing **all** mutation (TTL/window/options/ECN, and it still writes
IP-ID 0). This driver only fixes the **final** IP-ID below the re-stamp, while **armed**:

- Outbound **IPv4 TCP** → IP-ID `0`  (nmap TI/CI=Z)
- Outbound **IPv4 ICMP** → IP-ID = incrementing counter  (nmap II=I)
- Recompute the IPv4 header checksum.
- Everything else passes through untouched. **No per-flow state** (per-protocol only) —
  keeps the kernel component minimal, auditable, and easy to sign.

**Fail-safe:** the driver defaults to **pass-through**; it mutates only while armed, and
**auto-disarms when the control handle closes** (mimic exit / crash). A crash never
leaves host traffic mangled.

## Control channel (matches the shipped Go client)

`internal/stack/hifi_windows.go` (`hifiCorrector`) opens `\\.\MimicHiFi` and drives:

| IOCTL | Code | Payload |
|-------|------|---------|
| `IOCTL_MIMICHIFI_ARM`    | `0x0012A000` | 1 byte mode (`1` = Linux persona) |
| `IOCTL_MIMICHIFI_DISARM` | `0x0012A004` | none |

`CTL_CODE(FILE_DEVICE_NETWORK=0x12, fn, METHOD_BUFFERED, FILE_WRITE_ACCESS)`,
fn `0x800` (arm) / `0x801` (disarm). Defined once in `mimichifi/mimichifi.h`.

## Layout

```
driver/
  mimichifi/
    mimichifi.h        # IOCTL contract + the pure-C IP-ID rewrite core (done)
    mimichifi.inf      # NDIS LWF INF (modifying filter)              (draft)
    filter.c           # LWF: DriverEntry/Attach/Detach/SendNBL       (TODO: build loop)
    device.c           # control device + IRP_MJ_DEVICE_CONTROL       (TODO: build loop)
    mimichifi.vcxproj  # VS driver project (WindowsDriver targets)     (TODO: build loop)
  scripts/
    sign-test.ps1      # self-signed cert + signtool + testsigning
    install.ps1        # netcfg install + start
    uninstall.ps1      # netcfg uninstall
```

`filter.c` / `device.c` / `mimichifi.vcxproj` are completed against the real WDK
headers once the toolchain is present (below) — base the NDIS boilerplate on Microsoft's
`Windows-driver-samples/network/ndis/filter` (ndislwf) sample and graft in
`MimicHiFi_RewriteIpId()` (mimichifi.h) inside `FilterSendNetBufferLists`, plus the
control device from `device.c`.

## Toolchain (this host)

- ✅ VS 2022 Community + C++ x64 toolset (14.43/14.44) + Spectre libs + Windows SDK 26100.
- ⏳ **WDK** — the missing piece. Either the **EWDK** (self-contained;
  `LaunchBuildEnv.cmd` → `msbuild`) or the standalone **WDK + WDK.vsix** for VS.

## Build → sign → install → validate

```powershell
# build (VS+WDK)
msbuild driver\mimichifi\mimichifi.vcxproj /p:Configuration=Release /p:Platform=x64
#   or in an EWDK build env: LaunchBuildEnv.cmd then the same msbuild line

driver\scripts\sign-test.ps1     # self-sign the .sys/.cat + enable test-signing (reboot)
driver\scripts\install.ps1       # netcfg -l mimichifi.inf -c s -i ms_mimichifi
# run mimic with a Linux persona + high_fidelity: true  -> backend arms the driver
# scan from Kali: nmap -Pn -O --osscan-guess -p 80,9999 <vm>
#   SUCCESS = SEQ shows TI=Z%CI=Z and "OS details: Linux 4.15 - 5.19" (exact)
driver\scripts\uninstall.ps1
```

**Lab signing only.** Test-signing weakens Secure Boot/HVCI — the deliberate
"intrusive opt-in" cost. Production = Microsoft attestation signing (future).

## Status — ✅ VALIDATED EXACT (2026-06-25)

Phase 0 (mechanism) ✅ GO · Phase 1 (Go seam, on `main`) ✅ · Phase 2 (this driver) ✅
**builds, loads, arms, and delivers `TI=Z` on the wire.**

End-to-end proof on a fresh **SeaBIOS** Server-2016 VM (no Secure Boot, so a test-signed
driver loads): self-signed → trusted → `testsigning` + reboot → `netcfg` install →
`sc query mimichifi` = RUNNING (no BSOD) → mimic (Ubuntu persona + `high_fidelity: true`)
armed `\\.\MimicHiFi` → **nmap from Kali: `OS details: Linux 4.15 - 5.19` EXACT** (was 95%
aggressive guess). The opt-in tier reaches WinDivert-Linux exact = parity with eBPF.

Build (EWDK 10.0.28000): mount the EWDK ISO, then
`cmd /c "call E:\BuildEnv\SetupBuildEnv.cmd & msbuild mimichifi.vcxproj /p:Platform=x64"`.
The trailing `DrvCat` MSBuild task errors on a missing `Microsoft.Kits.Logger` assembly
*after* the artifacts are produced — harmless; sign with `scripts\sign-test.ps1`
(embed-sign .sys → inf2cat → sign .cat). Validation harness: `scratchpad/hifi_validate.ps1`.

**Key fix:** rewrite the IP-ID by mapping the MDL in place (`MmGetSystemAddressForMdlSafe`),
NOT `NdisGetDataBuffer` + a scratch copy (which silently no-ops on the non-contiguous send
case → TI stayed =I). See `filter.c` `FilterSendNetBufferLists`.
