# Phase 0 — mimic-hifi network-break root cause CONFIRMED (2026-06-26)

Live A/B on a fresh SeaBIOS Server-2016 clone (proxmox 9523, 10.0.255.102), current
(buggy) signed driver installed + armed, Ubuntu persona, scanned/transferred to Kali
(10.0.254.70). Driver control + tests driven OUT-OF-BAND via the QEMU guest agent
(`ga.py`) so the connectivity break couldn't strand the test.

## A/B result (outbound bulk-TCP blast, VM -> Kali:9000 sink)

| Condition | Outbound TCP |
|---|---|
| offload ON, driver NOT armed (baseline) | 300 MB / 2.7 s = 109 MB/s — OK |
| offload ON, driver ARMED | CONNECT_FAIL — SYN never completes (total break) |
| offload OFF (Disable-NetAdapterLso + ChecksumOffload), driver ARMED | 218 MB / 20 s — OK |

Arming breaks outbound TCP **only with NIC TX offload on**. Even a bare SYN (never LSO)
fails ⇒ the **IP-checksum-offload** interaction is the dominant culprit.

## Byte-level proof (tcpdump on Kali, VM outbound SYN, offload ON + armed)

```
IP (... ttl 64, id 0, ... length 52, bad cksum ffff (->2915)!)
    10.0.255.102.49721 > 10.0.254.70.9000: Flags [SEW], cksum 0xda7b (correct) ...
```

- `id 0` → the driver's IP-ID rewrite WORKS (TI=Z achieved).
- `bad cksum ffff` (should be `0x2915`) → IP **header** checksum corrupt; TCP checksum fine.

## Mechanism

NIC has IP-checksum-offload ON (`Get-NetAdapterChecksumOffload` = RxTxEnabled; LSO
V1IPv4 = True). The driver rewrites IP-ID, **recomputes the IP header checksum, AND
leaves the IP-checksum-offload request flag set**. The virtio NIC then re-checksums on
top of the driver's value → one's-complement double-add wraps to `0xffff` → every
outbound IP packet ships a bad header checksum → the receiver drops at L3 → connect and
bulk both fail. Single-packet nmap probes that the *host stack* answers can still match
Linux because of TI=Z, but any flow the VM originates dies.

## Fix (Phase 1)

`FilterSendNetBufferLists` / `MimicHiFi_RewriteIpId` must become offload-aware:
- If `NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo).Transmit.IpHeaderChecksum`
  is set → rewrite IP-ID and **do NOT compute** the checksum (leave the stack's 0
  placeholder; the NIC fills it over the modified header).
- Else → rewrite IP-ID and recompute (current behavior; correct for non-offloaded /
  WinDivert-reinjected packets).
- Skip LSO NBLs (`TcpLargeSendNetBufferListInfo` != 0) entirely.

VM 9523 kept warm (testsigning on, old LWF installed, mimic stopped) for re-validation.

---

## Phase 1 FIX — built, signed, deployed, VALIDATED ON-WIRE (2026-06-26)

Fix (offload/LSO-aware send path): `driver/mimichifi/{mimichifi.h,filter.c,filter.h}`.
- `MimicHiFi_RewriteIpId` gained `recomputeChecksum`: when IP-checksum offload is
  requested it changes only the IP-ID and leaves the checksum to the NIC (no double-add).
- `FilterSendNetBufferLists`: reads `TcpIpChecksumNetBufferListInfo` (recompute only when
  NOT offloaded), skips LSO NBLs (`TcpLargeSendNetBufferListInfo`), atomic ICMP id
  (`InterlockedIncrement16`), VLAN bound 22->38.
- Off-target unit test `driver/mimichifi/test/rewrite_test.c` — 15/15 pass.
- Built via EWDK (E:), re-signed .sys+.cat with the VM-trusted `Mimic HiFi Test` cert,
  netcfg-reinstalled on clone 9523.

Same A/B that broke before, now with the FIXED driver:

| Condition | Before fix | After fix |
|---|---|---|
| armed, offload ON — bulk blast | CONNECT_FAIL | **213 MB / 20 s — OK** |
| armed, offload ON — nmap -O | (broke WinRM) | **`OS details: Linux 4.15 - 5.19`** |
| armed, offload ON — VM outbound SYN on wire | `id 0`, `bad cksum ffff` | **`id 0`, `cksum correct`** |

Net: network stability restored AND TI=Z deception preserved, simultaneously, with NIC
offload on (the real-world default). Root cause closed.

---

## Phase 2 — connectivity safeguard (auto-disarm) — VALIDATED (2026-06-26)

New `internal/stack/connmon_windows.go` + backend hooks. While the hifi driver is armed,
mimic ICMP-pings the interface gateway (or `high_fidelity_canary`) every 5s; 3 consecutive
failures (~15s sustained) → auto-disarm to WinDivert, and it does NOT re-arm until restart.
Probe rides the mutated egress path (native IcmpSendEcho), so it measures what a real peer sees.

Operator policy (per the security tradeoff): `stack.high_fidelity_watchdog` (*bool, default ON):
- ON  → prioritize CONNECTIVITY (a driver failure can't strand the host).
- OFF → prioritize DECEPTION (driver holds regardless) AND denies an attacker an
  induced-degradation oracle (no trip to force the true OS to show).
Hardening: sustained-failure threshold (not a blip) + no auto-re-arm (no flap to oscillate).

On-VM validation (clone 9523, fixed driver):
| Test | Config | Result |
|---|---|---|
| A | watchdog default ON, healthy gateway | `watchdog active probe=10.0.240.1`; NO false-trip over 23s |
| B | watchdog ON, blackhole canary | `probe failed 1→2→AUTO-DISARMED` at ~15s; no re-arm |
| C | `high_fidelity_watchdog: false`, blackhole canary | `watchdog DISABLED`; holds, never disarms |
| wire | post-trip outbound IP-ID | **0 → non-zero** (7546,7548,…) — driver truly disarmed at the wire |

`go build/vet/test ./...` green on Windows. eBPF + WinDivert-standard paths untouched
(safeguard only runs when hifi is armed).
