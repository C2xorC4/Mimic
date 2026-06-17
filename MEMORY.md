# Mimic Project Memory

> **Depth lives in LittleJohnnyMnemonic (LJM), not here.** This file is the
> portable status snapshot that travels with the repo. Byte-level fix
> rationale, protocol-bug write-ups, and session-by-session history are in the
> LJM vault (`Memory/Project/mimic`, `Memory/Knowledge/net_*`, daydream buffer).
> On this host, recall those before re-deriving — don't duplicate them here.

## Current Status (as of 2026-06-06)

- **nmap `-O` → exact Windows 10/11 DB match** (no `-p` needed). Full
  SEQ/OPS/WIN/ECN/T1–T7/U1/IE vector matches Windows 11 21H2. Detailed vectors
  promoted to LJM Knowledge (`net_os_fingerprint_deception_vectors`).
- **TLS:** JARM + JA3S exact match vs Windows IIS Schannel (static ServerHello;
  handshake does not complete — no key material). JA4S unvalidated.
- **SMB honeypot (`smb_honeypot` service):** full share enumeration to nmap
  (`smb-enum-shares`), netexec, and direct impacket — guest/null **and** seeded
  fake-credential logins (NTLMv2-verified). SMBv1 + SMBv2/3.1.1 negotiation.
- **Service breadth (Phase 4, 2026-06-10):** SSH/SMTP/VNC/Telnet/Redis/HTTP per-OS
  + MySQL/MSSQL (capture-driven), all `nmap -sV`-hardened. See LJM
  `2026-06-10_mimic-phase4-service-breadth-complete` + `_honeypot-nmap-sv-hardening`.
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
    resume state in LJM buffer `2026-06-11_mimic-proxmox-template-track-resume-state`.
- **systemd daemon lifecycle (2026-06-15, BUILT + validated on argus, UNCOMMITTED):**
  `mimic stop [--purge]` / `install` / `uninstall [--purge]` + clean-on-start.
  Stateless content-diff TC teardown (`internal/ebpf/teardown.go`): removes only
  `deceiver_fingerprint*` filters by BPF name; `--purge` removes the clsact qdisc
  ONLY if no foreign filters remain (co-tenant-safe). nft tables (mimic_reject/
  mimic_block) safe by name-isolation. systemd unit: ExecStart=run, ExecStopPost=stop
  (crash safety net), Restart=on-failure, bounded caps. Validated: restart clean (no
  dup filter), nmap -O through daemon = Win10|11, co-tenancy keeps qdisc. Files:
  `cmd/mimic/{stop.go,install.go,run.go,assets/*}`, `internal/ebpf/teardown.go`.
- **Capture→template pipeline (Track 1, 2026-06-16, IN PROGRESS):** `mimic capture
  pcap <f> --server-ip <ip> --service <svc> --ports <p> --os <name>` -> manifest.yaml
  + response .bin + rewrite rules. **FIX (`internal/capture/session.go`, UNCOMMITTED):**
  ExtractExchanges now dedups duplicate packets by PAYLOAD CONTENT per direction —
  pktmon records each packet N× (per NIC/WFP/Npcap/QoS component) which was
  concatenating probes/responses N× (inflating lengths so signatures never matched a
  real probe). Content-key works for TCP+UDP (UDP has no seq). Batch-generated on
  argus `/tmp/gen/<os>/<svc>` from the 34 per-service pcaps (NOT pulled to repo):
  smb 8-9, rdp 12-15, nbns 3-4 = clean; **snmp ~236 (full MIB walk, verbose), http
  1070+ (http-enum 404 noise), llmnr skipped (python-probe sidecar has no `(IP)` +
  multicast: probe dest=224.0.0.252 not server, so 0 exchanges).**
  - **ARCHITECTURE (load-bearing):** `services/<name>/` = stateless template-replay
    (svcMgr.LoadService); `smb_honeypot`/`ftp_honeypot` = interactive hand-coded
    (`internal/honeypot/*`, special-cased in run.go). For SMB the **honeypot is the
    serving path** (does multi-step SESSION_SETUP/TREE_CONNECT/enum/auth that replay
    can't); captured `services/smb` template = REFERENCE/validation only. Editing
    captured templates can NOT regress the honeypot (separate code+data+selector).

## Track-1 refinement queue (priority order, handle after restart)
1. **RDP & SMB enhancements.** RDP: semantic rewrite-typing on `services/rdp` replay
   template (timestamp/NLA fields → live, not generic `random`). SMB: NOT the replay
   template (honeypot is primary) — instead use the captured authentic SMB2 negotiate
   responses to fix the **honeypot build-number gap** (MEMORY.md gap #2; honeypot
   hardcodes 19041) so build# derives from the profile per-OS.
2. **http re-capture de-noise.** Re-capture IIS WITHOUT `http-enum` (just
   http-headers,http-title,http-server-header) -> ~handful of real templates instead
   of 1070 404s. Capture harness `infra/proxmox/capture.ps1` ready.
3. **llmnr.** Fix server-IP extraction (sidecar is python-probe output, parse
   `target=<ip>`), AND handle multicast in the processor (response-without-direct-
   probe / dest=multicast-group) so the LLMNR response template extracts.
4. **snmp (last).** 236 per-OID templates valid for OID-keyed replay but heavy;
   optional collapse/curate.

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
- **impacket/netexec compatibility (2026-06-05/06):** see LJM Knowledge
  `net_impacket_smb3_processcontextlist_bug` and
  `net_smb_honeypot_signing_encryption_constraint` for the full reasoning. Net:
  send **one** NegotiateContext (PreauthIntegrity only — no Encryption, since a
  keyless honeypot can't decrypt TRANSFORM_HEADERs); return the guest session
  flag so the client zeroes the session key and skips 3.1.1 signing.
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

## Known Gaps / Next Priority

1. **smbmap parity** — smbmap 1.10.4 reports `0 sessions` at 3.1.1 (its own
   signing handling). Full parity needs real SMB2 3.1.1 signing (SP800-108 KDF
   over SessionKey + running preauth SHA-512). Large lift, deferred.
2. **Build-number consistency** — netexec prints `19041` from the hardcoded NTLM
   CHALLENGE Version field, not the profile (Win11=22000). Derive from profile.
3. **JA4S validation** — JARM/JA3S validated; JA4S (FoxIO; Suricata 8.0 / Zeek)
   is the current standard and unmeasured. Byte-faithful replay likely passes;
   confirm with FoxIO ja4 tooling or Suricata 8.0.
4. **Cross-service credential leak** — plant the seeded creds in HTTP/maze/config
   artifacts so the reuse loop actually closes (SMB side already accepts them).
5. **eBPF host-telemetry stealth** — BPF(SCHED_CLS) load is auditable; the
   Linux-host/Windows-fingerprint contradiction is the strongest detection
   surface. Possible mitigation: `prog_name` + process-ancestry spoofing (see
   LJM daydream `mimic-ebpf-stealth-gap`). Reframes a "hard limit" as solvable.
6. **TLS handshake completion** — per-conn TLS proxy for 443.
7. **Service expansion** — MSRPC/135 real endpoint-mapper capture, `--services
   all`, SSH/HTTP banners, deeper SMB scripts.

## Operational

### argus-lab (test target)
- IP `10.0.254.45`, iface `ens18`, SSH key `~/.ssh/argus_lab` (port 2222), Go
  1.25.6 at `/usr/local/go/bin`, repo at `~/mimic/`.
- Boot persistence: `/etc/modules-load.d/mimic.conf` loads `nft_reject` +
  `nft_reject_inet`.

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
