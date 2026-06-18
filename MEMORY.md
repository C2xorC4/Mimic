# Mimic Project Memory

> **Depth is split between this file and LittleJohnnyMnemonic (LJM).** This
> `MEMORY.md` is the portable operational snapshot that travels with the repo
> (queue, lab state, validation results, handoff). LJM holds durable project
> context (`Memory/Project/mimic`), byte-level vectors
> (`Memory/Knowledge/net_os_fingerprint_deception_vectors`), and protocol-bug
> write-ups (`net_impacket_*`, `net_smb_*`). Recall LJM before re-deriving;
> don't duplicate Knowledge entries here.

## Current Status (as of 2026-06-06; latest work 2026-06-18)

> **Thin-decoys queue (order 3,2,4,1):** **ALL DONE + VALIDATED** (2026-06-18).
> (#3) WinRM, (#2) MSRPC ept_map, (#4) NetBIOS/139, (#1) RDP/3389 CredSSP.
> RDP live: Kali `nmap --script rdp-ntlm-info` → Product_Version **10.0.20348**
> (Server 2022 profile), NetBIOS/DNS names match `netbios_name`. `os_edition`
> gates 135/139 on workstation vs server. Lab warm on argus; Kali 9511 up.

- **nmap `-O` → exact Windows 10/11 DB match** (no `-p` needed). Full
  SEQ/OPS/WIN/ECN/T1–T7/U1/IE vector matches Windows 11 21H2. Detailed vectors
  promoted to LJM Knowledge (`net_os_fingerprint_deception_vectors`).
- **TLS:** JARM + JA3S exact match vs Windows IIS Schannel (static ServerHello;
  handshake does not complete — no key material). JA4S unvalidated.
- **SMB honeypot (`smb_honeypot` service):** full share enumeration to nmap
  (`smb-enum-shares`), netexec, and direct impacket — guest/null **and** seeded
  fake-credential logins (NTLMv2-verified). SMBv1 + SMBv2/3.1.1 negotiation.
- **Service breadth (Phase 4, 2026-06-10):** SSH/SMTP/VNC/Telnet/Redis/HTTP per-OS
  + MySQL/MSSQL (capture-driven), all `nmap -sV`-hardened. Summarized in LJM
  `Memory/Project/mimic` (Phase 4 section).
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
    resume state in LJM `Memory/Project/mimic` (Proxmox capture track section).
- **systemd daemon lifecycle (2026-06-15, committed `9ed9935`, validated on argus):**
  `mimic stop [--purge]` / `install` / `uninstall [--purge]` + clean-on-start.
  Stateless content-diff TC teardown (`internal/ebpf/teardown.go`): removes only
  `deceiver_fingerprint*` filters by BPF name; `--purge` removes the clsact qdisc
  ONLY if no foreign filters remain (co-tenant-safe). nft tables (mimic_reject/
  mimic_block) safe by name-isolation. systemd unit: ExecStart=run, ExecStopPost=stop
  (crash safety net), Restart=on-failure, bounded caps. Validated: restart clean (no
  dup filter), nmap -O through daemon = Win10|11, co-tenancy keeps qdisc. Files:
  `cmd/mimic/{stop.go,install.go,run.go,assets/*}`, `internal/ebpf/teardown.go`.
- **Capture→template pipeline (Track 1, 2026-06-16, COMPLETE 2026-06-18):** `mimic capture
  pcap <f> --server-ip <ip> --service <svc> --ports <p> --os <name>` -> manifest.yaml
  + response .bin + rewrite rules. **FIX (`internal/capture/session.go`, committed `9ed9935`):**
  ExtractExchanges now dedups duplicate packets by PAYLOAD CONTENT per direction —
  pktmon records each packet N× (per NIC/WFP/Npcap/QoS component) which was
  concatenating probes/responses N× (inflating lengths so signatures never matched a
  real probe). Content-key works for TCP+UDP (UDP has no seq). Batch-generated on
  argus `/tmp/gen/<os>/<svc>` from the 34 per-service pcaps (NOT pulled to repo):
  smb 8-9, rdp 12-15, nbns 3-4 = clean; **snmp 236→3** (system MIB curation,
  2026-06-18), **http 1071→6** (http-enum filter), **llmnr 0→1** (multicast +
  sidecar target IP, 2026-06-18). Regen `/tmp/gen` only when promoting artifacts
  into `services/` — not Proxmox VM templates.
  - **ARCHITECTURE (load-bearing):** `services/<name>/` = stateless template-replay
    (svcMgr.LoadService); `smb_honeypot`/`ftp_honeypot`/`rdp` = interactive hand-coded
    (`internal/honeypot/*`, special-cased in run.go). For SMB the **honeypot is the
    serving path** (does multi-step SESSION_SETUP/TREE_CONNECT/enum/auth that replay
    can't); captured `services/smb` template = REFERENCE/validation only. **`rdp` in
    `services:` starts the stateful honeypot** (X.224→TLS→CredSSP), not the template;
    `services/rdp/responses/*.bin` supplies nego + JARM static hello only. Editing
    captured templates can NOT regress the honeypots (separate code+data+selector).

## Track-1 refinement queue (priority order, handle after restart)
1. ✅ **RDP & SMB enhancements — DONE (2026-06-17, live-validated on argus).**
   **SMB:** NTLM CHALLENGE Version field now derives major/minor/build from the
   profile (`Server.osVersionTriple()` parses `cfg.OSVersion`, same source as
   `nativeOSString()`); fallback stays 10.0.19041 when OSVersion unset (tests).
   Closes gap #2. Files: `internal/honeypot/smb/{ntlm.go,server.go,ntlm_test.go}`.
   **Live-validated:** raw SMB2 NEGOTIATE→SESSION_SETUP probe vs the running Win11
   honeypot returns NTLM Version **10.0 build 22000** (was 19041).
   **RDP (`services/rdp/manifest.yaml`, replay path via `serve`):** two fixes.
   (a) TLS ServerHello random typing — it's a TLS **1.3** hello
   (supported_versions→0x0304), so the first-4-bytes `timestamp_unix` typing was
   wrong (no gmt_unix_time in 1.3); changed to full 32-byte `random`. (b) Added
   `legacy_session_id` echo (offset 44, len 32, type `echo`) — a 1.3 server MUST
   echo the client's session_id; the static value was a tell. **Live-validated:**
   ServerHello random[:4] is now per-connection random (not wall-clock), and a
   ClientHello with session_id=0xAB×32 gets that value echoed back (was static
   `ad526b9d…`).
   **KEY FINDING — generated RDP templates NOT integrated (deliberate).** Inspected
   `/tmp/gen/<os>/rdp` on argus: the 1232-byte "ServerHello+Certificate" responses
   are a 127-byte cleartext ServerHello followed by **TLS 1.3 encrypted handshake
   records** (`\x17\x03\x03…` — Certificate/CertVerify/Finished are encrypted under
   handshake keys in 1.3). Those bytes are session-bound to keys we don't have;
   replaying them to a new client is useless AND a tell. The generated set also
   contains 0-byte responses and encrypted app-data records. So the hand-crafted
   127-byte ServerHello is the max useful cleartext — integrating the generated
   templates would be a **regression**, not an upgrade. nmap can't extract an RDP
   cert from TLS 1.3 anyway (encrypted on the wire). RDP item is closed.
2. ✅ **http re-capture de-noise — DONE (2026-06-18).** Capture pipeline now
   filters http-enum path noise in `internal/capture/http_filter.go`: non-root
   GET/HEAD paths dropped; OPTIONS/POST/TRACE/etc. kept. `classifyHTTPProbe`
   buckets surviving probes (`http_get`, `http_options`, …) instead of
   per-path SHA256 hashes. **Validated on argus:** same Win11 IIS pcap
   (`iis_20260612_103947`, 10.0.250.31) **1071→6** manifest probes; clean
   hmdxin pcap **5** probes; unit tests in `http_filter_test.go` +
   `http_capture_test.go`. Re-capture without `http-enum` still recommended for
   smaller pcaps; `infra/proxmox/capture.ps1` drop remains best practice.
3. ✅ **llmnr — DONE (2026-06-18).** Multicast queries to `224.0.0.252:5355`
   attributed to configured server IP; UDP/5355 sessions aggregate by client IP
   (ignore ephemeral port); sidecar `.nmap.txt` `target=<ip>` auto-selected for
   `capture pcap --service llmnr`; manifest protocol infers `udp`. **Validated on
   argus:** Win11 proxmox pcap with wrong `--server-ip` still extracts **1** probe
   (sidecar override 10.0.251.64), was 0 exchanges.
4. ✅ **snmp — DONE (2026-06-18).** Pipeline keeps **system MIB only**
   (`1.3.6.1.2.1.1.*` — sysDescr/sysUpTime/sysName); drops snmp-interfaces
   ifTable GET-NEXT walk (~233/236 exchanges). Live proxmox analysis + nmap
   sidecar: `-sV`/`snmp-sysdescr` need the 3 system OIDs; full walk is
   enumeration noise (http-enum parallel). **Validated:** srv2022 pcap **236→3**
   probes. `snmp-interfaces` deep fidelity deferred (needs stateful handler or
   opt-in full capture).

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
- **impacket/netexec compatibility (2026-06-05/06, signing extended 2026-06-17):**
  see LJM Knowledge `net_impacket_smb3_processcontextlist_bug` and
  `net_smb_honeypot_signing_encryption_constraint`. Net: send **one**
  NegotiateContext (PreauthIntegrity only — no Encryption); guest/null sessions
  use `IS_GUEST` so clients skip signing; **seeded creds get full 3.1.1 signing**
  (`signing.go`, SP800-108 KDF + AES-128-CMAC) and file download works.
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

## OSE-2026-001 red-team exercise — validated impact + gaps (2026-06-17)

Controller ran 6 AI operators (3 Claude / 3 Grok) vs 3 targets. Clean A/B for Mimic:
**same Ubuntu 22.04.5 base image + same backdoored vsftpd 2.3.4**, one bare
(`mimic-lab-linux-bare`, Op-3) vs one Mimic'd (`mimic-lab-linux-mimic`, Op-5). Op-1
hit a *real* Win11 22H2 (22621) box = fidelity reference. Logs in `../MTest/`.

**Impact (Op-3 bare vs Op-5 Mimic):** both rooted via the vsftpd backdoor — Mimic
is a deception/cost layer, NOT a vuln shield (can't patch a real service it doesn't
front). Effect: time-to-root 8m36s → ~23m (~2.7×); open-port surface 1 → 6 (5
decoys); OS attribution flipped to "Windows 11" until shell. SMB honeypot WIN:
svc_backup authenticated + enumerated IPC$/ADMIN$/C$ (cred-leak loop fired). Caveat:
a skilled operator flagged deception indicators *pre-shell* (would burn it in a real
op), and much of the "cost" was a self-inflicted bug (TS incoherence, below).

**Tells / gaps surfaced (canonical tracker; statuses updated as fixed):**
> Status legend: ⏳ open · 🔨 code-complete, pending argus validation · ✅ validated.
> **Validation run 2026-06-17 on argus (10.0.254.45):** built (bpf2go), unit tests
> green incl. RFC-4493 AES-CMAC vectors. SMB signing, coherence linter, firewall
> drop all VALIDATED live (below). eBPF loads/attaches/non-breaking; the byte-level
> TSval-coherence capture needs a *Linux* client (Windows doesn't negotiate TCP TS;
> strx was down) — the one remaining check.
- ✅ P0 **TS incoherence (BUG):** eBPF overrode TSval only on SYN/SYN-ACK (stripping
  the kernel's per-connection random offset) but left data segments with the offset
  → SYN-ACK 7.88M vs data 3.3B TSval discontinuity → standard clients PAWS-drop the
  payload. Broke real vsftpd delivery AND Mimic's own SMB negotiation (Op-5 had to
  `sysctl tcp_timestamps=0` locally to proceed). **FIX (`internal/ebpf/fingerprint.c`,
  2026-06-17):** new data/pure-ACK block overrides TSval on established segments
  (opt_len==12, NOP,NOP,TS) to the same `bpf_ktime` ms clock as the SYN-ACK template,
  gated on the Win11 branch (window_scale>0 && tcp_timestamps). Coherent, keeps TS=A.
  **VALIDATED (argus + Kali Linux client, 2026-06-17):** bpf2go-rebuilt; eBPF loads
  (jited, id 311). With a Kali client (tcp_timestamps=1) hitting the Win11 honeypot,
  tcpdump of argus egress on 445 shows every data-segment TS val ≈ uptime_ms
  (201,659,115→201,661,406 at uptime_ms=201,652,100) — the clean bpf_ktime clock,
  monotonic, NOT the kernel's ~3.3B random-offset value (Op-5). Functional proof: the
  Linux client completed NEGOTIATE+SESSION_SETUP+TREE_CONNECT (no PAWS drop; pre-fix
  this failed). Windows clients don't negotiate TS so the fix is a no-op for them.
- ✅ P0 **OS↔service coherence:** vsftpd (Linux daemon) on a "Windows 11" host = the
  single strongest tell (Op-5 FINDING-006). Extends gap #5. **FIX (`internal/coherence`,
  wired in run.go):** background startup self-audit parses /proc/net/tcp[6] for FOREIGN
  LISTEN ports (skips Mimic's own via /proc/self/fd socket inodes — so the deliberate
  vsftpd FTP honeypot isn't flagged), banner-grabs them, and WARNs when a Unix/Linux
  tell (vsftpd/ubuntu/debian/postfix/…) contradicts a Windows profile. Advisory only.
  **VALIDATED (argus):** flagged a planted vsftpd (2121) AND the real Ubuntu sshd
  (2222) under a Win11 profile; correctly did NOT flag Mimic's own SMB listener.
- ✅ **Closed-port disposition = RST (Linux), not DROP:** Op-5 closed ports RST'd;
  real firewalled Win11 (Op-1) dropped 997+. RST betrays unfirewalled Linux under a
  client persona. **FIX (`internal/services/firewall.go`, opt-in
  `firewall.closed_port_behavior: drop`):** default-drop catch-all in the mimic_reject
  table, added AFTER T2/T3+closed rules; accepts established/related FIRST (live SSH
  survives) + open_ports/preserve_ports allow-list. Default stays `reset` (keeps the
  nmap closed-port probe for high-confidence -O). preserve_ports MUST list SSH.
  TRADEOFF: drop loses nmap's closed-port probes (lower -O confidence, like real Op-1).
  **VALIDATED (argus):** closed 9999→filtered/timeout (not RST), open 445 + preserve
  2222→reachable, live SSH survived, nft order correct (T2/T3→estab→allow→drop).
- ✅ **SMB serves no file content:** auth + share-enum OK but READ → ACCESS_DENIED /
  "Bad SMB2 signature" (Op-5 FINDING-011). Extends gap #1. **FIX — full SMB2/3 signing
  (`internal/honeypot/smb/signing.go` + session/server/ntlm/credentials, 2026-06-17):**
  on a verified seeded cred, derive SessionBaseKey (HMAC-MD5 ntowfv2/NTProofStr) →
  ExportedSessionKey (RC4 if KEY_EXCH) → SigningKey (SP800-108 KDF; 3.1.1 uses the
  running preauth SHA-512 hash accumulated over NEG+SESSION_SETUP) → sign responses
  (AES-128-CMAC for 3.x, HMAC-SHA256 for 2.x). Guest fallback if no preauth chain.
  Also added FileAllInformation (QueryInfo class 18) so smbclient `get` works (its
  "getattrib" precheck returned NT_STATUS_NOT_SUPPORTED, blocking downloads).
  **VALIDATED (argus, live smbclient):** svc_backup authenticates over a SIGNED SMB
  **3.1.1** session (dialect 0x0311), enumerates the full C$ tree, AND downloads a
  332-byte bait file (passwords.txt) — the exact Op-5 failure, now working. AES-CMAC
  also RFC-4493-vector-validated (signing_test.go).
- 📋 **Port persona wrong for edition:** Mimic "Win11" exposed 135/139/443/445/3389;
  real Win11 client (Op-1) exposed 3389/5040/5357/5985/7680 with 135/139/445
  FILTERED (overlap = only 3389). Decoy set reads as server, not DESKTOP client.
- ✅ **Thin decoys → interactive services (COMPLETE, 2026-06-18).** Root cause:
  `listener.go` did `return` (silent FIN) on any probe-miss, and TLS services only
  static-replayed JARM probes — so real clients "ACK the ClientHello, get nothing."
  Direction chosen by user: make decoys interactive like SMB (banners/responses/
  workflows), **Phase A (plaintext breadth) + Phase B (TLS) together**, per-service
  miss behavior.
  - **DONE + validated (argus):** dual-path TLS (`internal/services/tlsterm.go` +
    listener): a ClientHello matching a manifest probe (JARM/scanner) still gets the
    static Schannel ServerHello (fingerprint PRESERVED); any other ClientHello is
    terminated with crypto/tls (self-signed cert, CN=computer name) and served a
    backend. `services/https` now `tls: true, tls_backend: http` → `openssl s_client`
    completes TLSv1.3 + cert, `curl -sk https://` returns an IIS page. **Tradeoff
    (load-bearing):** can't have stock-Go termination AND the Schannel JARM/JA3S on
    the *same* handshake — dual-path keeps JARM for scanners, real TLS for clients; a
    deep analyst probing both could see Go-vs-Schannel divergence (accepted).
  - **DONE + validated (argus + Kali Linux client, 2026-06-17):**
    - **TLS cert CN mechanism:** cert subject = computer name (netbios_name → hostname
      → "WORKSTATION"), coherent with SMB ComputerName / NBNS. `openssl s_client` →
      `subject=CN=WIN11LAB`. (`listener.go` tlsConfig, `tlsterm.go`.)
    - **MSRPC/135 bind_ack:** BIND (ptype 0x0b) → bind_ack (0x0c) accepting ctx 0 / NDR
      (was bind_nack = "rejects all RPC", a tell). Validated: a crafted bind from Kali
      → ptype 0x0c + call_id echo. Non-bind RPC ptypes still get bind_nack (not silence).
      `services/msrpc/{manifest.yaml,responses/bind_ack.bin}`.
  - **Silent-FIN assessed:** http (404 catch-all) + netbios (negative-session catch-all)
    already answer any probe; speaks-first services banner on connect; 443 fixed via TLS
    termination. `default_response` mechanism is available for any future gap.
  - **Work order set by user (2026-06-18): WinRM → MSRPC ept_map → NetBIOS/139 → RDP.**
    Foundational: **`os_edition` primitive** added — `OSProfile.ResolvedEdition()`
    (`internal/config/types.go`) returns workstation/server/dc (explicit `edition:`
    field, else inferred from family+name; "" for non-Windows), surfaced as the
    `os_edition` service option in `SetProfileOptions` (`internal/services/manager.go`).
    This is the config-derived switch that gates edition-dependent behaviour
    (135/139 open-vs-filtered, WinRM presence, SMB signing/computer-name defaults) so
    manifests can `requires: {os_edition: server}`. Unit-tested (types_test.go). The
    17 name-only profiles work unchanged via name inference. **Wired (2026-06-18):**
    `EditionExposesPort` + `shouldStartService` gate msrpc/139; SMB honeypot binds 139
    on server/dc only.
  - ✅ **WinRM/5985 — DONE + VALIDATED (argus + Kali, 2026-06-18).**
    `services/winrm/manifest.yaml` rewritten: a captured template existed (April, real
    Win11 HMDXIN) but had two tells — fixed both. (a) **POST /wsman → 401** Negotiate+
    Kerberos challenge (was 404 — a real WinRM challenges, never 404s its own endpoint;
    new `responses/winrm_401.bin`). (b) **live `Date:`** via `http_date` on every
    response (was frozen 2026-02-18 capture date). GET /wsman → 405 (Allow: POST), other
    → HTTP.sys 404; `default_response` set. All advertise `Server: Microsoft-HTTPAPI/2.0`.
    **Live (Kali→argus:5985):** GET → 404 + Date=today; POST /wsman → 401 Negotiate/
    Kerberos; `nmap -sV` → "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)". Edition note:
    belongs in `services:` for server profiles (client SKUs don't run it by default).
  - ✅ **MSRPC/135 ept_map — DONE + VALIDATED (argus + Kali, 2026-06-18).** Captured a
    real `impacket-rpcdump` exchange from a proxmox Win11 25H2 box (9512, 10.0.254.67):
    single ept_lookup (opnum 2) whose response = 11 DCE/RPC fragments (10×4280+2916 =
    **45,716 B**, 138 endpoints). `services/msrpc` now `stateful: true`: BIND→bind_ack
    (captured, real 4280 max-frag), then ept_lookup→`responses/epm_lookup.bin`. Two new
    rewrite types (`internal/services/responder.go`): **`dcerpc_callid`** walks PDUs by
    frag_len and echoes the client's call_id into EVERY fragment header (so the multi-
    frag reply correlates regardless of client call_id); **`host_ip`** (token=capture IP)
    replaces the capture IP in ncacn_ip_tcp tower floors with the host's egress IPv4
    (`hostEgressIPv4()` via inert UDP dial + InterfaceAddrs fallback). Unit-tested
    (`msrpc_epm_test.go`: 11 frags, call_id echo, IP gone). **Live (Kali→argus:135):**
    rpcdump enumerates all 138 endpoints; ncacn_ip_tcp bindings show **10.0.254.45**
    (argus), zero leak of capture .67; np towers show DESKTOP-G6JUGNO (matched via
    `netbios_name` — the documented coherence mitigation). Was "bind ok, no enum"; now
    full self-consistent endpoint map. RESIDUAL (deferred): dynamic ncacn_ip_tcp ports
    (49664+) advertised but not actually listening (mild tell).
  - ✅ **NetBIOS/139 — DONE (2026-06-18).** `smb_honeypot` binds TCP 139 on Server/DC
    editions (`Config.NetBIOSPort`): NBSS 0x81→0x82 handshake then full SMB2/3 state
    machine (same as 445). `config.EditionExposesPort` gates 135/139/msrpc/netbios
    template on workstation (filtered, like real Win11 client). Template `netbios`
    skipped when honeypot owns 139. Files: `internal/honeypot/smb/nbss.go`,
    `internal/config/edition_ports.go`, `cmd/mimic/run.go`.
  - ✅ **RDP/3389 — DONE + VALIDATED (argus + Kali, 2026-06-18).** Stateful
    honeypot `internal/honeypot/rdp/`: X.224 nego (`rdp_neg_tls.bin`) →
    **dual-path TLS** (JARM-only ClientHellos → static `tls_server_hello.bin`;
    real clients → `crypto/tls`) → CredSSP TSRequest NTLM Type 1→Type 2 with
    **Product_Version from `profile.Version`** + live MsvAvTimestamp. Handles
    **raw ASN.1 CredSSP** (nmap `rdp-ntlm-info` sends no TPKT over TLS) and
    TPKT-wrapped TSRequest (mstsc path). `run.go` intercepts `rdp` in `services:`.
    **Live (Kali→argus:3389, Server 2022 profile):** `nmap --script rdp-ntlm-info`
    → Product_Version **10.0.20348**, Target_Name/NetBIOS/DNS = WORKGROUP /
    DESKTOP-G6JUGNO. Closes OSE tell "3389 no-NTLM". `services/rdp/manifest.yaml`
    = JARM template reference only.
- 📋 **Process self-ID:** `ss -tlnp` → `/usr/local/bin/mimic run`; one PID owns all
  decoy ports; binary literally named `mimic`. Post-shell instant unmask. Extends #5.

## Strategic roadmap (2026-06-18, parallel tracks)

**Scope:** OSE = network confusion + interactive service depth; not post-shell host
telemetry. **North star:** Windows reverse-client (WFP/Npcap hooks, same capture
pipeline inverted) after Linux benchmarks pass.

| Track | Focus | Current |
|-------|-------|---------|
| **A — OSE** | Cred-leak loop, JA4S measure, dynamic RPC ports (49664+) | In progress |
| **B — Breadth** | `--services all`, edition gating, deeper SMB scripts | Queued |
| **C — Hygiene** | argus sync, packet-template regen on promote only | Ongoing |

## Known Gaps / Next Priority

1. **smbmap parity (verify-first)** — SMB 3.1.1 signing **implemented and
   validated** (`signing.go`, `fa194f7`; smbclient signed download OK). smbmap
   v1.10.4 still reported `0 sessions` **before** the signing fix — **retest
   pending** (Phase 0). Tool-specific residual only; not a signing implementation gap.
2. ✅ **Build-number / cross-layer OS-identity coherence (RESOLVED 2026-06-17;
   roadmap Mimic_R_C.md item #7 "self-consistency is the entire value prop").**
   NTLM CHALLENGE Version derived from the profile via `Server.osVersionTriple()`;
   fallback 10.0.19041 only when OSVersion unset. All 17 Windows profiles carry a
   correct `version:` (each emits its own build), so "hardcoded 19041 regardless of
   profile" is closed. **Cross-layer audit + fixes:**
   - **Win11 profile was self-contradictory:** `version` said 10.0.22000 (21H2) but
     the stack block + RDP template were captured from 25H2. Set to **10.0.26200**
     (25H2) so eBPF stack, SMB/NTLM build, NativeOS, and RDP all agree. Faithful (a
     real 25H2 box behaves identically, incl. nmap mislabeling it 21H2). Win11 stack
     has window=65535 + timestamps-ON, vs Win10/2022 8192+off — a real 25H2 change.
   - **MsvAvTimestamp (0x0007) added** to NTLM TargetInfo (live FILETIME). Modern
     Windows always includes it; absence was a tell. Safe — NTLMv2 verify uses the
     client's blob, not our TargetInfo. AV order now 0x2,0x1,0x4,0x3,0x7,0x0.
   - **Server 2025 profile added** (`profiles/windows/server-2025.yaml`, 10.0.26100)
     from a real nmap -O capture (proxmox, captures/proxmox/srv2025): WIN=FFFF,
     OPS M5B4NW8ST11, TS=A — i.e. 25H2-class stack. Closes a captured-but-unprofiled OS.
   - **Audit clean:** Win10@19041 and all server profiles@RTM builds match their
     stacks; no other version/capture contradiction found.
   **Validated live on argus:** raw SMB2 probe reads NTLM Version **10.0 build 26200**
   from the Win11 honeypot; MsvAvTimestamp present and live (FILETIME delta 0s);
   Server 2025 profile loads + applies eBPF cleanly. Files:
   `internal/honeypot/smb/{ntlm.go,ntlm_test.go}`, `profiles/windows/{11.yaml,server-2025.yaml}`.
3. **JA4S validation** — JARM/JA3S validated; JA4S (FoxIO; Suricata 8.0 / Zeek)
   is the current standard and unmeasured. Byte-faithful replay likely passes;
   confirm with FoxIO ja4 tooling or Suricata 8.0.
4. **Cross-service credential leak** — plant the seeded creds in HTTP/maze/config
   artifacts so the reuse loop actually closes (SMB side already accepts them).
5. **eBPF host-telemetry stealth** — BPF(SCHED_CLS) load is auditable; the
   Linux-host/Windows-fingerprint contradiction is the strongest detection
   surface. Possible mitigation: `prog_name` + process-ancestry spoofing (see
   LJM daydream `mimic-ebpf-stealth-gap`). Reframes a "hard limit" as solvable.
   *(OSE-2026-001 confirmed: vsftpd-on-Windows mismatch + `mimic` process self-ID
   were the operator's deception tells — see exercise section.)*
6. **TLS handshake completion** — ✅ 443 dual-path TLS (2026-06-17); ✅ 3389
   CredSSP honeypot (2026-06-18, validated `rdp-ntlm-info`).
   *(OSE-2026-001: 443 FIN-after-ClientHello and 3389 no-NTLM were the tells.)*
7. **Service expansion** — ✅ MSRPC/135 endpoint-mapper capture+replay DONE (2026-06-18,
   ept_lookup; see thin-decoys section). Remaining: `--services all`, deeper SMB scripts.

## Operational

### argus-lab (test target)
- IP `10.0.254.45`, iface `ens18`, SSH key `~/.ssh/argus_lab` (port 2222), Go
  1.25.6 at `/usr/local/go/bin`, repo at `~/mimic/`.
- Boot persistence: `/etc/modules-load.d/mimic.conf` loads `nft_reject` +
  `nft_reject_inet`.
- **As of 2026-06-18 handoff: mimic is RUNNING** on argus from `/tmp/mimic_full.yaml`
  (profile "Windows 11"; services msrpc, winrm, netbios, nbns; netbios_name
  `DESKTOP-G6JUGNO`; closed 80,8080; debug logging → `/tmp/mimic.log`). Built from the
  synced tree (full eBPF build OK). Restart/teardown sequence below.

### Kali attack client (for stateful-protocol validation — #4/#1)
- **VM 9511 `kali-mimic-client` @ 10.0.254.70** (proxmox node nexus, linked clone of
  template 9341 kali-2026). Reach: `ssh -o BatchMode=yes -o PreferredAuthentications=publickey
  -i ~/.ssh/argus_lab root@10.0.254.70` (Windows: `C:\Windows\System32\OpenSSH\ssh.exe`).
- Provisioned this session: argus_lab pubkey injected into root's authorized_keys (the
  9341 template did NOT carry it); sshd `UseDNS no` + `GSSAPIAuthentication no` set
  (`/etc/ssh/sshd_config.d/99-fast.conf`) — without these SSH hangs ~30s/connect. sshd
  is NOT enabled on boot by default — if the clone is reset, re-enable via the QEMU
  guest agent (`systemctl enable --now ssh`) before key-based SSH works.
- Tools: nmap, **impacket-rpcdump** (the rpcdump.py binary), nxc, tcpdump, tshark, python3.
- Drive proxmox from ss-book via `infra/proxmox/lab.py` (python; token auto-loaded).
  Capture target for re-capture: `python lab.py deploy 9011 <vmid> --linked --start`
  → `lab.py ip <vmid>` → `lab.py prep <vmid>` (fw off) → capture → `lab.py destroy <vmid>`.
- **Kept running** at handoff (do not destroy — needed for RDP argus validation).

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
