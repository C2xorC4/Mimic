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
