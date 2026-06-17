# Mimic (public demo & documentation)

Network deception platform for Linux: kernel-level TCP/IP fingerprint
modification (eBPF) plus application-layer service emulation. Makes a
Linux host present as another operating system to active fingerprinting
tools (`nmap -O`, JARM, JA3S) and common service scanners.

**This repository does not contain the Mimic product source code.** It
provides public documentation, validation examples, and demonstration
materials. The commercial product is distributed separately under
license.

## What Mimic does

- **Stack layer:** eBPF TC hooks rewrite TTL, TCP options, timestamps,
  window behavior, ICMP traits, and related stack signals.
- **Service layer:** Probe-matched response replay for SMB, RDP, HTTPS,
  SSH, and other services with dynamic field rewriting.
- **Telemetry:** Structured events to NDJSON files and syslog for SIEM
  ingestion.

## Proof points (run against a licensed deployment)

With the Windows 11 profile active on a licensed eval host:

```bash
# OS fingerprint — expect exact Windows 10/11 DB match
nmap -O <target>

# Service fingerprinting
nmap -sV -p 445,443,3389 <target>
```

See [`docs/validation.md`](docs/validation.md) for expected outputs and
demo recordings.

## Request evaluation access

Mimic is proprietary software. To request a time-limited evaluation
binary under NDA:

**[CONTACT EMAIL]**

Include: organization, intended use (purple team / SOC validation /
research), and deployment environment (Linux version, kernel).

## Repository contents

| Path | License |
|------|---------|
| `docs/` | Documentation © [COPYRIGHT HOLDER]. All rights reserved. |
| `examples/` | Example configs and commands for documentation only — not a license to the product |
| `assets/` | Demo media (screenshots, recordings) |

No source code in this repository is licensed for redistribution or
derivative commercial use. Do not infer product rights from files here.

## Relationship to the product repository

The canonical Mimic implementation is maintained in a **private**
repository. This public repo exists for credibility and technical
communication, not as an open-source edition of the product.

## Legal

- Product use: governed by the Mimic End User License Agreement provided
  with eval or commercial distributions.
- This repo: documentation and examples only; see [`LICENSE`](LICENSE).

## Contact

[Licensing and partnership inquiries: CONTACT EMAIL]