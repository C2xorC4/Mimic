# Mimic AI pentest vuln lab

Controlled Proxmox lab on **nexus** (`10.0.240.8`) for comparing standard pentest
methodology against bare vulnerable targets vs the same Linux target with Mimic
deception enabled.

## Targets

| VM name | Role | VMID (default) | Vuln |
|---------|------|----------------|------|
| `mimic-lab-win11` | Windows control | 9501 | MSMQ CVE-2023-21554 (`:1801`) |
| `mimic-lab-linux-bare` | Linux control | 9502 | vsftpd 2.3.4 backdoor (`:21`) |
| `mimic-lab-linux-mimic` | Deception test | 9503 | Same vsftpd; Mimic → Windows 11 |
| `mimic-lab-attacker` | Assessment host | 9504 | (none) |

Golden templates (build once):

| Template | VMID (default) | Source |
|----------|----------------|--------|
| `mimic-lab-ubuntu-vuln` | 9200 | Ubuntu 22.04 cloud image + provision script |
| Win11 vuln | 9011 clone + `provision_win11.ps1` | Existing golden Win11 template |

## Quick start (operator)

1. Copy [`lab/vulnlab/network.example.yaml`](../../lab/vulnlab/network.example.yaml) to
   `lab/vulnlab/network.local.yaml` and adjust IPs/VMIDs if needed.
2. Proxmox token is read from [`infra/packer/windows/make_autounattend_isos.py`](../../infra/packer/windows/make_autounattend_isos.py) (`TOKEN_HEADER` — same as `capture.ps1`). Override with `PVE_TOKEN` if needed.
3. Build the Ubuntu golden template (once): see [lab/vulnlab/README.md](../../lab/vulnlab/README.md).
4. Deploy fleet: `python lab/vulnlab/vulnlab.py deploy --start`
5. Snapshot golden state: `python lab/vulnlab/vulnlab.py snapshot --name base`
6. Reset between AI runs: `python lab/vulnlab/vulnlab.py reset`

## Rules of engagement (assessors)

**In scope:** The three target VMs — all ports **except** management.

**Out of scope:**

- **TCP 2222** on any host (management SSH)
- Proxmox / hypervisor / non-target lab hosts
- DoS

Assessor brief to give AI each run is in [experiment-protocol.md](experiment-protocol.md).

## SMB / Mimic config

`linux-mimic` uses the **default Mimic testing config** ([`config.yaml.example`](../../config.yaml.example)
/ [`lab/vulnlab/configs/mimic-linux-mimic.yaml.example`](../../lab/vulnlab/configs/mimic-linux-mimic.yaml.example)
— same credential pool and `smb_honeypot` defaults). No lab-specific credential workflow.

At test time the operator supplies the assessor with **target scope + RoE + creds** in the
session brief — nothing beyond that.

## Documentation map

| File | Purpose |
|------|---------|
| [experiment-protocol.md](experiment-protocol.md) | AI RoE, run template, scoring rubric |
| [ground-truth.md](ground-truth.md) | Operator-only: builds, CVEs, expected nmap, cred ids |
| [network.example.yaml](network.example.yaml) | Committed IP/VMID reference (no secrets) |

## Implementation layout

```
docs/vulnlab/          ← committed docs (this tree)
lab/vulnlab/           ← committed automation (no secrets)
infra/                 ← gitignored; Proxmox tokens stay local
```