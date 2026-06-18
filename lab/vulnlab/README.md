# Vuln lab automation

Committed scripts for the Mimic pentest comparison lab. Secrets and local overrides
stay in `network.local.yaml` (gitignored).

## Prerequisites

- Proxmox **nexus** (`10.0.240.8`) — API token auto-loaded from `infra/packer/windows/make_autounattend_isos.py` ([`lab/pve_auth.py`](../pve_auth.py))
- Existing Win11 golden template **9011** on nexus
- Python 3 + `requests` (`pip install requests`)
- [`infra/proxmox/lab.py`](../../infra/proxmox/lab.py) present locally (gitignored tree)

## One-time setup

```powershell
cd D:\Repos\Security\Mimic
copy lab\vulnlab\network.example.yaml lab\vulnlab\network.local.yaml
# edit VMIDs/IPs if needed
# token: uses TOKEN_HEADER in infra\packer\windows\make_autounattend_isos.py
```

### 1. Ubuntu golden template (9200)

1. Create VM 9200 from Ubuntu 22.04 cloud image on nexus (UEFI, virtio, guest agent).
2. Static IP `10.0.250.120` or DHCP; enable `qemu-guest-agent`.
3. Copy `scripts/provision_linux.sh` to the guest and run as root:

   ```bash
   curl -sO http://<operator-bucket>/provision_linux.sh   # or scp via :2222 after first boot
   chmod +x provision_linux.sh
   ./provision_linux.sh --role template
   ```

4. Templatize: `python infra/proxmox/lab.py templatize 9200`

### 2. Win11 vuln template (optional separate template)

Clone 9011 → 9501, run `scripts/provision_win11.ps1`, validate MSMQ, snapshot `base`.
Or provision after each `deploy` — script is idempotent.

### 3. Deploy fleet

```bash
python lab/vulnlab/vulnlab.py deploy --start
python lab/vulnlab/vulnlab.py provision-linux   # guest-agent exec on 9502/9503
python lab/vulnlab/vulnlab.py provision-win11   # guest-agent on 9501
python lab/vulnlab/vulnlab.py configure-mimic  # copy config to 9503 only
python lab/vulnlab/scripts/validate_targets.sh
python lab/vulnlab/vulnlab.py snapshot --name base
```

## Day-2 operations

```bash
python lab/vulnlab/vulnlab.py reset              # all targets → base
python lab/vulnlab/vulnlab.py reset --vm linux_mimic
python lab/vulnlab/vulnlab.py status
```

## Mimic config

Deploy [`configs/mimic-linux-mimic.yaml.example`](configs/mimic-linux-mimic.yaml.example)
to `/etc/mimic/config.yaml` on `linux-mimic` — uses the same default credential pool as
[`config.yaml.example`](../../config.yaml.example). At test time, supply creds + scoping
to the assessor in the session brief.

## Files

| Path | Purpose |
|------|---------|
| `vulnlab.py` | Fleet deploy / reset / snapshot / guest-agent provision |
| `network.example.yaml` | Default VMIDs and IPs |
| `scripts/provision_linux.sh` | vsftpd vuln, Mimic deps, SSH :2222-only |
| `scripts/provision_win11.ps1` | MSMQ + optional enum share |
| `scripts/validate_targets.sh` | Operator pre-flight nmap checks |
| `configs/` | Mimic lab config template |