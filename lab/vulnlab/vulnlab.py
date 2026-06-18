#!/usr/bin/env python3
"""
vulnlab.py — fleet manager for Mimic AI pentest comparison lab.

Wraps infra/proxmox/lab.py for clone/snapshot/reset and adds guest-agent
provisioning hooks for Linux/Windows targets.

Auth: auto-loaded from infra/packer/windows/make_autounattend_isos.py (see lab/pve_auth.py).

Examples:
    python lab/vulnlab/vulnlab.py status
    python lab/vulnlab/vulnlab.py deploy --start
    python lab/vulnlab/vulnlab.py provision-linux
    python lab/vulnlab/vulnlab.py provision-win11
    python lab/vulnlab/vulnlab.py snapshot --name base
    python lab/vulnlab/vulnlab.py reset
"""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

REPO = Path(__file__).resolve().parents[2]
LAB_PY = REPO / "infra" / "proxmox" / "lab.py"
sys.path.insert(0, str(REPO / "lab"))
from pve_auth import pve_auth_header, resolve_pve_token  # noqa: E402
VULNLAB_DIR = Path(__file__).resolve().parent
SCRIPTS = VULNLAB_DIR / "scripts"


def load_network() -> dict:
    for name in ("network.local.yaml", "network.example.yaml"):
        path = VULNLAB_DIR / name
        if path.exists():
            with path.open() as f:
                return yaml.safe_load(f)
    sys.exit("no network.local.yaml or network.example.yaml in lab/vulnlab/")


def lab_cmd(*args: str) -> None:
    if not LAB_PY.exists():
        sys.exit(f"missing {LAB_PY} — infra/ is local-only")
    env = os.environ.copy()
    if "PVE_TOKEN" not in env:
        env["PVE_TOKEN"] = resolve_pve_token()
    rc = subprocess.call([sys.executable, str(LAB_PY), *args], env=env)
    if rc != 0:
        sys.exit(rc)


def template_vmid(net: dict, key: str) -> int:
    t = net["templates"][key]
    return int(t)


def vm_entry(net: dict, name: str) -> dict:
    return net["vms"][name]


def guest_exec(vmid: int, shell: str, label: str = "exec") -> None:
    """Run bash -c on Linux guest via QEMU guest agent (same API as lab.py prep)."""
    import requests
    import urllib3

    urllib3.disable_warnings()

    host = os.environ.get("PVE_HOST", "10.0.240.8:8006")
    node = os.environ.get("PVE_NODE", "nexus")
    base = f"https://{host}/api2/json/nodes/{node}/qemu/{vmid}/agent"
    headers = pve_auth_header()

    cmd = [
        ("command", "bash"),
        ("command", "-c"),
        ("command", shell),
    ]
    r = requests.post(f"{base}/exec", headers=headers, verify=False, data=cmd, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"guest exec failed {vmid}: {r.text[:300]}")
    pid = r.json()["data"]["pid"]
    for _ in range(120):
        time.sleep(2)
        d = requests.get(
            f"{base}/exec-status", headers=headers, verify=False, params={"pid": pid}, timeout=15
        ).json().get("data")
        if d and d.get("exited"):
            code = d.get("exitcode", -1)
            out = (d.get("out-data") or "").strip()
            err = (d.get("err-data") or "").strip()
            print(f"  {label} {vmid}: exit={code}")
            if out:
                print(out[-4000:])
            if err:
                print(err[-2000:], file=sys.stderr)
            if code != 0:
                sys.exit(f"guest exec {vmid} exit {code}")
            return
    sys.exit(f"guest exec {vmid} timeout")


def guest_exec_powershell(vmid: int, script: str) -> None:
    import requests
    import urllib3

    urllib3.disable_warnings()
    host = os.environ.get("PVE_HOST", "10.0.240.8:8006")
    node = os.environ.get("PVE_NODE", "nexus")
    base = f"https://{host}/api2/json/nodes/{node}/qemu/{vmid}/agent"
    headers = pve_auth_header()
    cmd = [
        ("command", "powershell.exe"),
        ("command", "-NoProfile"),
        ("command", "-ExecutionPolicy"),
        ("command", "Bypass"),
        ("command", "-Command"),
        ("command", script),
    ]
    r = requests.post(f"{base}/exec", headers=headers, verify=False, data=cmd, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"guest exec failed {vmid}: {r.text[:300]}")
    pid = r.json()["data"]["pid"]
    for _ in range(120):
        time.sleep(2)
        d = requests.get(
            f"{base}/exec-status", headers=headers, verify=False, params={"pid": pid}, timeout=15
        ).json().get("data")
        if d and d.get("exited"):
            print(f"  win11 prep {vmid}: exit={d.get('exitcode')}")
            return
    sys.exit(f"guest exec {vmid} timeout")


def cmd_status(_args: argparse.Namespace) -> None:
    net = load_network()
    print("== Vuln lab fleet (configured) ==")
    for key, ent in net["vms"].items():
        mimic = ent.get("mimic")
        extra = f" mimic={mimic}" if mimic is not None else ""
        print(f"  {key:<14} vmid={ent['vmid']:<5} ip={ent['ip']}{extra}")
    print()
    lab_cmd("list")


def cmd_deploy(args: argparse.Namespace) -> None:
    net = load_network()
    targets = ["win11", "linux_bare", "linux_mimic"]
    if args.vm:
        targets = [args.vm]
    for key in targets:
        ent = vm_entry(net, key)
        tmpl_key = ent.get("template", "ubuntu_vuln")
        if tmpl_key == "win11":
            src = template_vmid(net, "win11")
        else:
            src = template_vmid(net, "ubuntu_vuln")
        name = ent["name"]
        vmid = int(ent["vmid"])
        linked = ["--linked"] if ent.get("clone", "linked") == "linked" else []
        print(f"== deploy {key} -> {vmid} from {src}")
        lab_cmd("deploy", str(src), str(vmid), "--name", name, *linked, *(["--start"] if args.start else []))


def cmd_snapshot(args: argparse.Namespace) -> None:
    net = load_network()
    names = args.targets or ["win11", "linux_bare", "linux_mimic", "attacker"]
    for key in names:
        if key not in net["vms"]:
            continue
        vmid = int(net["vms"][key]["vmid"])
        lab_cmd("snapshot", str(vmid), "--name", args.name)


def cmd_reset(args: argparse.Namespace) -> None:
    net = load_network()
    snap = args.name or net.get("snapshots", {}).get("golden", "base")
    names = [args.vm] if args.vm else ["win11", "linux_bare", "linux_mimic"]
    for key in names:
        vmid = int(net["vms"][key]["vmid"])
        lab_cmd("reset", str(vmid), "--name", snap, *(["--start"] if args.start else []))


def _read_script(name: str) -> str:
    path = SCRIPTS / name
    if not path.exists():
        sys.exit(f"missing script {path}")
    return path.read_text(encoding="utf-8")


def cmd_provision_linux(args: argparse.Namespace) -> None:
    net = load_network()
    b64 = base64.b64encode(_read_script("provision_linux.sh").encode()).decode()
    targets = [args.vm] if args.vm else ["linux_bare", "linux_mimic"]
    for key in targets:
        ent = vm_entry(net, key)
        vmid = int(ent["vmid"])
        role = "mimic" if ent.get("mimic") else "bare"
        print(f"== provision-linux {key} ({vmid}) role={role}")
        shell = (
            f"echo {b64} | base64 -d > /tmp/provision_linux.sh && "
            f"chmod +x /tmp/provision_linux.sh && "
            f"/tmp/provision_linux.sh --role {role}"
        )
        guest_exec(vmid, shell, label="linux")


def cmd_provision_win11(_args: argparse.Namespace) -> None:
    net = load_network()
    vmid = int(net["vms"]["win11"]["vmid"])
    b64 = base64.b64encode(_read_script("provision_win11.ps1").encode("utf-8")).decode()
    print(f"== provision-win11 ({vmid})")
    ps_cmd = (
        "New-Item -ItemType Directory -Force -Path C:\\lab | Out-Null; "
        f"[IO.File]::WriteAllBytes('C:\\lab\\provision_win11.ps1', "
        f"[Convert]::FromBase64String('{b64}')); "
        "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\lab\\provision_win11.ps1"
    )
    guest_exec_powershell(vmid, ps_cmd)


def cmd_configure_mimic(_args: argparse.Namespace) -> None:
    """Remind operator to deploy default Mimic lab config on linux-mimic."""
    cfg_example = VULNLAB_DIR / "configs" / "mimic-linux-mimic.yaml.example"
    print("Configure linux-mimic (mgmt :2222):")
    print(f"  1. Copy {cfg_example} -> /etc/mimic/config.yaml")
    print("  2. Fix interface: ip -br link")
    print("  3. systemctl restart mimic")
    print("  4. nmap -O <linux-mimic-ip> from attacker")
    print("  Test brief: target IP + RoE + creds (default pool) — nothing else required.")


def main() -> None:
    p = argparse.ArgumentParser(description="Mimic vuln lab fleet manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="show configured fleet + proxmox list").set_defaults(func=cmd_status)

    d = sub.add_parser("deploy", help="clone templates to fleet VMIDs")
    d.add_argument("--start", action="store_true")
    d.add_argument("--vm", choices=["win11", "linux_bare", "linux_mimic"])
    d.set_defaults(func=cmd_deploy)

    s = sub.add_parser("snapshot", help="snapshot fleet VMs")
    s.add_argument("--name", default="base")
    s.add_argument("--targets", nargs="*", help="subset: win11 linux_bare linux_mimic attacker")
    s.set_defaults(func=cmd_snapshot)

    r = sub.add_parser("reset", help="rollback targets to golden snapshot")
    r.add_argument("--name", default=None, help="snapshot name (default: base from network yaml)")
    r.add_argument("--vm", choices=["win11", "linux_bare", "linux_mimic"])
    r.add_argument("--start", action="store_true")
    r.set_defaults(func=cmd_reset)

    pl = sub.add_parser("provision-linux", help="guest-agent run provision_linux.sh")
    pl.add_argument("--vm", choices=["linux_bare", "linux_mimic"])
    pl.set_defaults(func=cmd_provision_linux)

    sub.add_parser("provision-win11", help="guest-agent run provision_win11.ps1").set_defaults(
        func=cmd_provision_win11
    )

    sub.add_parser("configure-mimic", help="print mimic/credentials deploy steps").set_defaults(
        func=cmd_configure_mimic
    )

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()