#!/usr/bin/env python3
"""
eBPF matrix runner for the Linux host. Cycles the captured-profiles set on a Linux VM
(mimic eBPF backend, root) and scans each persona from Kali. SSH-driven.

  python ebpf_matrix.py <vmip>
"""
import subprocess
import sys

sys.path.insert(0, r"C:\Users\C2xor\AppData\Local\Temp\claude\D--repos-security-Mimic\f8c80049-ce5f-4175-b55c-5a8df8176670\scratchpad")
from matrix_run import PROFILES, LINUX, nmap_scan

KEY = r"C:\Users\C2xor\.ssh\argus_lab"
SSH = r"C:\Windows\System32\OpenSSH\ssh.exe"


def vm_ssh(vmip, cmd, timeout=60):
    full = [SSH, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            "-i", KEY, "root@" + vmip, cmd]
    try:
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return "SSH-TIMEOUT"


def arm(vmip, profile):
    # kill any prior mimic, clean eBPF TC + nft, write cfg, start detached, settle
    cfg = (
        f'profile: "{profile}"\\ninterface: eth0\\nservices: [http]\\nclosed_ports: [9999]\\n'
        'firewall:\\n    closed_port_behavior: reset\\n'
        'profiles_dir: /root/profiles\\nservices_dir: /root/services\\n'
        'logging:\\n    log_dir: /root\\n    level: warn\\n    to_stdout: false\\n'
    )
    script = (
        "pkill -TERM -x mimic 2>/dev/null; sleep 2; pkill -9 -x mimic 2>/dev/null; "
        "tc qdisc del dev eth0 clsact 2>/dev/null; "
        "nft delete table inet mimic_reject 2>/dev/null; nft delete table inet mimic_block 2>/dev/null; "
        f"printf '{cfg}' > /root/cfg.yaml; "
        "setsid /root/mimic run -c /root/cfg.yaml -i eth0 >/root/mimic.log 2>&1 </dev/null & "
        "sleep 9; echo armed=$(pgrep -x mimic | head -1)"
    )
    return vm_ssh(vmip, script, 40)


def main():
    vmip = sys.argv[1] if len(sys.argv) > 1 else "10.0.250.53"
    print(f"=== eBPF MATRIX vmip={vmip} ===", flush=True)
    results, offline = [], []
    for p in PROFILES:
        arm(vmip, p)
        osline, ti, up = nmap_scan(vmip)
        fam = "linux" if p in LINUX else "win"
        results.append((p, fam, ti, osline, up))
        if not up:
            offline.append(p)
        print(f"[ebpf] {p:24s} up={up} {ti:10s} {osline}", flush=True)
    vm_ssh(vmip, "pkill -TERM -x mimic; sleep 1; tc qdisc del dev eth0 clsact 2>/dev/null; echo done", 20)
    print("\n=== SUMMARY (ebpf) ===", flush=True)
    for p, fam, ti, osline, up in results:
        print(f"  {p:24s} [{fam}] {ti:10s} {osline}", flush=True)
    print(f"\nSTABILITY: {'PASS (all reachable)' if not offline else 'FAIL offline=' + str(offline)}", flush=True)


if __name__ == "__main__":
    main()
