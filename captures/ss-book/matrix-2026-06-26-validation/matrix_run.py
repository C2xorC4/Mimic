#!/usr/bin/env python3
"""
Captured-profiles matrix runner for the Windows host (both fidelity levels).

Drives mimic on a Windows VM OUT-OF-BAND via the guest agent (ga.run) so a
connectivity blip can never strand the run, and scans each persona from Kali.

  python matrix_run.py <hifi|winstd> <vmid> <vmip>

mode:
  hifi   - Linux personas arm the mimic-hifi driver (high_fidelity: true) -> expect TI=Z / EXACT
  winstd - Linux personas run plain WinDivert (high_fidelity: false)      -> expect ~family (TI=I)
Windows personas never arm the driver either way (winQuirks).
"""
import re
import subprocess
import sys
import time

sys.path.insert(0, r"C:\Users\C2xor\AppData\Local\Temp\claude\D--repos-security-Mimic\f8c80049-ce5f-4175-b55c-5a8df8176670\scratchpad")
import ga  # reuse the guest-agent exec

KALI = "10.0.254.70"
KEY = r"C:\Users\C2xor\.ssh\argus_lab"
SSH = r"C:\Windows\System32\OpenSSH\ssh.exe"

WINDOWS = ["Windows 10", "Windows 11", "Windows Server 2016",
           "Windows Server 2019", "Windows Server 2022", "Windows Server 2025"]
LINUX = ["Ubuntu", "Debian", "Fedora", "Rocky Linux", "CentOS 7", "Arch Linux", "Kali Linux"]
LINUX_YAML = {"Ubuntu": "ubuntu", "Debian": "debian", "Fedora": "fedora", "Rocky Linux": "rocky",
              "CentOS 7": "centos-7", "Arch Linux": "arch", "Kali Linux": "kali"}
PROFILES = WINDOWS + LINUX


def ga_quiet(vmid, ps, timeout=60):
    """Run a guest PS script, suppressing ga's stdout chatter."""
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ga.run(vmid, ps, timeout)
    return buf.getvalue()


def set_linux_hifi(vmid, enabled):
    val = "true" if enabled else "false"
    ps = (
        "$ErrorActionPreference='Continue';"
        "$names=@('ubuntu','debian','fedora','rocky','centos-7','arch','kali');"
        "foreach($n in $names){ $u=\"C:\\mimic\\profiles\\linux\\$n.yaml\";"
        " if(Test-Path $u){ (Get-Content $u | Where-Object { $_ -notmatch 'high_fidelity' }) + "
        f"'  high_fidelity: {val}' | Set-Content $u }} }};"
        "'linux high_fidelity set'"
    )
    ga_quiet(vmid, ps, 40)


def arm_profile(vmid, profile):
    ps = (
        "$ErrorActionPreference='Continue';"
        "Get-Process mimic -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1;"
        "Remove-Item C:\\mimic\\mimic.log -ErrorAction SilentlyContinue;"
        f"$cfg=\"profile: `\"{profile}`\"`ninterface: Ethernet`nservices: [http]`nclosed_ports: [9999]`n"
        "firewall:`n    closed_port_behavior: reset`nprofiles_dir: C:\\mimic\\profiles`n"
        "services_dir: C:\\mimic\\services`nlogging:`n    log_dir: C:\\mimic`n    level: warn`n    to_stdout: false\";"
        "Set-Content C:\\mimic\\cfg.yaml $cfg -Encoding utf8;"
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='C:\\mimic\\mimic.exe run -c C:\\mimic\\cfg.yaml -i Ethernet'} | Out-Null;"
        "Start-Sleep 9; 'armed ' + ((Get-Process mimic -ErrorAction SilentlyContinue) -ne $null)"
    )
    return ga_quiet(vmid, ps, 45)


def nmap_scan(vmip):
    cmd = [SSH, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
           "-i", KEY, "root@" + KALI, f"nmap -Pn -O --osscan-guess -p 80,9999 {vmip}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=140).stdout
    except subprocess.TimeoutExpired:
        return "SCAN-TIMEOUT (VM may be offline)", "", False
    osline = ""
    for m in ("OS details:", "Aggressive OS guesses:", "No exact OS matches", "Too many fingerprints"):
        idx = out.find(m)
        if idx >= 0:
            osline = out[idx:out.find("\n", idx)].strip()
            break
    ti = ""
    mti = re.search(r"TI=[^%)\s]*", out)
    if mti:
        ti = mti.group(0)
    up = ("Host is up" in out) or bool(osline)
    return osline or "(no OS line)", ti, up


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "hifi"
    vmid = int(sys.argv[2]) if len(sys.argv) > 2 else 9523
    vmip = sys.argv[3] if len(sys.argv) > 3 else "10.0.255.102"
    print(f"=== MATRIX mode={mode} vmid={vmid} vmip={vmip} ===", flush=True)
    set_linux_hifi(vmid, enabled=(mode == "hifi"))
    results = []
    offline = []
    for p in PROFILES:
        arm_profile(vmid, p)
        osline, ti, up = nmap_scan(vmip)
        fam = "linux" if p in LINUX else "win"
        results.append((p, fam, ti, osline, up))
        if not up:
            offline.append(p)
        print(f"[{mode}] {p:24s} up={up} {ti:10s} {osline}", flush=True)
    # stop mimic, leave VM safe
    ga_quiet(vmid, "Get-Process mimic -ErrorAction SilentlyContinue | Stop-Process -Force; 'stopped'", 30)
    print(f"\n=== SUMMARY ({mode}) ===", flush=True)
    for p, fam, ti, osline, up in results:
        print(f"  {p:24s} [{fam}] {ti:10s} {osline}", flush=True)
    print(f"\nSTABILITY: {'PASS (all profiles reachable)' if not offline else 'FAIL offline=' + str(offline)}", flush=True)


if __name__ == "__main__":
    main()
