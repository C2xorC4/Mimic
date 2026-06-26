#!/usr/bin/env python3
"""
ga.py - out-of-band QEMU guest-agent exec for the Mimic lab.

Runs a PowerShell command/script on a Windows VM over the virtio-serial guest
agent (NOT the network) and captures stdout/stderr. This survives a network /
WinRM outage -- exactly what we need while the mimic-hifi driver is armed and may
be breaking the VM's TCP path.

Reuses lab.py's PVE auth (lab/pve_auth.py). Requires `requests`.

Usage:
    python ga.py <vmid> --cmd "<powershell-one-liner>"        # inline
    python ga.py <vmid> --ps <file.ps1>                       # script file
    python ga.py <vmid> --cmd "..." --timeout 120 --no-wait   # fire-and-forget

Output: prints "[exit=N]" then the captured stdout, then stderr (prefixed).
"""
import argparse
import base64
import os
import sys
import time

import requests
import urllib3

try:  # Windows console is cp1252; log output may carry em-dashes/arrows. Don't crash.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.environ.get("PVE_HOST", "10.0.240.8:8006")
NODE = os.environ.get("PVE_NODE", "nexus")
BASE = f"https://{HOST}/api2/json"


def _decode(s):
    """out-data is base64 per the QEMU GA spec, but some PVE builds hand back
    already-decoded plain text. Try base64; fall back to the raw string."""
    if not s:
        return ""
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", "replace")
    except Exception:
        return s


def _token():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = r"D:\repos\security\Mimic"
    for p in (os.path.join(repo, "lab"),):
        if p not in sys.path:
            sys.path.insert(0, p)
    from pve_auth import pve_auth_header
    return pve_auth_header()


def run(vmid, ps_text, timeout, wait=True):
    H = _token()
    base = f"{BASE}/nodes/{NODE}/qemu/{vmid}/agent"
    # Match cmd_prep's proven shape: powershell -NoProfile -Command "<script>" passed
    # as a single argv element (requests sends it as one form field = one arg). This
    # PVE captures stdout/stderr by default; no capture-output field.
    cmd = [
        ("command", "powershell.exe"), ("command", "-NoProfile"),
        ("command", "-Command"), ("command", ps_text),
    ]
    r = requests.post(f"{base}/exec", headers=H, verify=False, data=cmd, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"ERROR exec HTTP {r.status_code}: {r.text[:400]}")
    data = r.json().get("data")
    if not data or "pid" not in data:
        sys.exit(f"ERROR exec: no pid in response: {r.text[:400]}")
    pid = data["pid"]
    if not wait:
        print(f"[pid={pid}] (no-wait)")
        return 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        d = requests.get(f"{base}/exec-status", headers=H, verify=False,
                         params={"pid": pid}, timeout=15).json().get("data")
        if d and d.get("exited"):
            out = _decode(d.get("out-data", ""))
            err = _decode(d.get("err-data", ""))
            print(f"[exit={d.get('exitcode')}]")
            if out.strip():
                print(out)
            if err.strip():
                print("---stderr---")
                print(err)
            return d.get("exitcode", 0) or 0
    print(f"[TIMEOUT after {timeout}s, pid={pid} still running]")
    return 124


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vmid", type=int)
    ap.add_argument("--cmd")
    ap.add_argument("--ps")
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--no-wait", action="store_true")
    a = ap.parse_args()
    if a.ps:
        with open(a.ps, "r", encoding="utf-8") as f:
            ps_text = f.read()
    elif a.cmd:
        ps_text = a.cmd
    else:
        sys.exit("need --cmd or --ps")
    sys.exit(run(a.vmid, ps_text, a.timeout, wait=not a.no_wait))


if __name__ == "__main__":
    main()
