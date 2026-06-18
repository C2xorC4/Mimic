"""
Proxmox API token resolution for Mimic lab tooling.

Priority:
  1. PVE_TOKEN environment variable (full "user@realm!name=secret" value)
  2. PVEAPIToken=... in infra/packer/windows/make_autounattend_isos.py
     (same source capture.ps1 uses via -TokenFile)
  3. PVE_TOKEN_FILE env override for the fallback file path
"""

from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TOKEN_FILE = REPO_ROOT / "infra" / "packer" / "windows" / "make_autounattend_isos.py"
_TOKEN_RE = re.compile(r"PVEAPIToken=([^\"']+)")


def resolve_pve_token() -> str:
    tok = os.environ.get("PVE_TOKEN", "").strip()
    if tok:
        return tok

    path = Path(os.environ.get("PVE_TOKEN_FILE", DEFAULT_TOKEN_FILE))
    if not path.is_file():
        raise SystemExit(
            "ERROR: PVE_TOKEN not set and token file not found:\n"
            f"  {path}\n"
            "Rotate/update TOKEN_HEADER in make_autounattend_isos.py (same as capture.ps1), "
            "or set PVE_TOKEN for this shell."
        )

    text = path.read_text(encoding="utf-8", errors="replace")
    match = _TOKEN_RE.search(text)
    if not match:
        raise SystemExit(f"ERROR: no PVEAPIToken= line in {path}")

    return match.group(1).strip()


def pve_auth_header() -> dict[str, str]:
    return {"Authorization": f"PVEAPIToken={resolve_pve_token()}"}