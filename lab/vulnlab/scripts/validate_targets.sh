#!/usr/bin/env bash
# Operator pre-flight checks from attacker VM or any lab-VLAN host with nmap.
# Reads IPs from lab/vulnlab/network.local.yaml (or network.example.yaml).

set -euo pipefail

VULNLAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CFG="${VULNLAB_NETWORK:-$VULNLAB_DIR/network.local.yaml}"
[[ -f "$CFG" ]] || CFG="$VULNLAB_DIR/network.example.yaml"

if ! command -v nmap >/dev/null; then
  echo "nmap required"; exit 1
fi

parse_ip() {
  local key=$1
  awk -v k="$key" '
    $0 ~ "^  " k ":$" { found=1; next }
    found && /^  [a-z]/ { exit }
    found && /ip:/ { print $2; exit }
  ' "$CFG"
}

WIN11="$(parse_ip win11)"
BARE="$(parse_ip linux_bare)"
MIMIC="$(parse_ip linux_mimic)"

check() {
  local label=$1 ip=$2
  echo "=== $label ($ip) ==="
  nmap -Pn -O --osscan-guess "$ip" 2>/dev/null | sed -n '/Running:/,/OS details:/p' || true
  nmap -Pn -sV -p 21,22,1801,445 "$ip" 2>/dev/null | sed -n '/PORT /,$p' || true
  echo
}

echo "Vuln lab validation (operator) — cfg=$CFG"
echo

check "win11" "$WIN11"
check "linux-bare" "$BARE"
check "linux-mimic" "$MIMIC"

echo "--- RoE reminder: port 2222 is out of scope ---"
echo "linux-mimic expects: nmap -O => Windows; port 21 => vsftpd; port 22 => closed"