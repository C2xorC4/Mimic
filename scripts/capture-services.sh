#!/bin/bash
# Capture service responses from HMDXIN
# Run this AFTER running hmdxin-setup-services.ps1 on the Windows machine

set -e

TARGET="${1:-10.0.250.7}"  # HMDXIN Windows 11 IP (hmdxin.blackic.systems)
INTERFACE="${2:-enp73s0f1}"
CAPTURE_DIR="./captures/hmdxin-services-$(date +%Y%m%d-%H%M%S)"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges for packet capture."
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
    exit 1
fi

echo "=== Service Capture Script ==="
echo "Target: $TARGET"
echo "Capture dir: $CAPTURE_DIR"
echo "Interface: $INTERFACE"
echo ""

mkdir -p "$CAPTURE_DIR"

# Helper function for timed capture with probing
capture_and_probe() {
    local name="$1"
    local ports="$2"
    local filter="$3"
    shift 3

    echo ""
    echo "=== $name ($ports) ==="

    local pcap="$CAPTURE_DIR/${name}.pcapng"

    # Start tcpdump in background
    echo "[*] Starting capture..."
    tcpdump -U -i "$INTERFACE" -w "$pcap" "$filter" >/dev/null 2>&1 &
    local capture_pid=$!
    sleep 1

    # Verify capture started
    if ! kill -0 $capture_pid 2>/dev/null; then
        echo "[!] Capture failed to start for $name"
        return 1
    fi
    echo "[*] Capture running (pid $capture_pid)"

    # Run probe commands
    echo "[*] Probing $name..."
    for cmd in "$@"; do
        echo "    Running: ${cmd:0:60}..."
        eval "$cmd" 2>&1 || true
    done

    # Wait for responses
    sleep 2

    # Stop capture
    echo "[*] Stopping capture..."
    kill -TERM $capture_pid 2>/dev/null || true
    wait $capture_pid 2>/dev/null || true

    # Verify file
    if [[ -f "$pcap" && -s "$pcap" ]]; then
        local size=$(stat -c%s "$pcap")
        echo "[+] $name capture complete: $pcap ($size bytes)"
    else
        echo "[!] $name capture empty or failed"
    fi
}

# 1. WinRM
capture_and_probe "winrm" "5985/5986" \
    "host $TARGET and (port 5985 or port 5986)" \
    "curl -s --connect-timeout 5 http://$TARGET:5985/wsman -o /dev/null" \
    "nmap -sV -p 5985,5986 $TARGET >> $CAPTURE_DIR/winrm-nmap.txt"

# 2. SSH
capture_and_probe "ssh" "22" \
    "host $TARGET and port 22" \
    "nc -w5 $TARGET 22 < /dev/null >> $CAPTURE_DIR/ssh-banner.txt" \
    "nmap -sV -p 22 --script ssh2-enum-algos $TARGET >> $CAPTURE_DIR/ssh-nmap.txt"

# 3. HTTP
capture_and_probe "http" "80/443" \
    "host $TARGET and (port 80 or port 443)" \
    "curl -s --connect-timeout 5 -I http://$TARGET/ >> $CAPTURE_DIR/http-headers.txt" \
    "curl -s --connect-timeout 5 http://$TARGET/ >> $CAPTURE_DIR/http-index.html" \
    "nmap -sV -p 80,443 $TARGET >> $CAPTURE_DIR/http-nmap.txt"

# 4. SNMP
capture_and_probe "snmp" "161/UDP" \
    "host $TARGET and udp port 161" \
    "snmpget -v2c -c public -t 2 $TARGET 1.3.6.1.2.1.1.1.0 >> $CAPTURE_DIR/snmp-sysdescr.txt" \
    "nmap -sU -p 161 --script snmp-sysdescr $TARGET >> $CAPTURE_DIR/snmp-nmap.txt"

# 5. LLMNR
capture_and_probe "llmnr" "5355/UDP" \
    "host $TARGET and udp port 5355" \
    "nmap -sU -p 5355 --script llmnr-resolve --script-args llmnr-resolve.hostname=HMDXIN $TARGET >> $CAPTURE_DIR/llmnr-nmap.txt"

# 6. mDNS
capture_and_probe "mdns" "5353/UDP" \
    "udp port 5353" \
    "nmap -sU -p 5353 --script dns-service-discovery $TARGET >> $CAPTURE_DIR/mdns-nmap.txt"

# 7. SSDP
capture_and_probe "ssdp" "1900/UDP" \
    "udp port 1900" \
    "echo -e 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ssdp:discover\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' | nc -u -w3 $TARGET 1900 >> $CAPTURE_DIR/ssdp-response.txt" \
    "nmap -sU -p 1900 $TARGET >> $CAPTURE_DIR/ssdp-nmap.txt"

# 8. WSD
capture_and_probe "wsd" "3702/UDP" \
    "host $TARGET and udp port 3702" \
    "nmap -sU -p 3702 $TARGET >> $CAPTURE_DIR/wsd-nmap.txt"

# Summary
echo ""
echo "=== Capture Summary ==="
ls -la "$CAPTURE_DIR/"
echo ""
pcap_count=$(find "$CAPTURE_DIR" -name "*.pcapng" -size +0 2>/dev/null | wc -l)
echo "Successful pcapng captures: $pcap_count"
echo "Captures saved to: $CAPTURE_DIR"
