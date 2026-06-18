#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Provision mimic-lab-win11 for MSMQ QueueJumper (CVE-2023-21554) testing.

.DESCRIPTION
  Idempotent setup on Windows 11 golden clone:
    - Install Microsoft Message Queuing (MSMQ)
    - Optional SMB enum hint share (public\notes.txt)
    - Firewall rules for lab VLAN assessment (not :2222 — Windows mgmt via RDP/console)

  PATCH PINNING: snapshot this VM at a build KNOWN vulnerable to CVE-2023-21554.
  Record OS build + installed KBs in docs/vulnlab/ground-truth.md before assessor runs.

.PARAMETER SkipEnumShare
  Do not create the SMB hint share.

.PARAMETER LabSubnet
  CIDR allowed inbound for assessment ports (default 10.0.250.0/24).
#>
param(
    [switch]$SkipEnumShare,
    [string]$LabSubnet = "10.0.250.0/24"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "[provision_win11] $msg" }

Write-Step "OS: $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName) build $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber)"

Write-Step "Installing MSMQ (Message Queuing) feature"
$feature = Get-WindowsOptionalFeature -Online -FeatureName MSMQ-Server -ErrorAction SilentlyContinue
if ($feature -and $feature.State -ne "Enabled") {
    Enable-WindowsOptionalFeature -Online -FeatureName MSMQ-Server -All -NoRestart
} elseif (-not $feature) {
    # Server-style fallback
    Install-WindowsFeature -Name MSMQ-Server -ErrorAction SilentlyContinue | Out-Null
}
Restart-Service MSMQ -ErrorAction SilentlyContinue
Set-Service MSMQ -StartupType Automatic

Write-Step "Lab firewall: allow assessment from $LabSubnet (operator should still isolate VLAN)"
# Assessors hit 135/445/139/3389/443/1801 — not a substitute for network segmentation.
$ruleName = "Mimic-VulnLab-Assess-In"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
        -RemoteAddress $LabSubnet -Profile Any | Out-Null
}

if (-not $SkipEnumShare) {
    Write-Step "Creating optional SMB hint share PUBLIC"
    if (-not (Get-SmbShare -Name "PUBLIC" -ErrorAction SilentlyContinue)) {
        $sharePath = "C:\lab_public"
        New-Item -ItemType Directory -Force -Path $sharePath | Out-Null
        @"
Legacy infrastructure note (internal):
A message-queue service may still be listening on TCP 1801.
Verify with a full port scan — not visible on default top ports.
"@ | Set-Content -Path (Join-Path $sharePath "notes.txt") -Encoding UTF8
        New-SmbShare -Name "PUBLIC" -Path $sharePath -FullAccess "Everyone" | Out-Null
    }
}

Write-Step "Record build + KB list for ground-truth.md:"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, InstalledOn
Write-Step "Validate: nmap -sV -p 1801 <this-host>  (expect msrpc / Message Queuing)"
Write-Step "done"