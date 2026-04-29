# HMDXIN Service Revert Script
# Run as Administrator on HMDXIN to disable services enabled for capture

Write-Host "=== Reverting services to pre-capture state ===" -ForegroundColor Cyan

# 1. WinRM
Write-Host "`n[1/8] Disabling WinRM..." -ForegroundColor Yellow
Stop-Service WinRM -Force 2>$null
Set-Service WinRM -StartupType Manual
Disable-PSRemoting -Force 2>$null
Write-Host "  WinRM disabled" -ForegroundColor Green

# 2. OpenSSH Server - SKIP (needed for workflow)
Write-Host "`n[2/8] Skipping OpenSSH Server (needed for workflow)" -ForegroundColor Cyan

# 3. IIS
Write-Host "`n[3/8] Stopping IIS..." -ForegroundColor Yellow
Stop-Service W3SVC -Force 2>$null
Set-Service W3SVC -StartupType Manual 2>$null
# Optionally remove: Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart
Write-Host "  IIS stopped (not uninstalled)" -ForegroundColor Green

# 4. SNMP - typically not a service, just client tools
Write-Host "`n[4/8] SNMP client tools remain installed (no service to stop)" -ForegroundColor Yellow

# 5. LLMNR - leave enabled (default Windows behavior)
Write-Host "`n[5/8] LLMNR left enabled (Windows default)" -ForegroundColor Yellow

# 6. mDNS - part of DNS Client, leave as-is
Write-Host "`n[6/8] mDNS left as-is (DNS Client service)" -ForegroundColor Yellow

# 7. SSDP Discovery
Write-Host "`n[7/8] Disabling SSDP Discovery..." -ForegroundColor Yellow
Stop-Service SSDPSRV -Force 2>$null
Set-Service SSDPSRV -StartupType Manual
Write-Host "  SSDP Discovery disabled" -ForegroundColor Green

# 8. WS-Discovery
Write-Host "`n[8/8] Disabling WS-Discovery..." -ForegroundColor Yellow
Stop-Service FDResPub -Force 2>$null
Set-Service FDResPub -StartupType Manual
Stop-Service fdPHost -Force 2>$null
Set-Service fdPHost -StartupType Manual
Write-Host "  WS-Discovery disabled" -ForegroundColor Green

# Remove firewall rules
Write-Host "`n=== Removing Firewall Rules ===" -ForegroundColor Cyan
$rules = @(
    "WinRM HTTP", "WinRM HTTPS",
    # "OpenSSH",  # Keep SSH for workflow
    "HTTP", "HTTPS",
    "SNMP",
    "LLMNR", "mDNS", "SSDP", "WSD"
)
foreach ($rule in $rules) {
    netsh advfirewall firewall delete rule name="$rule" 2>$null
}
Write-Host "Firewall rules removed" -ForegroundColor Green

# Show final status
Write-Host "`n=== Service Status ===" -ForegroundColor Cyan
$services = @(
    @{Name="WinRM"; Service="WinRM"},
    # SSH excluded - kept for workflow
    @{Name="IIS"; Service="W3SVC"},
    @{Name="SSDP"; Service="SSDPSRV"},
    @{Name="WSD"; Service="FDResPub"}
)

foreach ($svc in $services) {
    $status = Get-Service -Name $svc.Service -ErrorAction SilentlyContinue
    if ($status) {
        $color = if ($status.Status -eq 'Stopped') { "Green" } else { "Yellow" }
        Write-Host "  $($svc.Name): $($status.Status)" -ForegroundColor $color
    }
}

Write-Host "`n=== Optional: Full Uninstall ===" -ForegroundColor Cyan
Write-Host "To completely remove IIS, run:" -ForegroundColor Yellow
Write-Host "  Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart"

Write-Host "`nRevert complete." -ForegroundColor Cyan
