# HMDXIN Service Setup Script
# Run as Administrator on HMDXIN

Write-Host "=== Setting up services for packet capture ===" -ForegroundColor Cyan

# 1. WinRM (HTTP 5985, HTTPS 5986)
Write-Host "`n[1/8] Enabling WinRM..." -ForegroundColor Yellow
Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force 2>$null
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
Write-Host "  WinRM enabled on ports 5985/5986" -ForegroundColor Green

# 2. OpenSSH Server
Write-Host "`n[2/8] Installing OpenSSH Server..." -ForegroundColor Yellow
$sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($sshCapability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
# Configure SSH to allow password auth
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfig) {
    $content = Get-Content $sshdConfig
    $content = $content -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes'
    $content | Set-Content $sshdConfig
    Restart-Service sshd
}
Write-Host "  OpenSSH Server enabled on port 22" -ForegroundColor Green

# 3. IIS (HTTP 80, HTTPS 443)
Write-Host "`n[3/8] Installing IIS..." -ForegroundColor Yellow
$iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
if ($iisFeature.State -ne 'Enabled') {
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures -All -NoRestart
}
Start-Service W3SVC 2>$null
Write-Host "  IIS enabled on ports 80/443" -ForegroundColor Green

# 4. SNMP Service
Write-Host "`n[4/8] Installing SNMP..." -ForegroundColor Yellow
$snmpFeature = Get-WindowsCapability -Online | Where-Object Name -like 'SNMP*'
if ($snmpFeature.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0 2>$null
}
# SNMP service may need manual install via Windows Features
Write-Host "  SNMP client installed (full SNMP service requires Windows Features)" -ForegroundColor Yellow

# 5. LLMNR (Link-Local Multicast Name Resolution) - Enabled by default
Write-Host "`n[5/8] Checking LLMNR..." -ForegroundColor Yellow
$llmnrDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
if ($llmnrDisabled.EnableMulticast -eq 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 1
    Write-Host "  LLMNR re-enabled" -ForegroundColor Green
} else {
    Write-Host "  LLMNR already enabled (port 5355/UDP)" -ForegroundColor Green
}

# 6. mDNS (Bonjour) - Part of DNS Client
Write-Host "`n[6/8] Checking mDNS..." -ForegroundColor Yellow
Write-Host "  mDNS handled by DNS Client service (port 5353/UDP)" -ForegroundColor Green

# 7. SSDP Discovery
Write-Host "`n[7/8] Enabling SSDP Discovery..." -ForegroundColor Yellow
Set-Service SSDPSRV -StartupType Automatic
Start-Service SSDPSRV
Write-Host "  SSDP Discovery enabled (port 1900/UDP)" -ForegroundColor Green

# 8. WSD (Function Discovery)
Write-Host "`n[8/8] Enabling WS-Discovery..." -ForegroundColor Yellow
Set-Service FDResPub -StartupType Automatic
Start-Service FDResPub
Set-Service fdPHost -StartupType Automatic
Start-Service fdPHost
Write-Host "  WS-Discovery enabled (port 3702/UDP)" -ForegroundColor Green

# Open firewall for all services
Write-Host "`n=== Configuring Firewall ===" -ForegroundColor Cyan
# WinRM
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985 2>$null
netsh advfirewall firewall add rule name="WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986 2>$null
# SSH
netsh advfirewall firewall add rule name="OpenSSH" dir=in action=allow protocol=TCP localport=22 2>$null
# IIS
netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80 2>$null
netsh advfirewall firewall add rule name="HTTPS" dir=in action=allow protocol=TCP localport=443 2>$null
# SNMP
netsh advfirewall firewall add rule name="SNMP" dir=in action=allow protocol=UDP localport=161 2>$null
# Discovery protocols
netsh advfirewall firewall add rule name="LLMNR" dir=in action=allow protocol=UDP localport=5355 2>$null
netsh advfirewall firewall add rule name="mDNS" dir=in action=allow protocol=UDP localport=5353 2>$null
netsh advfirewall firewall add rule name="SSDP" dir=in action=allow protocol=UDP localport=1900 2>$null
netsh advfirewall firewall add rule name="WSD" dir=in action=allow protocol=UDP localport=3702 2>$null

Write-Host "`nFirewall rules added" -ForegroundColor Green

# Show final status
Write-Host "`n=== Service Status ===" -ForegroundColor Cyan
$services = @(
    @{Name="WinRM"; Port="5985/5986"; Service="WinRM"},
    @{Name="SSH"; Port="22"; Service="sshd"},
    @{Name="IIS"; Port="80/443"; Service="W3SVC"},
    @{Name="SSDP"; Port="1900"; Service="SSDPSRV"},
    @{Name="WSD"; Port="3702"; Service="FDResPub"}
)

foreach ($svc in $services) {
    $status = Get-Service -Name $svc.Service -ErrorAction SilentlyContinue
    if ($status.Status -eq 'Running') {
        Write-Host "  $($svc.Name) ($($svc.Port)): Running" -ForegroundColor Green
    } else {
        Write-Host "  $($svc.Name) ($($svc.Port)): $($status.Status)" -ForegroundColor Red
    }
}

Write-Host "`n=== Listening Ports ===" -ForegroundColor Cyan
netstat -an | Select-String "LISTENING" | Select-String "22|80|443|161|1900|3702|5355|5353|5985|5986"

Write-Host "`nSetup complete! Run the capture script next." -ForegroundColor Cyan
