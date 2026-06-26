# uninstall.ps1 — remove the mimic-hifi NDIS LWF. Elevated.
$ErrorActionPreference = 'Continue'
& netcfg -v -u MS_MimicHiFi
Write-Host "mimic-hifi LWF removed. (Optional) disable test-signing: bcdedit /set testsigning off + reboot." -ForegroundColor Yellow
