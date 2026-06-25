# install.ps1 — install the mimic-hifi NDIS LWF. Elevated. Requires test-signing on
# (run sign-test.ps1 + reboot first). netcfg binds the filter into the network stack.
param([string]$DriverDir = (Join-Path $PSScriptRoot '..\mimichifi'))
$ErrorActionPreference = 'Stop'
$inf = (Resolve-Path (Join-Path $DriverDir 'mimichifi.inf')).Path
# Component id = the INF's manufacturer model key (MS_MimicHiFi).
& netcfg -v -l $inf -c s -i MS_MimicHiFi
if ($LASTEXITCODE -ne 0) { throw "netcfg install failed ($LASTEXITCODE) — check test-signing + signature trust" }
Write-Host "mimic-hifi LWF installed. Control device: \\.\MimicHiFi (driver pass-through until mimic arms it)." -ForegroundColor Green
Write-Host "Verify: 'sc query mimichifi' and 'netcfg -q MS_MimicHiFi'." -ForegroundColor Green
