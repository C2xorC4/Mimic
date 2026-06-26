# sign-test.ps1 — lab test-signing for mimic-hifi.sys (+ .cat). Elevated.
# Creates a self-signed code-signing cert, trusts it (Root + TrustedPublisher),
# builds + signs the catalog, signs the .sys, and enables test-signing (reboot needed).
# LAB ONLY — test-signing weakens Secure Boot/HVCI. Production = MS attestation signing.
param(
  [string]$DriverDir = (Join-Path $PSScriptRoot '..\mimichifi'),
  [string]$CertName  = 'Mimic HiFi Test CodeSign'
)
$ErrorActionPreference = 'Stop'
$sdkBin = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
          Sort-Object FullName -Descending | Select-Object -First 1
$signtool = $sdkBin.FullName
$inf2cat  = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\$($sdkBin.Directory.Parent.Name)\x86\Inf2Cat.exe"
$sys = Join-Path $DriverDir 'x64\Release\mimichifi.sys'
$inf = Join-Path $DriverDir 'mimichifi.inf'
$pkg = Split-Path $sys

# 1. self-signed code-signing cert (CN), reuse if present
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=$CertName" | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
            -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')   # EKU: Code Signing
}
# 2. trust it (kernel driver load needs the cert in Root + TrustedPublisher)
$tp = "Cert:\LocalMachine\TrustedPublisher"; $rt = "Cert:\LocalMachine\Root"
foreach ($store in $tp,$rt) {
  if (-not (Get-ChildItem $store | Where-Object Thumbprint -eq $cert.Thumbprint)) {
    $s = Get-Item $store.Replace('Cert:\','Cert:\'); $st = New-Object System.Security.Cryptography.X509Certificates.X509Store(($store -replace '.*\\',''),'LocalMachine')
    $st.Open('ReadWrite'); $st.Add($cert); $st.Close()
  }
}
# 3. catalog (inf2cat) + sign .cat + sign .sys
& $inf2cat /driver:$pkg /os:10_X64 /verbose
& $signtool sign /fd SHA256 /a /s My /n $CertName /tr http://timestamp.digicert.com /td SHA256 (Join-Path $pkg 'mimichifi.cat')
& $signtool sign /fd SHA256 /a /s My /n $CertName /tr http://timestamp.digicert.com /td SHA256 $sys
# 4. enable test-signing
bcdedit /set testsigning on | Out-Null
Write-Host "Signed. REBOOT to apply test-signing, then run install.ps1." -ForegroundColor Yellow
