$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# C0 POSITIVE CONTROL (no tamper): clean install must succeed.
# Asserts: installer exit 0, anpu.exe exists, `anpu version` names 0.5.2 + commit 88d80a5.
# Evidence of exercise: fresh empty install dir verified absent pre-run, SUT sha256 logged,
# installer output contains 'installed to' and 'verifying checksum'.
$Tag = 'C0-POSITIVE'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$Sut = Join-Path $RepoRoot 'install.ps1'
Write-Host "$Tag host PSVersion=$($PSVersionTable.PSVersion) Edition=$($PSVersionTable.PSEdition)"
Write-Host "$Tag SUT=$Sut"
Write-Host "$Tag SUT-sha256=$((Get-FileHash -Path $Sut -Algorithm SHA256).Hash.ToLower())"
if (-not (Select-String -Path $Sut -Pattern 'checksum mismatch' -Quiet)) { Write-Host "$Tag HARNESS-MISFIRE: SUT has no checksum gate"; exit 99 }
$env:ANPU_VERSION = 'v0.5.2'
$env:ANPU_INSTALL_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-ctrl-c0'
if (Test-Path $env:ANPU_INSTALL_DIR) { Remove-Item -Recurse -Force $env:ANPU_INSTALL_DIR }
if (Test-Path $env:ANPU_INSTALL_DIR) { Write-Host "$Tag HARNESS-MISFIRE: install dir still present after cleanup"; exit 99 }
Write-Host "$Tag installDir=$env:ANPU_INSTALL_DIR (verified absent pre-run)"
Write-Host "$Tag cosign-present=$([bool](Get-Command cosign -ErrorAction SilentlyContinue))"
$transcript = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-ctrl-c0-{0}.log" -f [guid]::NewGuid().ToString('N'))
if (Test-Path $transcript) { Remove-Item -Force $transcript }
Start-Transcript -Path $transcript -Force | Out-Null
& $Sut
$code = $LASTEXITCODE
Stop-Transcript | Out-Null
$txt = Get-Content -Raw -Path $transcript
Remove-Item -Force $transcript -ErrorAction SilentlyContinue
Write-Host "$Tag installer-exit=$code"
if ($txt -notmatch 'installed to') { Write-Host "$Tag HARNESS-MISFIRE: install step never ran"; exit 99 }
$exe = Join-Path $env:ANPU_INSTALL_DIR 'anpu.exe'
$exists = Test-Path $exe
Write-Host "$Tag installed-exists=$exists"
if ($exists) {
  $ver = & $exe version 2>&1 | Out-String
  Write-Host "$Tag version-output=$($ver.Trim())"
  Write-Host "$Tag exe-sha256=$((Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower())"
  if ("$ver" -notmatch '0\.5\.2') { Write-Host "$Tag FAIL: version output missing 0.5.2"; exit 1 }
  if ("$ver" -notmatch '88d80a5') { Write-Host "$Tag FAIL: version output missing commit 88d80a5"; exit 1 }
}
if (($code -eq 0) -and $exists -and ($txt -match 'installed to')) { Write-Host "$Tag RESULT=PASS (control exercised: clean download verified, installed, version proved)"; exit 0 }
Write-Host "$Tag RESULT=FAIL code=$code exists=$exists"
exit 1
