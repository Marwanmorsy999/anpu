$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# T3 ZIP-TAMPER via irm|iex (the real user path).
# `exit` inside iex only ends the CHILD powershell.exe process, so this file runs the
# whole scenario in a child: parent asserts on child exit code + child log.
# Asserts: child exit != 0, child log names 'checksum mismatch',
# 'host window survived' (parent alive post-child), nothing installed.
$Tag = 'T3-ZIPTAMPER-IEX'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$Sut = Join-Path $RepoRoot 'install.ps1'
$env:ANPU_SUT = "$Sut"
# Child host follows the parent edition: 5.1 Desktop -> powershell.exe, Core -> pwsh.
$ChildExe = 'powershell.exe'
if ($PSVersionTable.PSEdition -eq 'Core') { $ChildExe = 'pwsh' }
if ($env:ANPU_CHILD_EXE) { $ChildExe = $env:ANPU_CHILD_EXE }
$runId = [guid]::NewGuid().ToString('N')
$childLog = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-tamper-t3-$runId.log")
$childScript = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-tamper-t3-child-$runId.ps1")
if (Test-Path $childLog) { Remove-Item -Force $childLog }
$childBody = @'
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Tag = 'T3-CHILD'
$Sut = $env:ANPU_SUT
if ([string]::IsNullOrWhiteSpace($Sut)) { $Sut = 'https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1' }
$global:AnpuTamperLog = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-tamper-t3-marker-{0}.log" -f [guid]::NewGuid().ToString('N'))
if (Test-Path $global:AnpuTamperLog) { Remove-Item -Force $global:AnpuTamperLog }
Write-Host "$Tag host PSVersion=$($PSVersionTable.PSVersion) Edition=$($PSVersionTable.PSEdition)"
$env:ANPU_VERSION = 'v0.5.2'
$env:ANPU_INSTALL_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t3'
if (Test-Path $env:ANPU_INSTALL_DIR) { Remove-Item -Recurse -Force $env:ANPU_INSTALL_DIR }
if (Test-Path $env:ANPU_INSTALL_DIR) { Write-Host "$Tag HARNESS-MISFIRE: install dir present"; exit 99 }
Write-Host "$Tag installDir=$env:ANPU_INSTALL_DIR (verified absent pre-run)"
function Invoke-WebRequest {
  param($Uri, $OutFile)
  if ($OutFile) {
    Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Uri -OutFile $OutFile
    if ("$OutFile" -like '*.zip') {
      $before = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
      $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
      try { $fs.WriteByte(0x41) } finally { $fs.Close() }
      $after = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
      Add-Content -Path $global:AnpuTamperLog -Value "TAMPER-FIRED sha-before=$before sha-after=$after changed=$($before -ne $after)"
      Write-Host "$Tag TAMPER-FIRED sha-before=$before sha-after=$after changed=$($before -ne $after)"
      if ($before -eq $after) { Write-Host "$Tag HARNESS-MISFIRE: tamper inert"; exit 99 }
    }
  } else {
    Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Uri
  }
}
Write-Host "$Tag invoking: SUT=$Sut (repo checkout; iex of the local file)"
Get-Content -Raw -Path $Sut | Invoke-Expression
$code = $LASTEXITCODE
$fired = @()
if (Test-Path $global:AnpuTamperLog) { $fired = @(Get-Content -Path $global:AnpuTamperLog) }
Write-Host "$Tag POST-IEX LASTEXITCODE=$code tamper-count=$($fired.Count)"
foreach ($line in $fired) { Write-Host "$Tag marker: $line" }
if ($fired.Count -lt 1) { Write-Host "$Tag HARNESS-MISFIRE: tamper matched zero files"; exit 99 }
exit $code
'@
Set-Content -Path $childScript -Value $childBody -NoNewline
Write-Host "$Tag parent PSVersion=$($PSVersionTable.PSVersion) Edition=$($PSVersionTable.PSEdition) (parent alive pre-child)"
$ErrorActionPreference = 'Continue'
& $ChildExe -NoProfile -ExecutionPolicy Bypass -File $childScript *> $childLog
$childCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Write-Host "$Tag parent alive post-child (host window survived: True)"
Write-Host "$Tag child-exit=$childCode"
$log = Get-Content -Raw -Path $childLog
Write-Host "----- child log begin -----"
Write-Host $log
Write-Host "----- child log end -----"
$exists = Test-Path (Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t3\anpu.exe')
Write-Host "$Tag installed-exists=$exists"
if (($childCode -ne 0) -and ($log -match 'checksum mismatch') -and ($log -match 'TAMPER-FIRED') -and (-not $exists)) { Write-Host "$Tag RESULT=PASS (iex tamper exercised: child aborted $childCode, host survived, nothing installed)"; exit $childCode }
Write-Host "$Tag RESULT=FAIL child=$childCode mismatch-present=$($log -match 'checksum mismatch') tamper-present=$($log -match 'TAMPER-FIRED') exists=$exists"
if ($childCode -ne 0) { exit $childCode }
exit 1
