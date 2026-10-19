$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# T1 ZIP-TAMPER via script invocation (& ./install.ps1).
# Asserts: exit != 0, output names 'checksum mismatch', nothing installed.
# Tamper proof: $script:Tampered counter must be >= 1 (guard: zero matches = HARNESS-MISFIRE exit 99),
# zip sha256 logged before AND after appending 1 byte, want-vs-got both printed.
$Tag = 'T1-ZIPTAMPER-CALL'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$Sut = Join-Path $RepoRoot 'install.ps1'
$script:Tampered = 0
$global:AnpuTamperLog = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t1-marker.log'
if (Test-Path $global:AnpuTamperLog) { Remove-Item -Force $global:AnpuTamperLog }
Write-Host "$Tag host PSVersion=$($PSVersionTable.PSVersion) Edition=$($PSVersionTable.PSEdition)"
Write-Host "$Tag SUT=$Sut"
Write-Host "$Tag SUT-sha256=$((Get-FileHash -Path $Sut -Algorithm SHA256).Hash.ToLower())"
$env:ANPU_VERSION = 'v0.5.2'
$env:ANPU_INSTALL_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t1'
if (Test-Path $env:ANPU_INSTALL_DIR) { Remove-Item -Recurse -Force $env:ANPU_INSTALL_DIR }
if (Test-Path $env:ANPU_INSTALL_DIR) { Write-Host "$Tag HARNESS-MISFIRE: install dir still present"; exit 99 }
Write-Host "$Tag installDir=$env:ANPU_INSTALL_DIR (verified absent pre-run)"
Write-Host "$Tag cosign-present=$([bool](Get-Command cosign -ErrorAction SilentlyContinue))"
function Invoke-WebRequest {
  param($Uri, $OutFile)
  Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Uri -OutFile $OutFile
  if ("$OutFile" -like '*.zip') {
    $before = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
    # Portable 1-byte append (works on 5.1 Desktop AND pwsh 7 Core):
    # -Encoding Byte exists only on 5.1; use a raw FileStream on both.
    $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    try { $fs.WriteByte(0x41) } finally { $fs.Close() }
    $after = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
    # NOTE: the SUT runs in a child scope, so $script: counters reset there.
    # Marker file = cross-scope tamper proof (survives the child-scope reset).
    Add-Content -Path $global:AnpuTamperLog -Value "TAMPER-FIRED file=$OutFile sha-before=$before sha-after=$after changed=$($before -ne $after)"
    Write-Host "$Tag TAMPER-FIRED file=$OutFile sha-before=$before sha-after=$after changed=$($before -ne $after)"
    if ($before -eq $after) { Write-Host "$Tag HARNESS-MISFIRE: tamper did not change the file"; exit 99 }
  }
}
$transcript = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-tamper-t1-{0}.log" -f [guid]::NewGuid().ToString('N'))
if (Test-Path $transcript) { Remove-Item -Force $transcript }
Start-Transcript -Path $transcript -Force | Out-Null
& $Sut
$code = $LASTEXITCODE
Stop-Transcript | Out-Null
$txt = Get-Content -Raw -Path $transcript
Remove-Item -Force $transcript -ErrorAction SilentlyContinue
$fired = @()
if (Test-Path $global:AnpuTamperLog) { $fired = @(Get-Content -Path $global:AnpuTamperLog) }
Write-Host "$Tag tamper-count=$($fired.Count)"
foreach ($line in $fired) { Write-Host "$Tag marker: $line" }
if ($fired.Count -lt 1) { Write-Host "$Tag HARNESS-MISFIRE: tamper step matched zero files (glob empty)"; exit 99 }
Write-Host "$Tag installer-exit=$code"
$m = [regex]::Match("$txt", 'want ([0-9a-f]+), got ([0-9a-f]+)')
if ($m.Success) { Write-Host "$Tag evidence want=$($m.Groups[1].Value) got=$($m.Groups[2].Value) differ=$($m.Groups[1].Value -ne $m.Groups[2].Value)" }
$exe = Join-Path $env:ANPU_INSTALL_DIR 'anpu.exe'
$exists = Test-Path $exe
Write-Host "$Tag installed-exists=$exists"
if (($code -ne 0) -and ($txt -match 'checksum mismatch') -and (-not $exists)) { Write-Host "$Tag RESULT=PASS (zip tamper exercised: mismatch named, abort pre-install)"; exit $code }
Write-Host "$Tag RESULT=FAIL code=$code mismatch-present=$($txt -match 'checksum mismatch') exists=$exists"
if ($code -ne 0) { exit $code }
exit 1
