$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# T2 CHECKSUMS-TAMPER via script invocation (& ./install.ps1).
# Mutates exactly 1 hex char in the published checksums.txt AFTER download.
# Asserts: exit != 0, output names 'checksum mismatch', nothing installed.
# Tamper proof: $script:Tampered must be >= 1 (zero = HARNESS-MISFIRE exit 99);
# clean zip hash vs published want logged (must MATCH pre-tamper, proving we compare
# against the right hash), tampered want + actual got logged separately.
$Tag = 'T2-SUMTAMPER-CALL'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$Sut = Join-Path $RepoRoot 'install.ps1'
$global:AnpuTamperLog = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t2-marker.log'
if (Test-Path $global:AnpuTamperLog) { Remove-Item -Force $global:AnpuTamperLog }
$script:ZipName = 'anpu_0.5.2_windows_amd64.zip'
Write-Host "$Tag host PSVersion=$($PSVersionTable.PSVersion) Edition=$($PSVersionTable.PSEdition)"
Write-Host "$Tag SUT=$Sut"
Write-Host "$Tag SUT-sha256=$((Get-FileHash -Path $Sut -Algorithm SHA256).Hash.ToLower())"
$env:ANPU_VERSION = 'v0.5.2'
$env:ANPU_INSTALL_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'anpu-tamper-t2'
if (Test-Path $env:ANPU_INSTALL_DIR) { Remove-Item -Recurse -Force $env:ANPU_INSTALL_DIR }
if (Test-Path $env:ANPU_INSTALL_DIR) { Write-Host "$Tag HARNESS-MISFIRE: install dir still present"; exit 99 }
Write-Host "$Tag installDir=$env:ANPU_INSTALL_DIR (verified absent pre-run)"
function Invoke-WebRequest {
  param($Uri, $OutFile)
  Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Uri -OutFile $OutFile
  if ("$OutFile" -like '*checksums.txt') {
    # NOTE: child-scope reset (see T1) — marker file is the cross-scope proof.
    Add-Content -Path $global:AnpuTamperLog -Value "TAMPER-HOOK file=$OutFile"
    $origLines = [System.IO.File]::ReadAllLines($OutFile)
    $entry = $origLines | Where-Object { $_ -like "*$script:ZipName" } | Select-Object -First 1
    if ($null -eq $entry) { Write-Host "$Tag HARNESS-MISFIRE: zip entry not found in checksums.txt"; exit 99 }
    $want0 = ($entry -split '\s+')[0]
    $zipPath = Join-Path ([System.IO.Path]::GetDirectoryName($OutFile)) $script:ZipName
    if (-not (Test-Path $zipPath)) { Write-Host "$Tag HARNESS-MISFIRE: zip not yet downloaded when sums arrived"; exit 99 }
    $gotClean = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    Write-Host "$Tag BASELINE clean-zip-sha256=$gotClean published-want=$want0 match=$($gotClean -eq $want0.ToLower())"
    if ($gotClean -ne $want0.ToLower()) { Write-Host "$Tag HARNESS-MISFIRE: clean download does not match published hash (fixture broken)"; exit 99 }
    $lines = @($origLines)
    $mut = 0
    for ($i = 0; $i -lt $lines.Length; $i++) {
      if ($lines[$i] -like "*$script:ZipName") {
        $orig = $lines[$i]
        if ($orig[0] -eq 'a') { $n = 'b' } else { $n = 'a' }
        $lines[$i] = $n + $orig.Substring(1)
        $mut++
        Add-Content -Path $global:AnpuTamperLog -Value "TAMPER-FIRED before=[$orig] after=[$($lines[$i])]"
        Write-Host "$Tag TAMPER-FIRED before=[$orig] after=[$($lines[$i])]"
      }
    }
    if ($mut -lt 1) { Write-Host "$Tag HARNESS-MISFIRE: zero lines mutated"; exit 99 }
    [System.IO.File]::WriteAllLines($OutFile, $lines)
    $afterHash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "$Tag checksums.txt-sha256-after-tamper=$afterHash mutated-lines=$mut"
  }
}
$transcript = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-tamper-t2-{0}.log" -f [guid]::NewGuid().ToString('N'))
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
if ($m.Success) { Write-Host "$Tag evidence installer-want=$($m.Groups[1].Value) installer-got=$($m.Groups[2].Value)" }
$exe = Join-Path $env:ANPU_INSTALL_DIR 'anpu.exe'
$exists = Test-Path $exe
Write-Host "$Tag installed-exists=$exists"
if (($code -ne 0) -and ($txt -match 'checksum mismatch') -and (-not $exists)) { Write-Host "$Tag RESULT=PASS (sums tamper exercised: right-hash baseline proved, mismatch named, abort pre-install)"; exit $code }
Write-Host "$Tag RESULT=FAIL code=$code mismatch-present=$($txt -match 'checksum mismatch') exists=$exists"
if ($code -ne 0) { exit $code }
exit 1
