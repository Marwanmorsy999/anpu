<#
.SYNOPSIS
  Windows tamper harness for install.ps1.

.DESCRIPTION
  Serves fixture trees over a local HTTP server and runs the real
  install.ps1 (invoked with -File) against them. Cases:

    clean          positive control: pristine archive + pristine
                   checksums.txt must install and the binary must run.
    zip-tamper     a tampered archive must abort non-zero and install
                   nothing.
    sums-tamper    a tampered checksums.txt must abort non-zero and
                   install nothing.
    control-wrong  a DELIBERATELY WRONG control: pristine fixtures are
                   served but the case expects an abort, so the installer
                   legitimately succeeds. This case must be reported by
                   the harness as verdict "failure" - it proves the
                   abort detection is not vacuously true.

  Every tamper case prints the hash before and after the mutation and
  fails hard if the two are equal (an inert mutation would make the
  whole test meaningless).

  Each case prints a machine-readable line:
    TAMPER-CASE name=<case> observed=<abort|installed> exit=<code> verdict=<success|failure>

  The process exits 0 only when every case matched its expected verdict
  (the three required cases "success", the control case "failure").

.PARAMETER FixtureDir
  Directory holding the pristine release assets (the Windows archive and
  checksums.txt).

.PARAMETER Version
  Release tag, e.g. v0.5.4. The fixtures are served under this path.

.PARAMETER WorkDir
  Scratch directory for the fixture trees, the per-case install dirs and
  the summary file.

.PARAMETER ShellExe
  The PowerShell executable used to invoke install.ps1 ("powershell" for
  Windows PowerShell 5.1, "pwsh" for PowerShell 7).

.PARAMETER InstallScript
  Path to install.ps1.

.PARAMETER Port
  First TCP port for the fixture servers (each case uses one port).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string] $FixtureDir,
  [Parameter(Mandatory = $true)][string] $Version,
  [Parameter(Mandatory = $true)][string] $WorkDir,
  [Parameter(Mandatory = $true)][string] $ShellExe,
  [Parameter(Mandatory = $true)][string] $InstallScript,
  [int] $Port = 18241
)

# Windows PowerShell 5.1 turns a native command's stderr into a
# terminating NativeCommandError as soon as it is merged into the
# pipeline, so errors are collected explicitly instead.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:Failures = 0
$script:CaseIndex = 0

function Get-Sha256Lower([string] $Path) {
  return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Get-PublishedHash([string] $ChecksumsPath, [string] $AssetName) {
  $line = Select-String -Path $ChecksumsPath -Pattern ([regex]::Escape($AssetName) + "$") | Select-Object -First 1
  if ($null -eq $line) { return $null }
  return (($line.Line -split '\s+')[0]).ToLower()
}

function Stop-Server($Proc) {
  if ($null -eq $Proc) { return }
  try { Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue } catch { }
}

function Start-FixtureServer([string] $Root, [int] $ServerPort) {
  $py = $null
  foreach ($candidate in @('python3', 'python')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $py = $candidate; break }
  }
  if ($null -eq $py) { throw "python not found on PATH; cannot serve fixtures" }

  $outLog = Join-Path $WorkDir ("server-$ServerPort.out.log")
  $errLog = Join-Path $WorkDir ("server-$ServerPort.err.log")
  $proc = Start-Process -FilePath $py `
    -ArgumentList @("-m", "http.server", "$ServerPort", "--directory", ('"{0}"' -f $Root)) `
    -NoNewWindow -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog

  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 300
    try {
      $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/" -UseBasicParsing -TimeoutSec 2
      if ($resp.StatusCode -eq 200) { return $proc }
    } catch { }
  }
  Stop-Server $proc
  throw "fixture server on port $ServerPort never became reachable"
}

function New-CaseTree([string] $CaseName) {
  # <WorkDir>/cases/<case>/<version>/{archive,checksums.txt} - the layout
  # install.ps1 requests: $BASE/$VERSION/<asset> and $BASE/$VERSION/checksums.txt
  $root = Join-Path (Join-Path $WorkDir "cases") $CaseName
  $vdir = Join-Path $root $Version
  if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $vdir | Out-Null
  return @{ Root = $root; VersionDir = $vdir }
}

function Invoke-Case([string] $Name, [string] $Root, [bool] $ExpectAbort, [string] $ExpectedVerdict) {
  $script:CaseIndex++
  $serverPort = $Port + $script:CaseIndex
  $installDir = Join-Path $WorkDir ("install-" + $Name)
  if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }

  $savedBase = $env:ANPU_BASE_URL
  $savedVer = $env:ANPU_VERSION
  $savedDir = $env:ANPU_INSTALL_DIR
  $proc = $null
  $rc = $null
  $output = ""
  try {
    $proc = Start-FixtureServer -Root $Root -ServerPort $serverPort
    $env:ANPU_BASE_URL = "http://127.0.0.1:$serverPort"
    $env:ANPU_VERSION = $Version
    $env:ANPU_INSTALL_DIR = $installDir

    $output = (& $ShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $InstallScript 2>&1 | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    Stop-Server $proc
    $env:ANPU_BASE_URL = $savedBase
    $env:ANPU_VERSION = $savedVer
    $env:ANPU_INSTALL_DIR = $savedDir
  }

  $binary = Join-Path $installDir "anpu.exe"
  $installed = Test-Path -LiteralPath $binary
  $observed = if ($installed) { "installed" } else { "abort" }
  $verdict = "success"
  $why = ""

  if ($ExpectAbort) {
    if ($rc -eq 0) { $verdict = "failure"; $why = "installer exited 0 where an abort was required" }
    elseif ($installed) { $verdict = "failure"; $why = "installer installed a binary despite the tamper" }
  } else {
    if ($rc -ne 0) { $verdict = "failure"; $why = "installer failed on pristine assets (exit $rc)" }
    elseif (-not $installed) { $verdict = "failure"; $why = "installer exited 0 but installed nothing" }
  }

  Write-Host "TAMPER-CASE name=$Name observed=$observed exit=$rc verdict=$verdict expected=$ExpectedVerdict"
  if ($why -ne "") { Write-Host "  reason: $why" }
  $tail = ($output -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 3)
  foreach ($line in $tail) { Write-Host "  | $line" }

  if ($verdict -ne $ExpectedVerdict) {
    Write-Host "  expected verdict $ExpectedVerdict, got $verdict"
    $script:Failures++
  }
  return @{ Name = $Name; Observed = $observed; Exit = $rc; Verdict = $verdict; Installed = $installed; Expected = $ExpectedVerdict }
}

$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
try {
  if (-not (Test-Path -LiteralPath $FixtureDir)) { throw "fixture dir not found: $FixtureDir" }
  if (-not (Test-Path -LiteralPath $InstallScript)) { throw "install script not found: $InstallScript" }
  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

  $asset = "anpu_$($Version.TrimStart('v'))_windows_amd64.zip"
  $srcZip = Join-Path $FixtureDir $asset
  $srcSums = Join-Path $FixtureDir "checksums.txt"
  if (-not (Test-Path -LiteralPath $srcZip)) { throw "archive fixture not found: $srcZip" }
  if (-not (Test-Path -LiteralPath $srcSums)) { throw "checksums fixture not found: $srcSums" }

  $published = Get-PublishedHash -ChecksumsPath $srcSums -AssetName $asset
  if ($null -eq $published) { throw "no published hash for $asset" }
  $archiveSha = Get-Sha256Lower $srcZip
  Write-Host "fixture archive=$asset sha256=$archiveSha published=$published"
  if ($published -ne $archiveSha) { throw "fixture archive does not match the published hash" }

  $results = @()

  # --- case 1: clean (positive control) --------------------------------------
  $tree = New-CaseTree "clean"
  Copy-Item -LiteralPath $srcZip -Destination (Join-Path $tree.VersionDir $asset)
  Copy-Item -LiteralPath $srcSums -Destination (Join-Path $tree.VersionDir "checksums.txt")
  $results += Invoke-Case -Name "clean" -Root $tree.Root -ExpectAbort $false -ExpectedVerdict "success"

  # --- case 2: tampered archive ----------------------------------------------
  $tree = New-CaseTree "zip-tamper"
  $zipTarget = Join-Path $tree.VersionDir $asset
  Copy-Item -LiteralPath $srcZip -Destination $zipTarget
  Copy-Item -LiteralPath $srcSums -Destination (Join-Path $tree.VersionDir "checksums.txt")
  $before = Get-Sha256Lower $zipTarget
  [System.IO.File]::AppendAllText($zipTarget, "x")
  $after = Get-Sha256Lower $zipTarget
  Write-Host "zip-tamper sha256-before=$before sha256-after=$after"
  if ($before -eq $after) { throw "zip tamper was inert (hash unchanged) - the case would be vacuous" }
  $results += Invoke-Case -Name "zip-tamper" -Root $tree.Root -ExpectAbort $true -ExpectedVerdict "success"

  # --- case 3: tampered checksums.txt ----------------------------------------
  $tree = New-CaseTree "sums-tamper"
  Copy-Item -LiteralPath $srcZip -Destination (Join-Path $tree.VersionDir $asset)
  $sumsTarget = Join-Path $tree.VersionDir "checksums.txt"
  Copy-Item -LiteralPath $srcSums -Destination $sumsTarget
  $lines = [System.IO.File]::ReadAllLines($sumsTarget)
  $mutated = $false
  $sumsBefore = $null
  $sumsAfter = $null
  for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match "^([0-9a-fA-F]{64})(\s+.*" + [regex]::Escape($asset) + ")$") {
      $h = $Matches[1]
      # Replace the FIRST hex char with one that is guaranteed to differ
      # from it. A fixed replacement character would be a no-op whenever the
      # published hash happens to start with it (1 release in 16).
      $repl = if ($h[0] -ne "0") { "0" } else { "1" }
      $sumsBefore = $h.ToLower()
      $sumsAfter = ($repl + $h.Substring(1)).ToLower()
      $lines[$i] = $sumsAfter + $Matches[2]
      $mutated = $true
      break
    }
  }
  if (-not $mutated) { throw "no checksum line matched $asset" }
  [System.IO.File]::WriteAllLines($sumsTarget, $lines)
  Write-Host "sums-tamper published-before=$sumsBefore published-after=$sumsAfter"
  if ($sumsBefore -eq $sumsAfter) { throw "checksums tamper was inert (hash unchanged) - the case would be vacuous" }
  $results += Invoke-Case -Name "sums-tamper" -Root $tree.Root -ExpectAbort $true -ExpectedVerdict "success"

  # --- case 4: deliberately wrong control -----------------------------------
  # Pristine fixtures, but the case expects an abort: the installer
  # legitimately succeeds, so the harness must report verdict "failure".
  # This is the non-vacuity control for the abort detection itself.
  $tree = New-CaseTree "control-wrong"
  Copy-Item -LiteralPath $srcZip -Destination (Join-Path $tree.VersionDir $asset)
  Copy-Item -LiteralPath $srcSums -Destination (Join-Path $tree.VersionDir "checksums.txt")
  $results += Invoke-Case -Name "control-wrong" -Root $tree.Root -ExpectAbort $true -ExpectedVerdict "failure"

  # --- summary ---------------------------------------------------------------
  $summary = Join-Path $WorkDir "summary.txt"
  $sb = New-Object System.Text.StringBuilder
  foreach ($r in $results) {
    [void]$sb.AppendLine("name=$($r.Name) observed=$($r.Observed) exit=$($r.Exit) verdict=$($r.Verdict) expected=$($r.Expected)")
  }
  [System.IO.File]::WriteAllText($summary, $sb.ToString())
  Write-Host "TAMPER-SUMMARY $summary"
  Get-Content -LiteralPath $summary | ForEach-Object { Write-Host "TAMPER-SUMMARY-LINE $_" }

  $control = $results | Where-Object { $_.Name -eq "control-wrong" }
  if ($null -eq $control) { throw "control case did not run" }
  if ($control.Verdict -eq "failure") {
    Write-Host "TAMPER-OK control-wrong concluded failure as required (non-vacuity control)"
  } else {
    Write-Host "TAMPER-ERROR control-wrong must conclude failure, got $($control.Verdict)"
  }
} catch {
  Write-Host "TAMPER-ERROR harness error: $($_.Exception.Message)"
  $script:Failures++
} finally {
  # install.ps1 adds the install dir to the user PATH; restore it so the
  # harness leaves the machine exactly as it found it.
  if ($null -ne $savedUserPath) {
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    Write-Host "TAMPER-OK restored the user PATH"
  }
}

if ($script:Failures -gt 0) {
  Write-Host "TAMPER-RESULT failures=$script:Failures"
  exit 1
}
Write-Host "TAMPER-RESULT failures=0"
exit 0
