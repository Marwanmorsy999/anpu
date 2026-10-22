<#
.SYNOPSIS
  Guard tests for the ANPU_BASE_URL knob in install.ps1.

.DESCRIPTION
  Every check prints
    GUARD-CHECK case=<case> check=<name> verdict=<success|failure> <detail>
  and the script exits 0 only when every check passed.

    custom-no-allow  a non-official base URL without a usable cosign and
                     without ANPU_ALLOW_CUSTOM_BASE_URL=1 must be REFUSED:
                     non-zero exit, nothing installed, no download started.
    custom-allowed   the same base URL with ANPU_ALLOW_CUSTOM_BASE_URL=1
                     must print the non-official-source warning and proceed.
    default-base     the default (unset) base URL must behave exactly as
                     before and must NOT print the warning.
    official-base    the official base URL set explicitly is not "custom"
                     either: no warning, no refusal.

.PARAMETER InstallScript
  Path to install.ps1.

.PARAMETER FixtureDir
  Directory holding the published release assets that the local server
  will serve (the Windows archive and checksums.txt).

.PARAMETER Version
  Release tag, e.g. v0.5.5.

.PARAMETER WorkDir
  Scratch directory for the fixture tree, the per-case install dirs and
  the server logs.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string] $InstallScript,
  [Parameter(Mandatory = $true)][string] $FixtureDir,
  [Parameter(Mandatory = $true)][string] $Version,
  [Parameter(Mandatory = $true)][string] $WorkDir,
  [int] $Port = 18781
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:Failures = 0
$script:CaseIndex = 0

function Get-Sha256Lower([string] $Path) {
  return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
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

function Get-PathWithoutCosign {
  # A PATH without any cosign, so the "no usable cosign" case is
  # deterministic even on a machine that has cosign installed.
  $kept = @()
  foreach ($d in ($env:Path -split ';')) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    if (Test-Path -LiteralPath (Join-Path $d 'cosign.exe')) { continue }
    if (Test-Path -LiteralPath (Join-Path $d 'cosign')) { continue }
    $kept += $d
  }
  return ($kept -join ';')
}

function Invoke-GuardCase([string] $Name, [bool] $UseCustomBase, [bool] $AllowCustomBase, [bool] $UseOfficialBase) {
  $script:CaseIndex++
  $serverPort = $Port + $script:CaseIndex
  $installDir = Join-Path $WorkDir ("install-" + $Name)
  if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }

  $savedBase = $env:ANPU_BASE_URL
  $savedAllow = $env:ANPU_ALLOW_CUSTOM_BASE_URL
  $savedVer = $env:ANPU_VERSION
  $savedDir = $env:ANPU_INSTALL_DIR
  $savedPath = $env:Path
  $proc = $null
  $rc = $null
  $output = ""
  try {
    $proc = Start-FixtureServer -Root $FixtureRoot -ServerPort $serverPort
    $env:Path = (Get-PathWithoutCosign)
    $env:ANPU_VERSION = $Version
    $env:ANPU_INSTALL_DIR = $installDir
    if ($UseCustomBase) { $env:ANPU_BASE_URL = "http://127.0.0.1:$serverPort" }
    elseif ($UseOfficialBase) { $env:ANPU_BASE_URL = "https://github.com/Marwanmorsy999/anpu/releases/download" }
    else { $env:ANPU_BASE_URL = $null }
    if ($AllowCustomBase) { $env:ANPU_ALLOW_CUSTOM_BASE_URL = "1" }
    else { $env:ANPU_ALLOW_CUSTOM_BASE_URL = $null }

    $output = (& $ShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $InstallScript 2>&1 | Out-String)
    $rc = $LASTEXITCODE
  } finally {
    Stop-Server $proc
    $env:ANPU_BASE_URL = $savedBase
    $env:ANPU_ALLOW_CUSTOM_BASE_URL = $savedAllow
    $env:ANPU_VERSION = $savedVer
    $env:ANPU_INSTALL_DIR = $savedDir
    $env:Path = $savedPath
  }

  $installed = Test-Path -LiteralPath (Join-Path $installDir 'anpu.exe')
  Write-Host "--- case $Name (exit $rc, installed=$installed) ---"
  ($output -split "`r?`n" | Where-Object { $_.Trim() -ne "" }) | ForEach-Object { Write-Host "    $_" }
  return @{ Name = $Name; Exit = $rc; Installed = $installed; Output = $output }
}

function Test-Guard([string] $Case, [string] $Check, [bool] $Ok, [string] $Detail) {
  if ($Ok) {
    Write-Host "GUARD-CHECK case=$Case check=$Check verdict=success $Detail"
  } else {
    Write-Host "GUARD-CHECK case=$Case check=$Check verdict=failure $Detail"
    $script:Failures++
  }
}

$ShellExe = if ($env:GUARD_SHELL_EXE) { $env:GUARD_SHELL_EXE } else { "powershell" }
$FixtureRoot = Join-Path $WorkDir "www"
$VersionDir = Join-Path $FixtureRoot $Version
# install.ps1 adds the install dir to the user PATH; snapshot it so the
# harness leaves the machine exactly as it found it.
$savedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

try {
  if (-not (Test-Path -LiteralPath $InstallScript)) { throw "install script not found: $InstallScript" }
  if (-not (Test-Path -LiteralPath $FixtureDir)) { throw "fixture dir not found: $FixtureDir" }
  New-Item -ItemType Directory -Force -Path $VersionDir | Out-Null

  $asset = "anpu_$($Version.TrimStart('v'))_windows_amd64.zip"
  $srcZip = Join-Path $FixtureDir $asset
  $srcSums = Join-Path $FixtureDir 'checksums.txt'
  if (-not (Test-Path -LiteralPath $srcZip)) { throw "archive fixture not found: $srcZip" }
  if (-not (Test-Path -LiteralPath $srcSums)) { throw "checksums fixture not found: $srcSums" }
  Copy-Item -LiteralPath $srcZip -Destination (Join-Path $VersionDir $asset)
  Copy-Item -LiteralPath $srcSums -Destination (Join-Path $VersionDir 'checksums.txt')
  Write-Host "non-official source serves $asset plus a checksums.txt that matches it"

  # --- case 1: custom base URL, no allow variable, no cosign ---------------
  $r = Invoke-GuardCase -Name 'custom-no-allow' -UseCustomBase $true -AllowCustomBase $false -UseOfficialBase $false
  Test-Guard 'custom-no-allow' 'non-zero-exit' ($r.Exit -ne 0) "exit=$($r.Exit)"
  Test-Guard 'custom-no-allow' 'refusal-message' ($r.Output -match 'refusing to install from a non-official source') "the refusal message was printed"
  Test-Guard 'custom-no-allow' 'names-escape-hatch' ($r.Output -match 'ANPU_ALLOW_CUSTOM_BASE_URL=1') "the escape hatch is named"
  Test-Guard 'custom-no-allow' 'no-download-started' (-not ($r.Output -match 'anpu installer: downloading ')) "no download was started"
  Test-Guard 'custom-no-allow' 'nothing-installed' (-not $r.Installed) "no binary was installed"

  # --- case 2: custom base URL with the allow variable ---------------------
  $r = Invoke-GuardCase -Name 'custom-allowed' -UseCustomBase $true -AllowCustomBase $true -UseOfficialBase $false
  Test-Guard 'custom-allowed' 'warning-printed' ($r.Output -match 'WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE') "the non-official-source warning was printed"
  Test-Guard 'custom-allowed' 'warning-explains-risk' ($r.Output -match 'do NOT prove the archive') "the warning explains that checksums do not prove authenticity"
  Test-Guard 'custom-allowed' 'not-refused' (-not ($r.Output -match 'refusing to install from a non-official source')) "not refused"
  Test-Guard 'custom-allowed' 'install-proceeds' (($r.Exit -eq 0) -and $r.Installed) "exit=$($r.Exit), installed=$($r.Installed)"

  # --- case 3: the default base URL is unchanged and prints no warning -----
  $r = Invoke-GuardCase -Name 'default-base' -UseCustomBase $false -AllowCustomBase $false -UseOfficialBase $false
  Test-Guard 'default-base' 'install-ok' (($r.Exit -eq 0) -and $r.Installed) "exit=$($r.Exit), installed=$($r.Installed)"
  Test-Guard 'default-base' 'no-warning' (-not ($r.Output -match 'WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE')) "no warning"
  Test-Guard 'default-base' 'checksum-step-present' ($r.Output -match 'verifying checksum') "the normal checksum step ran"

  # --- case 4: the official base URL set explicitly is not "custom" --------
  $r = Invoke-GuardCase -Name 'official-base' -UseCustomBase $false -AllowCustomBase $false -UseOfficialBase $true
  Test-Guard 'official-base' 'no-warning' (-not ($r.Output -match 'WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE')) "no warning"
} catch {
  Write-Host "GUARD-ERROR harness error: $($_.Exception.Message)"
  $script:Failures++
} finally {
  if ($null -ne $savedUserPath) {
    [Environment]::SetEnvironmentVariable("Path", $savedUserPath, "User")
    Write-Host "GUARD-OK restored the user PATH"
  }
}

if ($script:Failures -gt 0) {
  Write-Host "GUARD-RESULT failures=$script:Failures"
  exit 1
}
Write-Host "GUARD-RESULT failures=0"
exit 0
