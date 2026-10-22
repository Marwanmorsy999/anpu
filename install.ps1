# ANPU installer for Windows (PowerShell 5.1+).
#
#   irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
#
# Env knobs (set before running):
#   $env:ANPU_VERSION     release tag, e.g. v0.4.1 (default: latest)
#   $env:ANPU_INSTALL_DIR install directory (default: $env:LOCALAPPDATA\anpu\bin)
#   $env:ANPU_BASE_URL    override the release download base URL (testing)
#   $env:ANPU_ALLOW_CUSTOM_BASE_URL
#                         set to 1 to allow a non-official ANPU_BASE_URL when
#                         no usable cosign is installed (see the warning below)
$ErrorActionPreference = "Stop"

$Repo = "Marwanmorsy999/anpu"
$OfficialPrefix = "https://github.com/Marwanmorsy999/anpu/"
$Version = $env:ANPU_VERSION
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }
$InstallDir = $env:ANPU_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $env:LOCALAPPDATA "anpu\bin" }

$Uninstall = $false
if ($env:ANPU_UNINSTALL -eq "1") { $Uninstall = $true }
if ($args -contains "--uninstall") { $Uninstall = $true }

if ($Uninstall) {
  Remove-Item -Path (Join-Path $InstallDir "anpu.exe") -Force -ErrorAction SilentlyContinue
  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($path -like "*$InstallDir*") {
    $newPath = ($path -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  }
  Write-Host "anpu installer: removed anpu binary"
  $dataDir = Join-Path $env:APPDATA "anpu"
  $purge = $false
  if ($env:ANPU_PURGE -eq "1") { $purge = $true }
  if (-not $purge -and [Environment]::UserInteractive) {
    $ans = Read-Host "Remove data directory too? [y/N]"
    if ($ans -match "^[yY]") { $purge = $true }
  }
  if ($purge) {
    Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
    Write-Host "anpu installer: removed data directory"
  } else {
    Write-Host "anpu installer: kept data directory (set ANPU_PURGE=1 to remove)"
  }
  exit 0
}

# User-facing failure: emit a capturable error record, then exit 1.
# The script runs with $ErrorActionPreference = "Stop"; a raw Write-Error
# would throw before `exit 1`, handing callers an exception instead of a
# clean exit code (callers do `$out = & ./install.ps1 2>&1; $LASTEXITCODE`).
function Fail([string]$Message) {
  $ErrorActionPreference = "Continue"
  Write-Error $Message
  exit 1
}

switch (([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture).ToString()) {
  "X64"   { $Arch = "amd64" }
  "Arm64" { $Arch = "arm64" }
  default { Fail "anpu installer: unsupported architecture: $_" }
}

function Get-CosignVersion {
  try {
    $out = & cosign version 2>&1 | Out-String
    $m = [regex]::Match($out, 'v?\d+\.\d+\.\d+')
    if ($m.Success) { return $m.Value.TrimStart('v') }
  } catch { }
  return $null
}
function Test-CosignVersionOk([string]$v, [string]$min) {
  if ([string]::IsNullOrWhiteSpace($v)) { return $false }
  try {
    return ([version]$v.TrimStart('v') -ge [version]$min.TrimStart('v'))
  } catch { return $false }
}
$CosignMin = "2.5.0"

# --- download source --------------------------------------------------------
# The published checksums.txt is downloaded from the SAME base URL as the
# archive, so the SHA-256 check only proves the archive was not corrupted
# in transit - it does NOT prove the archive came from the ANPU project.
# A hostile base URL can serve a fake archive together with a matching
# checksums.txt. Only the release signature (cosign) or a GitHub
# attestation proves authenticity.
$BaseRoot = "https://github.com/$Repo/releases/download"
$CustomBase = $false
if (-not [string]::IsNullOrWhiteSpace($env:ANPU_BASE_URL)) {
  $BaseRoot = $env:ANPU_BASE_URL.TrimEnd("/")
  if (-not $BaseRoot.StartsWith($OfficialPrefix)) { $CustomBase = $true }
}

# --- cosign availability ----------------------------------------------------
# Detected BEFORE any download: a non-official base URL is only allowed
# when the release signature can actually be verified (or the operator
# explicitly accepts the risk with ANPU_ALLOW_CUSTOM_BASE_URL=1).
$CosignPath = $null
$CosignVersion = $null
$CosignCmd = Get-Command cosign -ErrorAction SilentlyContinue
if ($CosignCmd) {
  $CosignPath = $CosignCmd.Source
  $CosignVersion = Get-CosignVersion
}
$CosignUsable = (Test-CosignVersionOk $CosignVersion $CosignMin)

if ($CustomBase) {
  Write-Host "anpu installer: ============================================================"
  Write-Host "anpu installer: WARNING: DOWNLOADING FROM A NON-OFFICIAL SOURCE"
  Write-Host "anpu installer:   base URL: $BaseRoot"
  Write-Host "anpu installer:   Official ANPU releases are published under"
  Write-Host "anpu installer:   $OfficialPrefix"
  Write-Host "anpu installer:   The SHA-256 checksums are downloaded from the SAME"
  Write-Host "anpu installer:   source, so they only prove the archive was not"
  Write-Host "anpu installer:   corrupted in transit - they do NOT prove the archive"
  Write-Host "anpu installer:   came from the ANPU project. A hostile server can"
  Write-Host "anpu installer:   serve a fake archive together with a matching"
  Write-Host "anpu installer:   checksums.txt. For authenticity verify the release"
  Write-Host "anpu installer:   signature with cosign (>= $CosignMin) or run"
  Write-Host "anpu installer:   'gh attestation verify <file> --repo Marwanmorsy999/anpu'."
  Write-Host "anpu installer: ============================================================"
  if (-not $CosignUsable) {
    if ($env:ANPU_ALLOW_CUSTOM_BASE_URL -ne "1") {
      Fail ("anpu installer: refusing to install from a non-official source: no usable " +
            "cosign (>= $CosignMin) was found, so the release signature cannot be verified. " +
            "Install cosign and retry, or set ANPU_ALLOW_CUSTOM_BASE_URL=1 to accept an " +
            "unverified download.")
    }
    Write-Host "anpu installer: WARNING: ANPU_ALLOW_CUSTOM_BASE_URL=1 is set, but no usable"
    Write-Host "anpu installer: cosign was found - this download CANNOT be signature-verified."
  }
}

function Resolve-LatestRelease([string]$Repository) {
  # PowerShell 5.1 compatibility: -MaximumRedirection 0 is unreliable on 5.1
  # (the redirect surfaces as a terminating error with no Location on some
  # builds), so try the GitHub API first, then the redirect chain, then HTML.
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest" -ErrorAction Stop
    if ($rel.tag_name) { return [string]$rel.tag_name }
  } catch { }
  $loc = $null
  try {
    $resp = Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest" -MaximumRedirection 0 -ErrorAction Stop
    $loc = $resp.Headers.Location
  } catch {
    $respObj = $_.Exception.Response
    if ($null -ne $respObj) {
      try { $loc = $respObj.Headers.Location } catch { $loc = $null }
      if ($null -eq $loc -and $respObj -is [System.Net.HttpWebResponse]) {
        try { $loc = $respObj.GetResponseHeader("Location") } catch { $loc = $null }
      }
    }
    if ([string]::IsNullOrWhiteSpace("$loc")) {
      $msg = "$($_.Exception.Message)"
      $m2 = [regex]::Match($msg, '/tag/(v?[\w\.\-]+)')
      if ($m2.Success) { return $m2.Groups[1].Value }
    }
  }
  if ($loc -is [System.Uri]) { $loc = $loc.AbsoluteUri }
  if ([string]::IsNullOrWhiteSpace("$loc")) {
    try {
      $page = Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest" -ErrorAction Stop
      $final = "$($page.BaseResponse.ResponseUri)"
      $m3 = [regex]::Match($final, '/tag/(.+)$')
      if ($m3.Success) { return $m3.Groups[1].Value }
    } catch { }
    return $null
  }
  $m = [regex]::Match("$loc", '/tag/(.+)$')
  if ($m.Success) { return $m.Groups[1].Value }
  return $null
}
if ($Version -eq "latest") {
  Write-Host "anpu installer: resolving latest release..."
  $Version = Resolve-LatestRelease $Repo
  if ([string]::IsNullOrWhiteSpace($Version)) { Fail "anpu installer: could not resolve latest release" }
}

function Test-WindowsReleaseSupported([string]$v) {
  # Windows shipped as .tar.gz before v0.4.0; the .zip layout this script
  # installs only exists for v0.4.0 and newer. v0.2.0 has no release assets.
  $t = $v.TrimStart('v')
  $parts = $t -split '\.'
  $maj = 0; $min = 0
  [int]::TryParse($parts[0], [ref]$maj) | Out-Null
  if ($parts.Count -gt 1) { [int]::TryParse($parts[1], [ref]$min) | Out-Null }
  if ($maj -gt 0) { return $true }
  return ($min -ge 4)
}
if (-not (Test-WindowsReleaseSupported $Version)) {
  Fail "anpu installer: Windows installer supports v0.4.0 and newer (requested $Version). v0.3.1 and earlier shipped Windows as .tar.gz; install manually from the release page."
}

$Base = "$BaseRoot/$Version"
$ZipName = "anpu_$($Version.TrimStart('v'))_windows_$Arch.zip"
$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  Write-Host "anpu installer: downloading $ZipName ($Version)..."
  Invoke-WebRequest -Uri "$Base/$ZipName" -OutFile (Join-Path $Tmp $ZipName)
  Invoke-WebRequest -Uri "$Base/checksums.txt" -OutFile (Join-Path $Tmp "checksums.txt")

  Write-Host "anpu installer: verifying checksum..."
  $line = Select-String -Path (Join-Path $Tmp "checksums.txt") -Pattern ([regex]::Escape($ZipName) + "$") | Select-Object -First 1
  if ($null -eq $line) { Fail "anpu installer: checksum entry for $ZipName not found" }
  $want = ($line.Line -split '\s+')[0]
  $got = (Get-FileHash -Path (Join-Path $Tmp $ZipName) -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $want.ToLower()) { Fail "anpu installer: checksum mismatch (want $want, got $got)" }

  if ($CosignUsable) {
    Write-Host "anpu installer: verifying cosign signature..."
    Invoke-WebRequest -Uri "$Base/checksums.txt.sigstore.json" -OutFile (Join-Path $Tmp "checksums.txt.sigstore.json")
    # Mandatory: a verification failure aborts the install.
    & $CosignPath verify-blob --bundle (Join-Path $Tmp "checksums.txt.sigstore.json") --certificate-identity-regexp "^https://github.com/$Repo/\.github/workflows/release\.yml@refs/tags/.*$" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" (Join-Path $Tmp "checksums.txt")
    if ($LASTEXITCODE -ne 0) { Fail "anpu installer: cosign signature verification failed" }
    Write-Host "anpu installer: cosign signature verified"
  } elseif (-not [string]::IsNullOrWhiteSpace($CosignVersion)) {
    Write-Host "anpu installer: WARNING: cosign $CosignVersion found, but signature verification requires cosign >= v$CosignMin - skipping signature verification (SHA-256 verification already passed)"
  } else {
    Write-Host "anpu installer: cosign not found, skipping signature verification (signature verification requires cosign >= v$CosignMin)"
  }

  Expand-Archive -Path (Join-Path $Tmp $ZipName) -DestinationPath (Join-Path $Tmp "out") -Force
  $bin = Get-ChildItem -Path (Join-Path $Tmp "out") -Filter "anpu.exe" -Recurse | Select-Object -First 1
  if ($null -eq $bin) { Fail "anpu installer: archive did not contain anpu.exe" }

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -Path $bin.FullName -Destination (Join-Path $InstallDir "anpu.exe") -Force

  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$path;$InstallDir", "User")
    Write-Host "anpu installer: added $InstallDir to your user PATH (restart the terminal to pick it up)"
  }
  Write-Host "anpu installer: installed to $(Join-Path $InstallDir 'anpu.exe')"
  & (Join-Path $InstallDir "anpu.exe") version
}
finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
