# ANPU installer for Windows (PowerShell 5.1+).
#
#   irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
#
# Env knobs (set before running):
#   $env:ANPU_VERSION     release tag, e.g. v0.3.1 (default: latest)
#   $env:ANPU_INSTALL_DIR install directory (default: $env:LOCALAPPDATA\anpu\bin)
#   $env:ANPU_WITH_TOOLS  when "1", pre-install all advanced-level external
#                         tools via the binary itself (needs Go toolchain for
#                         go-based tools; failures are reported, never fatal)
$ErrorActionPreference = "Stop"

$Repo = "Marwanmorsy999/anpu"
$Version = $env:ANPU_VERSION
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }
$InstallDir = $env:ANPU_INSTALL_DIR
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $env:LOCALAPPDATA "anpu\bin" }

switch (([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture).ToString()) {
  "X64"   { $Arch = "amd64" }
  "Arm64" { $Arch = "arm64" }
  default { Write-Error "anpu installer: unsupported architecture: $_"; exit 1 }
}

if ($Version -eq "latest") {
  Write-Host "anpu installer: resolving latest release..."
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $rel.tag_name
  if ([string]::IsNullOrWhiteSpace($Version)) { Write-Error "anpu installer: could not resolve latest release"; exit 1 }
}

$Base = "https://github.com/$Repo/releases/download/$Version"
$ZipName = "anpu_$($Version.TrimStart('v'))_windows_$Arch.zip"
$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("anpu-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  Write-Host "anpu installer: downloading $ZipName ($Version)..."
  Invoke-WebRequest -Uri "$Base/$ZipName" -OutFile (Join-Path $Tmp $ZipName)
  Invoke-WebRequest -Uri "$Base/checksums.txt" -OutFile (Join-Path $Tmp "checksums.txt")

  Write-Host "anpu installer: verifying checksum..."
  $line = Select-String -Path (Join-Path $Tmp "checksums.txt") -Pattern ([regex]::Escape($ZipName) + "$") | Select-Object -First 1
  if ($null -eq $line) { Write-Error "anpu installer: checksum entry for $ZipName not found"; exit 1 }
  $want = ($line.Line -split '\s+')[0]
  $got = (Get-FileHash -Path (Join-Path $Tmp $ZipName) -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $want.ToLower()) { Write-Error "anpu installer: checksum mismatch (want $want, got $got)"; exit 1 }

  # Cosign signature over checksums.txt (Sigstore keyless, published per
  # release as checksums.txt.sigstore.json). Verified when cosign is
  # available; otherwise the SHA-256 check above is the verification.
  if (Get-Command cosign -ErrorAction SilentlyContinue) {
    Write-Host "anpu installer: verifying cosign signature..."
    Invoke-WebRequest -Uri "$Base/checksums.txt.sigstore.json" -OutFile (Join-Path $Tmp "checksums.txt.sigstore.json")
    & cosign verify-blob --bundle (Join-Path $Tmp "checksums.txt.sigstore.json") --certificate-identity-regexp "^https://github.com/$Repo/\.github/workflows/release\.yml@refs/tags/.*$" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" (Join-Path $Tmp "checksums.txt")
    if ($LASTEXITCODE -ne 0) { Write-Error "anpu installer: cosign signature verification failed"; exit 1 }
  } else {
    Write-Host "anpu installer: cosign not found, skipping signature verification (checksum verified; install cosign from https://docs.sigstore.dev for full verification)"
  }

  Expand-Archive -Path (Join-Path $Tmp $ZipName) -DestinationPath (Join-Path $Tmp "out") -Force
  $bin = Get-ChildItem -Path (Join-Path $Tmp "out") -Filter "anpu.exe" -Recurse | Select-Object -First 1
  if ($null -eq $bin) { Write-Error "anpu installer: archive did not contain anpu.exe"; exit 1 }

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -Path $bin.FullName -Destination (Join-Path $InstallDir "anpu.exe") -Force

  # Add to user PATH if missing.
  $path = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$path;$InstallDir", "User")
    Write-Host "anpu installer: added $InstallDir to your user PATH (restart the terminal to pick it up)"
  }
  Write-Host "anpu installer: installed to $(Join-Path $InstallDir 'anpu.exe')"
  if ($env:ANPU_WITH_TOOLS -eq "1") {
    Write-Host "anpu installer: pre-installing advanced external tools (ANPU_WITH_TOOLS=1)..."
    & (Join-Path $InstallDir "anpu.exe") tools install --all --level advanced --yes
    if ($LASTEXITCODE -ne 0) { Write-Host "anpu installer: some tools failed (see above); scans warn-and-skip missing ones" }
  }
  Write-Host "anpu installer: run 'anpu scan https://example.com' for a first safe scan (only against targets you own or are authorized to test)"
  Write-Host "anpu installer: tip: 'anpu scan --auto-install' self-provisions missing tools on first use"
}
finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
