$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Isolated probe matrix: every case runs in its own child process, so a
# terminating error in one case cannot kill the probe or leak $LASTEXITCODE.
$Cases = @('case-ok.ps1','case-abort-exit1.ps1','case-werr-stop.ps1','case-werr-continue.ps1')
$Dir = Join-Path $PSScriptRoot 'probe-cases'
$Wrap = Join-Path $Dir 'case-iex-wrap.ps1'
foreach ($exe in @('powershell','pwsh')) {
  foreach ($c in $Cases) {
    $f = Join-Path $Dir $c
    $out = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f 2>&1
    $code = $LASTEXITCODE
    $short = (($out | Out-String) -replace '\s+', ' ').Trim()
    if ($short.Length -gt 220) { $short = $short.Substring(0, 220) + '...' }
    Write-Host ("PROBE shell={0} style=-File case={1} exit={2} out=[{3}]" -f $exe, $c, $code, $short)
  }
  # -Command variant of werr-stop: exit code can differ from -File.
  $werr = Join-Path $Dir 'case-werr-stop.ps1'
  $out = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& '$werr'" 2>&1
  $code = $LASTEXITCODE
  $short = (($out | Out-String) -replace '\s+', ' ').Trim()
  if ($short.Length -gt 220) { $short = $short.Substring(0, 220) + '...' }
  Write-Host ("PROBE shell={0} style=-Command case=case-werr-stop.ps1 exit={1} out=[{2}]" -f $exe, $code, $short)
  # iex style: wrapper child runs the iex, parent asserts on child exit.
  foreach ($t in @('case-ok.ps1','case-abort-exit1.ps1','case-werr-stop.ps1')) {
    $f = Join-Path $Dir $t
    $out = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Wrap -Target $f 2>&1
    $code = $LASTEXITCODE
    $short = (($out | Out-String) -replace '\s+', ' ').Trim()
    if ($short.Length -gt 220) { $short = $short.Substring(0, 220) + '...' }
    Write-Host ("PROBE shell={0} style=iex-wrap case={1} exit={2} out=[{3}]" -f $exe, $t, $code, $short)
  }
}
Write-Host 'PROBE-DONE'
