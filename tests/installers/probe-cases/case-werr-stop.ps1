$ErrorActionPreference = 'Stop'
Write-Host "CASE-WERR-STOP shell=$($PSVersionTable.PSVersion) edition=$($PSVersionTable.PSEdition)"
Write-Error 'PROBE-WERR-STOP'
Write-Host 'CASE-WERR-STOP reached-after (should never print)'
exit 0
