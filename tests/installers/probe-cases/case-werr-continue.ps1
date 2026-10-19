$ErrorActionPreference = 'Continue'
Write-Host "CASE-WERR-CONTINUE shell=$($PSVersionTable.PSVersion) edition=$($PSVersionTable.PSEdition)"
Write-Error 'PROBE-WERR-CONTINUE'
Write-Host 'CASE-WERR-CONTINUE reached-after=yes'
exit 0
