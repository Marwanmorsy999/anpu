$ErrorActionPreference = 'Continue'
Write-Host "CASE-ABORT shell=$($PSVersionTable.PSVersion) edition=$($PSVersionTable.PSEdition)"
Write-Error 'PROBE-ABORT'
exit 1
