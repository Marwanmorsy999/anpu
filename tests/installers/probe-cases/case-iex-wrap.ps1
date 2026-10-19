param([string]$Target)
# iex wrapper child: exit inside iex ends THIS host; assert in the parent.
$ErrorActionPreference = 'Continue'
Write-Host "CASE-IEX shell=$($PSVersionTable.PSVersion) edition=$($PSVersionTable.PSEdition) target=$Target"
Get-Content -Raw -Path $Target | Invoke-Expression
$code = $LASTEXITCODE
Write-Host "CASE-IEX post-iex LASTEXITCODE=$code"
exit $code
