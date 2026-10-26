# Phase 0: refuse to run anywhere except the disposable VM runner.
param(
    [string]$RepoRoot,
    [string]$InstallerPath,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$fail = 0

function Assert([string]$label, [bool]$condition) {
    if ($condition) { Write-Host "  PASS  $label" }
    else { Write-Host "  FAIL  $label" -ForegroundColor Red; $script:fail = 1 }
}

if ($env:OS -ne 'Windows_NT') {
    Write-Host 'These integration tests only run on Windows.' -ForegroundColor Red
    exit 1
}

Assert 'CHEATGUARD_VM=1 is set (disposable VM marker)' ($env:CHEATGUARD_VM -eq '1')

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert 'running elevated as Administrator' (
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Assert 'installer artifact path was provided' (-not [string]::IsNullOrWhiteSpace($InstallerPath))
Assert 'installer artifact exists' (
    -not [string]::IsNullOrWhiteSpace($InstallerPath) -and
    (Test-Path -LiteralPath $InstallerPath))
Assert 'resources/network-lockdown.ps1 exists in the checkout' (
    -not [string]::IsNullOrWhiteSpace($RepoRoot) -and
    (Test-Path -LiteralPath (Join-Path $RepoRoot 'resources\network-lockdown.ps1')))
Assert 'support/emergency-restore.ps1 exists in the checkout' (
    -not [string]::IsNullOrWhiteSpace($RepoRoot) -and
    (Test-Path -LiteralPath (Join-Path $RepoRoot 'support\emergency-restore.ps1')))

$app = Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue
Assert 'no CheatGuard process is already running' (-not $app)

exit $fail
