# Phase 1: silent install of the built installer and verification of the
# installed layout (executable, Start Menu group, uninstall registration).
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

$installDir = Join-Path $env:ProgramFiles 'CheatGuardCentral'
$installedExe = Join-Path $installDir 'CheatGuardCentral.exe'
$log = Join-Path $OutputDir 'install.log'

if (Test-Path -LiteralPath $installedExe) {
    Write-Host '  A previous install is present; removing it first...'
    & (Join-Path $PSScriptRoot '05-uninstall.ps1') -RepoRoot $RepoRoot -InstallerPath $InstallerPath -OutputDir $OutputDir | Out-Null
}

Write-Host "Installing $InstallerPath (silent)..."
$proc = Start-Process -FilePath $InstallerPath -ArgumentList '/quiet', '/norestart', "/log=$log" -Wait -PassThru
Assert "installer exited successfully (exit $($proc.ExitCode))" ($proc.ExitCode -eq 0)
if ($proc.ExitCode -ne 0 -and (Test-Path $log)) {
    Get-Content $log -Tail 40 | ForEach-Object { Write-Host "    log: $_" }
}

Assert 'CheatGuardCentral.exe present in the install directory' (Test-Path -LiteralPath $installedExe)
Assert 'bundled Java runtime present' (
    Test-Path -LiteralPath (Join-Path $installDir 'runtime'))
Assert 'Start Menu group created' (
    Test-Path -LiteralPath (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Cheat.Guard'))
Assert 'support/emergency-restore.ps1 shipped inside the installed folder' (
    Test-Path -LiteralPath (Join-Path $installDir 'support\emergency-restore.ps1'))

$uninstallEntry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
    Where-Object { $_.GetValue('DisplayName') -like '*CheatGuardCentral*' }
Assert 'uninstall entry registered with Windows' ($null -ne $uninstallEntry)

exit $fail
