# Phase 5: silent uninstall and verification that everything installed by
# phase 1 is gone (executable, Start Menu group, uninstall registration).
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

$installedExe = Join-Path $env:ProgramFiles 'CheatGuardCentral\CheatGuardCentral.exe'
if (-not (Test-Path -LiteralPath $installedExe)) {
    Write-Host '  Nothing installed - skipping uninstall phase.'
    exit 0
}

$app = Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue
if ($app) { $app | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }

Write-Host "Uninstalling via $InstallerPath /uninstall ..."
$proc = Start-Process -FilePath $InstallerPath -ArgumentList '/uninstall', '/quiet', '/norestart' -Wait -PassThru
Assert "uninstaller exited successfully (exit $($proc.ExitCode))" ($proc.ExitCode -eq 0)

# The burned MSI can take a moment to finish removing files after the bundle exits.
$gone = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (-not (Test-Path -LiteralPath $installedExe)) { $gone = $true; break }
}
Assert 'installed executable removed' $gone
Assert 'install directory removed' (
    -not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'CheatGuardCentral')))
Assert 'Start Menu group removed' (
    -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Cheat.Guard')))

$uninstallEntry = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
    Where-Object { $_.GetValue('DisplayName') -like '*CheatGuardCentral*' }
Assert 'uninstall registration removed' ($null -eq $uninstallEntry)

exit $fail
