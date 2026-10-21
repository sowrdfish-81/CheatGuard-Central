# Phase 2: the installed application starts, shows its window and creates its
# ProgramData directory - then is stopped cleanly.
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
Assert 'installed executable exists' (Test-Path -LiteralPath $installedExe)
if (-not (Test-Path -LiteralPath $installedExe)) { exit 1 }

Write-Host 'Starting the installed application...'
$app = Start-Process -FilePath $installedExe -PassThru

$windowSeen = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $running = Get-Process -Id $app.Id -ErrorAction SilentlyContinue
    if (-not $running) { break }
    $running.Refresh()
    if ($running.MainWindowHandle -ne 0) { $windowSeen = $true; break }
}

$alive = $null -ne (Get-Process -Id $app.Id -ErrorAction SilentlyContinue)
Assert 'application process started and stayed alive' $alive
Assert 'application main window appeared' $windowSeen
Assert 'ProgramData\CheatGuard data directory created' (
    Test-Path -LiteralPath (Join-Path $env:ProgramData 'CheatGuard'))

# The app may relaunch itself elevated; stop every instance of it.
Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.CloseMainWindow() | Out-Null } catch {}
}
Start-Sleep -Seconds 3
Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Assert 'application stopped cleanly' (
    $null -eq (Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue))

exit $fail
