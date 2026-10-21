# Phase 3: arm the REAL network-lockdown helper with the same config JSON the
# application writes, verify it goes ready and actually filters DNS, then stop
# it via stop.marker and verify the network is restored. This is the genuine
# lockdown machinery from resources/network-lockdown.ps1, on a real machine.
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

$networkDir = Join-Path $env:ProgramData 'CheatGuard\network'
New-Item -ItemType Directory -Force $networkDir | Out-Null
$helper = Join-Path $networkDir 'network-lockdown.ps1'
Copy-Item (Join-Path $RepoRoot 'resources\network-lockdown.ps1') $helper -Force

$stateFile = Join-Path $networkDir 'firewall_state.json'
$readyFile = Join-Path $networkDir 'ready.marker'
$stopFile = Join-Path $networkDir 'stop.marker'
$restoredFile = Join-Path $networkDir 'restored.marker'
$errorFile = Join-Path $networkDir 'error.txt'
$allowedIpFile = Join-Path $networkDir 'allowed-ips.txt'
$egressStatusFile = Join-Path $networkDir 'egress-status.txt'
$centralIpFile = Join-Path $networkDir 'central-ip.txt'
$lockStatusFile = Join-Path $networkDir 'file-lock-status.txt'
$protectRequestFile = Join-Path $networkDir 'protect.request'
$protectDoneFile = Join-Path $networkDir 'protect.done'
$configFile = Join-Path $networkDir 'active-config.json'
foreach ($f in @($allowedIpFile, $centralIpFile)) {
    if (-not (Test-Path -LiteralPath $f)) { New-Item -ItemType File -Path $f -Force | Out-Null }
}
Remove-Item -LiteralPath $stateFile, $readyFile, $stopFile, $restoredFile, $errorFile -Force -ErrorAction SilentlyContinue

# Same shape StrictNetworkLockdown.writeConfig() produces. No lockPathsFile:
# the helper then runs its network lockdown without the NTFS file wall, which
# this phase does not exercise (the real app supplies it during a session).
$installedExe = Join-Path $env:ProgramFiles 'CheatGuardCentral\CheatGuardCentral.exe'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$cfg = [ordered]@{
    parentPid         = $PID
    parentName        = $MyInvocation.MyCommand.Name
    dnsPort           = 53
    dnsIpv6           = $false
    userSid           = $sid
    programPath       = $installedExe
    vaultDir          = (Join-Path $env:ProgramData 'CheatGuard\vault')
    allowedIpFile     = $allowedIpFile
    egressStatusFile  = $egressStatusFile
    verifyHost        = 'example.org'
    centralIpFile     = $centralIpFile
    centralPort       = 47821
    lockStatusFile    = $lockStatusFile
    userSidForLocks   = $sid
    stateFile         = $stateFile
    readyFile         = $readyFile
    stopFile          = $stopFile
    restoredFile      = $restoredFile
    protectRequestFile = $protectRequestFile
    protectDoneFile   = $protectDoneFile
    errorFile         = $errorFile
}
$cfg | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding UTF8

function AdapterDnsLoopback([bool]$present) {
    $addresses = Get-DnsClientServerAddress -AddressFamily IPv4 |
        ForEach-Object { $_.ServerAddresses } | Select-Object -Unique
    if ($present) { return ($addresses -contains '127.0.0.1') }
    return (-not ($addresses -contains '127.0.0.1'))
}

Write-Host 'Arming the network lockdown helper (elevated, no prompt on the runner account)...'
$elevated = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -PassThru -WindowStyle Hidden `
    -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$helper`"", '-Config', "`"$configFile`""

$ready = $false
$deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path -LiteralPath $errorFile) {
        Write-Host '  Helper reported an error:' -ForegroundColor Yellow
        Get-Content $errorFile | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" }
        break
    }
    if (Test-Path -LiteralPath $readyFile) { $ready = $true; break }
}
Assert 'lockdown helper reached ready state' $ready
Assert 'helper saved the pre-session state snapshot' (Test-Path -LiteralPath $stateFile)
Assert 'DNS of local adapters now points at the CheatGuard filter (127.0.0.1)' (AdapterDnsLoopback $true)

if (-not (Test-Path -LiteralPath (Join-Path $OutputDir))) {
    New-Item -ItemType Directory -Force $OutputDir | Out-Null
}
Get-DnsClientServerAddress | Out-File (Join-Path $OutputDir 'dns-during-lockdown.txt')
Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue |
    Out-File (Join-Path $OutputDir 'firewall-rules-during-lockdown.txt')

Write-Host 'Stopping the lockdown (stop.marker) and waiting for restore...'
New-Item -ItemType File -Path $stopFile -Force | Out-Null
$restored = $false
$deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path -LiteralPath $restoredFile) { $restored = $true; break }
}
Assert 'helper wrote the restored marker' $restored
Assert 'DNS filters removed after restore' (AdapterDnsLoopback $false)

Start-Sleep -Seconds 2
Get-Process -Name powershell -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne $PID -and $_.Id -eq $elevated.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $stateFile, $readyFile, $stopFile, $restoredFile, $errorFile,
    $configFile, $protectRequestFile, $protectDoneFile -Force -ErrorAction SilentlyContinue

exit $fail
