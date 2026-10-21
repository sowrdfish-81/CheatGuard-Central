# Validates the PowerShell syntax of every .ps1 file in the repository
# (resources, support, test, test/integration, .github) using the PowerShell
# language parser. Exits non-zero on any parse error.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$files = Get-ChildItem -Path $repoRoot -Recurse -Filter *.ps1 -File |
    Where-Object {
        $rel = $_.FullName.Substring($repoRoot.Length + 1)
        $rel -notmatch '^(tools|build|dist|bin|node_modules|integration-output)(\\|/)' -and
        $rel -notmatch '^(\\.git)'
    } | Sort-Object FullName

if (-not $files) {
    Write-Output 'PS1 SYNTAX CHECK: no .ps1 files found'
    exit 1
}

$totalErrors = 0
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$errors)
    $relative = $file.FullName.Substring($repoRoot.Length + 1)
    if ($errors -and $errors.Count -gt 0) {
        Write-Output ("PS1 SYNTAX ERRORS in " + $relative + ": " + $errors.Count)
        foreach ($e in $errors) {
            Write-Output ("  line " + $e.Extent.StartLineNumber + ": " + $e.Message)
        }
        $totalErrors += $errors.Count
    } else {
        Write-Output ("PS1 OK  " + $relative)
    }
}

if ($totalErrors -gt 0) {
    Write-Output ("PS1 SYNTAX CHECK FAILED: " + $totalErrors + " error(s)")
    exit 1
}
Write-Output ("PS1 SYNTAX CHECK PASSED: " + $files.Count + " file(s) valid")
exit 0
