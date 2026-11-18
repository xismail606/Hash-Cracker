# Remove the local Hash Cracker installation created by setup.ps1.
# Usage: powershell -ExecutionPolicy Bypass -File .\uninstall.ps1

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$userBin = Join-Path $HOME ".local\bin"
$launcher = Join-Path $userBin "hashcrack.cmd"
$targets = @(
    (Join-Path $root ".venv"),
    (Join-Path $root "frontend\node_modules")
)

Write-Host "This will remove the Hash Cracker launcher and installed dependencies." -ForegroundColor Yellow
Write-Host "Your project files and audit history in $HOME\.hash_cracker will be kept."
if (-not $Force) {
    $answer = Read-Host "Continue? (y/N)"
    if ($answer -notin @("y", "Y", "yes", "YES", "Yes")) {
        Write-Host "Uninstall cancelled."
        exit 0
    }
}

if (Test-Path -LiteralPath $launcher) {
    Remove-Item -LiteralPath $launcher -Force
    Write-Host "Removed command launcher: $launcher"
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$keptEntries = @($userPath -split ';' | Where-Object {
    $_ -and ([IO.Path]::GetFullPath($_.TrimEnd('\')) -ine [IO.Path]::GetFullPath($userBin.TrimEnd('\')))
})
if ($keptEntries.Count -ne (@($userPath -split ';' | Where-Object { $_ }).Count)) {
    [Environment]::SetEnvironmentVariable("Path", ($keptEntries -join ';'), "User")
    Write-Host "Removed $userBin from your user PATH."
}

foreach ($target in $targets) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Host "Removed $target"
    }
}

Write-Host "Uninstall complete. Audit history and project files were kept." -ForegroundColor Green
