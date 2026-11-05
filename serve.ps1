# Launches the local web dashboard with the project's virtual environment,
# so `.\serve.ps1` works without activating .venv first.
#
# Usage:  .\serve.ps1            (default port 8765)
#         .\serve.ps1 -Port 9000
param(
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "The project virtual environment was not found at .venv\." -ForegroundColor Yellow
    Write-Host "Create it first (one-time setup):"
    Write-Host "  python -m venv .venv"
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -e ."
    Write-Host "  Set-Location frontend; npm install; npm run build; Set-Location .."
    exit 1
}

& $python -m password_audit serve --port $Port
