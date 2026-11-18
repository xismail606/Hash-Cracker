# Launches the local web dashboard with the chosen backend (Phase 11):
#   Python (Flask) or Rust. The script asks when both are installed and
#   stdin is a TTY; -Backend python|rust skips the prompt for scripts/CI.
#
# Usage:  .\serve.ps1                          (default port 8765)
#         .\serve.ps1 -Port 9000
#         .\serve.ps1 -Backend rust [-Port 9000]
param(
    [int]$Port = 8765,
    [string]$Backend = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Write-Usage {
    Write-Host "Usage: .\serve.ps1 [-Backend python|rust] [-Port 9000]"
}

if ($Backend -ne "" -and $Backend -ne "python" -and $Backend -ne "rust") {
    Write-Host "Unknown backend: $Backend" -ForegroundColor Red
    Write-Usage
    exit 2
}

# Backend detection: Python venv vs the Rust release binary.
$python = Join-Path $root ".venv\Scripts\python.exe"
$hasPython = Test-Path $python
$rustBin = $null
foreach ($name in @("hashcrack-rs.exe", "hashcrack-rs")) {
    $candidate = Join-Path $root "rust\target\release\$name"
    if (Test-Path $candidate) { $rustBin = $candidate; break }
}

if ($Backend -eq "") {
    if ($hasPython -and $rustBin -and [Environment]::UserInteractive) {
        $choice = Read-Host "Which backend should serve the dashboard? [1] Python [2] Rust (Enter=Python)"
        switch ($choice) {
            ""    { $Backend = "python" }
            "1"   { $Backend = "python" }
            "2"   { $Backend = "rust" }
            default {
                Write-Host "Unknown choice: $choice" -ForegroundColor Red
                exit 2
            }
        }
    } elseif ($hasPython) {
        $Backend = "python"
        if ($rustBin) {
            Write-Host "[serve] Non-interactive run with both backends installed; serving Python."
        }
    } elseif ($rustBin) {
        $Backend = "rust"
        Write-Host "[serve] Python backend not found; serving with Rust (run .\setup.ps1 -Backend python if this is unexpected)."
    } else {
        Write-Host "Neither backend is installed. Run setup first:" -ForegroundColor Yellow
        Write-Host "  .\setup.ps1 -Backend python    (Python backend)"
        Write-Host "  .\setup.ps1 -Backend rust      (Rust backend)"
        exit 1
    }
}

switch ($Backend) {
    "python" {
        if (-not $hasPython) {
            Write-Host "The Python backend is not installed. Run: .\setup.ps1 -Backend python" -ForegroundColor Yellow
            exit 1
        }
        & $python -m hash_cracker serve --port $Port
    }
    "rust" {
        if (-not $rustBin) {
            Write-Host "The Rust backend is not installed. Run: .\setup.ps1 -Backend rust" -ForegroundColor Yellow
            exit 1
        }
        & $rustBin serve --port $Port
    }
}
