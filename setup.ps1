# One-command setup for Hash Cracker (Windows).
# Downloads/installs everything needed to run the project:
#   Python venv + package (with optional extras), Node deps, frontend build.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\setup.ps1
#         .\setup.ps1 -SkipFrontend     (skip the npm steps)

param(
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step($msg) { Write-Host "[setup] $msg" -ForegroundColor Cyan }

# Check the frontend toolchain before spending time installing Python packages.
if (-not $SkipFrontend) {
    Step "Checking Node.js and npm..."
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCommand) {
        Write-Host "ERROR: Node.js 18+ was not found on PATH." -ForegroundColor Red
        Write-Host "Install Node.js with npm from https://nodejs.org, then reopen PowerShell." -ForegroundColor Yellow
        Write-Host "For a CLI/backend-only install, run: .\setup.ps1 -SkipFrontend" -ForegroundColor Yellow
        exit 1
    }
    try {
        $nodeVersion = (& $nodeCommand.Source --version).Trim()
        if ($LASTEXITCODE -ne 0) { throw "node --version failed" }
        $nodeSemver = [version]($nodeVersion -replace '^v', '')
    } catch {
        Write-Host "ERROR: Node.js was found but its version could not be read." -ForegroundColor Red
        exit 1
    }
    if ($nodeSemver.Major -lt 18) {
        Write-Host "ERROR: Node.js $nodeVersion found; version 18+ is required." -ForegroundColor Red
        Write-Host "Install a current release from https://nodejs.org." -ForegroundColor Yellow
        exit 1
    }

    # Prefer npm.cmd to avoid PowerShell execution-policy errors from npm.ps1.
    $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npmCommand) { $npmCommand = Get-Command npm -ErrorAction SilentlyContinue }
    if (-not $npmCommand) {
        Write-Host "ERROR: Node.js $nodeVersion is installed, but npm was not found on PATH." -ForegroundColor Red
        Write-Host "Install npm with Node.js (https://nodejs.org), then reopen PowerShell." -ForegroundColor Yellow
        Write-Host "For a CLI/backend-only install, run: .\setup.ps1 -SkipFrontend" -ForegroundColor Yellow
        exit 1
    }
    $npmPath = $npmCommand.Source
    try {
        $npmVersion = (& $npmPath --version).Trim()
        if ($LASTEXITCODE -ne 0) { throw "npm --version failed" }
    } catch {
        Write-Host "ERROR: npm was found but could not be run. Check your Node.js/npm installation." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Node.js $nodeVersion and npm $npmVersion OK"
}

# --- 1. Python ------------------------------------------------------------
Step "Checking Python (3.11+)..."
try {
    $pyVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
} catch {
    Write-Host "ERROR: Python was not found on PATH. Install Python 3.11+ from https://python.org" -ForegroundColor Red
    exit 1
}
$major, $minor = $pyVersion.Split(".")
if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 11)) {
    Write-Host "ERROR: Python $pyVersion found; 3.11+ is required." -ForegroundColor Red
    exit 1
}
Write-Host "  Python $pyVersion OK"

# --- 2. Virtual environment -------------------------------------------------
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Step "Creating virtual environment (.venv)..."
    & python -m venv .venv
} else {
    Step "Virtual environment already exists; reusing it."
}

# --- 3. Python package + extras ----------------------------------------------
Step "Installing the package with all extras (dev, encrypt, adaptive)..."
& $venvPython -m pip install --upgrade pip -q
& $venvPython -m pip install -e ".[dev,encrypt,adaptive]" -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip install failed." -ForegroundColor Red
    exit 1
}
Write-Host "  Python dependencies installed"

# --- 4. Node + frontend -------------------------------------------------------
if ($SkipFrontend) {
    Step "Skipping frontend build (-SkipFrontend)."
} else {
    Step "Installing frontend dependencies (npm ci)..."
    Push-Location frontend
    & $npmPath ci
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: npm ci failed." -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Step "Building the dashboard (npm run build)..."
    & $npmPath run build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: frontend build failed." -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Pop-Location
}

# --- 5. Verify -----------------------------------------------------------------
Step "Verifying the installation..."
& $venvPython -m pytest tests/ -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: some tests failed - the tool may still run, but report issues." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Run the dashboard:   .\serve.ps1        (http://127.0.0.1:8765)"
Write-Host "Run the CLI:         .venv\Scripts\python -m password_audit --help"
Write-Host ""
Write-Host "Authorized local auditing only - no remote targets, no network access."
