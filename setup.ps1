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

# Preflight Python before installing or changing the frontend toolchain.
Step "Checking Python (3.11+)..."
try {
    $pyVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ($LASTEXITCODE -ne 0) { throw "Python version check failed" }
} catch {
    Write-Host "ERROR: Python 3.11+ was not found on PATH. Install Python, then rerun setup." -ForegroundColor Red
    exit 1
}
$major, $minor = $pyVersion.Split(".")
if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 11)) {
    Write-Host "ERROR: Python $pyVersion found; 3.11+ is required." -ForegroundColor Red
    exit 1
}
Write-Host "  Python $pyVersion OK"

function Find-FrontendToolchain {
    $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
    $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npmCommand) { $npmCommand = Get-Command npm -ErrorAction SilentlyContinue }
    if (-not $nodeCommand -or -not $npmCommand) { return $false }

    try {
        $script:nodeVersion = (& $nodeCommand.Source --version).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }
        $nodeSemver = [version]($script:nodeVersion -replace '^v', '')
        $nodeSupported = ($nodeSemver.Major -ge 22) -or ($nodeSemver.Major -eq 20 -and $nodeSemver -ge [version]"20.3.0")
        if (-not $nodeSupported) { return $false }
        $script:npmPath = $npmCommand.Source
        $script:npmVersion = (& $script:npmPath --version).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }
        if ([version]$script:npmVersion -lt [version]"9.6.5") { return $false }
        return $true
    } catch {
        return $false
    }
}

function Install-FrontendToolchain {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Host "ERROR: Node.js/npm is missing and winget is unavailable." -ForegroundColor Red
        Write-Host "Install App Installer (which provides winget) from Microsoft Store, then rerun setup." -ForegroundColor Yellow
        Write-Host "For a CLI/backend-only install, run: .\setup.ps1 -SkipFrontend" -ForegroundColor Yellow
        exit 1
    }

    Step "Installing or repairing Node.js LTS and npm with winget..."
    & $winget.Source install --id OpenJS.NodeJS.LTS --exact --force --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: winget could not install Node.js/npm. It may require administrator approval." -ForegroundColor Red
        exit 1
    }

    # winget updates the persistent PATH, but this PowerShell process has a stale copy.
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath;$env:Path"

    # Prefer the standard Node MSI location if it is not yet in PATH.
    $nodeInstallDir = Join-Path $env:ProgramFiles "nodejs"
    if ((Test-Path (Join-Path $nodeInstallDir "node.exe")) -and (Test-Path (Join-Path $nodeInstallDir "npm.cmd"))) {
        $env:Path = "$nodeInstallDir;$env:Path"
    }

    if (-not (Find-FrontendToolchain)) {
        Write-Host "ERROR: Node.js/npm was installed but could not be found in this PowerShell session." -ForegroundColor Red
        Write-Host "Close PowerShell, open it again, and rerun setup." -ForegroundColor Yellow
        exit 1
    }
}

# Check or bootstrap the frontend toolchain before Python package installation.
if (-not $SkipFrontend) {
    Step "Checking Node.js and npm..."
    if (-not (Find-FrontendToolchain)) { Install-FrontendToolchain }
    Write-Host "  Node.js $nodeVersion and npm $npmVersion OK"
}

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

# Add a user-local command that works from any directory without activating .venv.
$userBin = Join-Path $HOME ".local\bin"
New-Item -ItemType Directory -Force -Path $userBin | Out-Null
$launcher = Join-Path $userBin "hashcrack.cmd"
Set-Content -Path $launcher -Encoding ASCII -Value "@echo off`r`n`"$venvPython`" -m password_audit %*`r`n"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($pathEntries -notcontains $userBin) {
    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $userBin } else { "$userPath;$userBin" }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    $env:Path = "$userBin;$env:Path"
    Step "Added $userBin to your user PATH; new terminals will pick it up."
}
Step "Installed the local command: hashcrack"

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
Write-Host "Run the CLI:         hashcrack --help (from any directory)"
Write-Host ""
Write-Host "Authorized local auditing only - no remote targets, no network access."
