# One-command setup for Hash Cracker (Windows).
# Downloads/installs everything needed to run the project:
#   Python venv + package (with optional extras), Node deps, frontend build,
#   and (Phase 11) optionally the Rust backend with its own CLI.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\setup.ps1
#         .\setup.ps1 -SkipFrontend                (skip the npm steps)
#         .\setup.ps1 -Backend python|rust|both    (skip the backend prompt)

param(
    [switch]$SkipFrontend,
    [string]$Backend = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step($msg) { Write-Host "[setup] $msg" -ForegroundColor Cyan }

# Preflight Python only when the Python backend may be installed.
if ($Backend -ne "rust") {
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
}

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
if (-not $SkipFrontend -and ($Backend -eq "" -or $Backend -eq "python" -or $Backend -eq "both")) {
    Step "Checking Node.js and npm..."
    if (-not (Find-FrontendToolchain)) { Install-FrontendToolchain }
    Write-Host "  Node.js $nodeVersion and npm $npmVersion OK"
}

# --- Backend choice (Phase 11) -------------------------------------------------
# The operator picks which backend(s) to install: python (default), rust,
# or both. Non-interactive runs must pass -Backend explicitly.
if ($Backend -eq "") {
    $choice = Read-Host "Which backend should be installed? [1] Python [2] Rust [3] Both (Enter=Python)"
    switch ($choice) {
        ""    { $Backend = "python" }
        "1"   { $Backend = "python" }
        "2"   { $Backend = "rust" }
        "3"   { $Backend = "both" }
        default {
            Write-Host "Unknown choice: $choice" -ForegroundColor Red
            exit 2
        }
    }
}
if ($Backend -ne "python" -and $Backend -ne "rust" -and $Backend -ne "both") {
    Write-Host "Unknown backend: $Backend" -ForegroundColor Red
    Write-Host "Usage: .\setup.ps1 [-SkipFrontend] [-Backend python|rust|both]"
    exit 2
}

function Find-RustToolchain {
    $cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if (-not $cargo) { $cargo = Get-Command cargo -ErrorAction SilentlyContinue }
    if (-not $cargo) {
        $cargoHome = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
        if (Test-Path $cargoHome) { return $cargoHome }
        return $null
    }
    return $cargo.Source
}

function Install-RustBackend {
    Step "Checking the Rust toolchain..."
    $cargo = Find-RustToolchain
    if (-not $cargo) {
        Step "Rust toolchain missing; installing rustup with the stable toolchain..."
        $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
        try {
            Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
        } catch {
            Write-Host "ERROR: could not download rustup-init.exe (network unavailable?)." -ForegroundColor Red
            return $false
        }
        & $rustupInit -y --default-toolchain stable
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: rustup installation failed." -ForegroundColor Red
            return $false
        }
        $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
        $cargo = Find-RustToolchain
    }
    if (-not $cargo) {
        Write-Host "ERROR: the Rust toolchain could not be provisioned; install rustup manually (https://rustup.rs) and rerun setup." -ForegroundColor Red
        return $false
    }
    Write-Host "  $(& $cargo --version) OK"

    Step "Building the Rust backend (cargo build --release)..."
    Push-Location rust
    & $cargo build --release
    $buildOk = ($LASTEXITCODE -eq 0)
    Pop-Location
    if (-not $buildOk) {
        Write-Host "ERROR: the Rust backend build failed." -ForegroundColor Red
        return $false
    }
    Step "Rust backend installed: rust\target\release\hashcrack-rs.exe"
    return $true
}

function Install-PythonBackend {
    # --- 2. Virtual environment ---
    $script:venvPython = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        Step "Creating virtual environment (.venv)..."
        & python -m venv .venv
    } else {
        Step "Virtual environment already exists; reusing it."
    }

    # --- 3. Python package + extras ---
    Step "Installing the package with all extras (dev, encrypt, adaptive)..."
    & $venvPython -m pip install --upgrade pip -q
    & $venvPython -m pip install -e ".[dev,encrypt,adaptive]" -q
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: pip install failed." -ForegroundColor Red
        return $false
    }
    Write-Host "  Python dependencies installed"

    # Add a user-local command that works from any directory without activating .venv.
    $userBin = Join-Path $HOME ".local\bin"
    New-Item -ItemType Directory -Force -Path $userBin | Out-Null
    $launcher = Join-Path $userBin "hashcrack.cmd"
    Set-Content -Path $launcher -Encoding ASCII -Value "@echo off`r`n`"$venvPython`" -m hash_cracker %*`r`n"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ';' | Where-Object { $_ })
    if ($pathEntries -notcontains $userBin) {
        $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $userBin } else { "$userPath;$userBin" }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        $env:Path = "$userBin;$env:Path"
        Step "Added $userBin to your user PATH; new terminals will pick it up."
    }
    Step "Installed the local command: hashcrack"

    # --- 4. Node + frontend ---
    if ($SkipFrontend) {
        Step "Skipping frontend build (-SkipFrontend)."
    } else {
        Step "Installing frontend dependencies (npm ci)..."
        Push-Location frontend
        & $npmPath ci
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: npm ci failed." -ForegroundColor Red
            Pop-Location
            return $false
        }
        Step "Building the dashboard (npm run build)..."
        & $npmPath run build
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: frontend build failed." -ForegroundColor Red
            Pop-Location
            return $false
        }
        Pop-Location
    }

    # --- 5. Verify ---
    Step "Verifying the installation..."
    & $venvPython -m pytest tests/ -q
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: some tests failed - the tool may still run, but report issues." -ForegroundColor Yellow
    }
    return $true
}

$pythonFailed = $false
$rustFailed = $false
if ($Backend -eq "python" -or $Backend -eq "both") {
    if (-not (Install-PythonBackend)) { $pythonFailed = $true }
}
if ($Backend -eq "rust" -or $Backend -eq "both") {
    if (-not (Install-RustBackend)) { $rustFailed = $true }
}
if ($pythonFailed -or $rustFailed) {
    Write-Host ""
    if ($pythonFailed) { Write-Host "ERROR: the Python backend installation failed." -ForegroundColor Red }
    if ($rustFailed) { Write-Host "ERROR: the Rust backend installation failed." -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
if ($Backend -eq "rust") {
    Write-Host "Run the dashboard:   .\serve.ps1 -Backend rust   (http://127.0.0.1:8765)"
    Write-Host "Run the CLI:         hashcrack-rs --help"
} elseif ($Backend -eq "both") {
    Write-Host "Run the dashboard:   .\serve.ps1        (asks: Python or Rust)"
    Write-Host "Run the CLI:         hashcrack --help | hashcrack-rs --help"
} else {
    Write-Host "Run the dashboard:   .\serve.ps1        (http://127.0.0.1:8765)"
    Write-Host "Run the CLI:         hashcrack --help (from any directory)"
}
Write-Host ""
Write-Host "Authorized local auditing only - no remote targets, no network access."
