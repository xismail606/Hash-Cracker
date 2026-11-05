#!/usr/bin/env bash
# One-command setup for Hash Cracker (Linux / macOS / Git Bash on Windows).
# Downloads/installs everything needed to run the project:
#   Python venv + package (with optional extras), Node deps, frontend build.
#
# Usage:  ./setup.sh [--skip-frontend]

set -euo pipefail

skip_frontend=false
[ "${1:-}" = "--skip-frontend" ] && skip_frontend=true

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

step() { echo "[setup] $1"; }

# --- 1. Python ------------------------------------------------------------
step "Checking Python (3.11+)..."
# Prefer python3, but fall back to python when python3 is a broken shim
# (e.g. the Windows Store alias inside Git Bash).
PYTHON=""
for candidate in python3 python; do
    if candidate_version=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null); then
        PYTHON="$candidate"
        py_version="$candidate_version"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.11+ was not found on PATH. Install it from https://python.org" >&2
    exit 1
fi
major="${py_version%%.*}"; minor="${py_version##*.}"
if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 11 ]; }; then
    echo "ERROR: Python $py_version found; 3.11+ is required." >&2
    exit 1
fi
echo "  Python $py_version OK"

# --- 2. Virtual environment -------------------------------------------------
# venv layout differs: bin/ on Linux/macOS, Scripts/ on Windows (Git Bash).
if [ -x "$root/.venv/bin/python" ]; then
    venv_python="$root/.venv/bin/python"
elif [ -x "$root/.venv/Scripts/python.exe" ]; then
    venv_python="$root/.venv/Scripts/python.exe"
else
    step "Creating virtual environment (.venv)..."
    "$PYTHON" -m venv .venv
    if [ -x "$root/.venv/bin/python" ]; then
        venv_python="$root/.venv/bin/python"
    else
        venv_python="$root/.venv/Scripts/python.exe"
    fi
fi
step "Virtual environment ready."

# --- 3. Python package + extras ----------------------------------------------
step "Installing the package with all extras (dev, encrypt, adaptive)..."
"$venv_python" -m pip install --upgrade pip -q
"$venv_python" -m pip install -e ".[dev,encrypt,adaptive]" -q
step "Python dependencies installed."

# --- 4. Node + frontend -------------------------------------------------------
if [ "$skip_frontend" = true ]; then
    step "Skipping frontend build (--skip-frontend)."
else
    if ! command -v node >/dev/null 2>&1; then
        echo "ERROR: Node.js was not found on PATH. Install Node 18+ from https://nodejs.org" >&2
        exit 1
    fi
    step "Installing frontend dependencies (npm install)..."
    (cd frontend && npm install)
    step "Building the dashboard (npm run build)..."
    (cd frontend && npm run build)
fi

# --- 5. Verify -----------------------------------------------------------------
step "Verifying the installation..."
"$venv_python" -m pytest tests/ -q || {
    echo "WARNING: some tests failed — the tool may still run, but report issues." >&2
}

echo
echo "Setup complete!"
echo
echo "Run the dashboard:   ./serve.sh            (http://127.0.0.1:8765)"
echo "Run the CLI:         .venv/bin/python -m password_audit --help"
echo
echo "Authorized local auditing only — no remote targets, no network access."
