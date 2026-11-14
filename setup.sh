#!/usr/bin/env bash
# One-command setup for Hash Cracker (Linux / macOS / Git Bash on Windows).
# Downloads/installs everything needed to run the project:
#   Python venv + package (with optional extras), Node deps, frontend build.
#
# Usage:  ./setup.sh [--skip-frontend]

set -euo pipefail

skip_frontend=false
if [ "$#" -gt 1 ]; then
    echo "Usage: ./setup.sh [--skip-frontend]" >&2
    exit 2
fi
case "${1:-}" in
    "") ;;
    --skip-frontend) skip_frontend=true ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Usage: ./setup.sh [--skip-frontend]" >&2
        exit 2
        ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

step() { echo "[setup] $1"; }

node_toolchain_ready() {
    command -v node >/dev/null 2>&1 || return 1
    command -v npm >/dev/null 2>&1 || return 1

    local version node_number major minor patch npm_ver npm_major npm_minor npm_patch
    version=$(node --version 2>/dev/null) || return 1
    node_number=${version#v}
    IFS=. read -r major minor patch <<< "$node_number"
    patch=${patch%%-*}
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    if [ "$major" -lt 22 ] && ! { [ "$major" -eq 20 ] && [ "$minor" -ge 3 ]; }; then
        return 1
    fi

    npm_ver=$(npm --version 2>/dev/null) || return 1
    IFS=. read -r npm_major npm_minor npm_patch <<< "$npm_ver"
    npm_patch=${npm_patch%%[-+]*}
    [[ "$npm_major" =~ ^[0-9]+$ && "$npm_minor" =~ ^[0-9]+$ && "$npm_patch" =~ ^[0-9]+$ ]] || return 1
    if [ "$npm_major" -lt 9 ] || { [ "$npm_major" -eq 9 ] && { [ "$npm_minor" -lt 6 ] || { [ "$npm_minor" -eq 6 ] && [ "$npm_patch" -lt 5 ]; }; }; }; then
        return 1
    fi

    echo "  Node.js $version and npm $npm_ver OK"
}

install_node_toolchain() {
    step "Node.js/npm is missing or incompatible; installing the latest LTS Node.js with npm for this user..."

    if [ -z "${NVM_DIR:-}" ]; then
        if [ -n "${XDG_CONFIG_HOME:-}" ]; then
            NVM_DIR="$XDG_CONFIG_HOME/nvm"
        else
            NVM_DIR="$HOME/.nvm"
        fi
    fi
    export NVM_DIR

    if ! command -v nvm >/dev/null 2>&1; then
        if [ ! -s "$NVM_DIR/nvm.sh" ]; then
            nvm_installer="https://raw.githubusercontent.com/nvm-sh/nvm/v0.41.0/install.sh"
            if command -v curl >/dev/null 2>&1; then
                curl -fsSL "$nvm_installer" | bash
            elif command -v wget >/dev/null 2>&1; then
                wget -qO- "$nvm_installer" | bash
            else
                echo "ERROR: curl or wget is required to install Node.js automatically." >&2
                exit 1
            fi
        fi
        if [ ! -s "$NVM_DIR/nvm.sh" ]; then
            echo "ERROR: nvm installation did not create $NVM_DIR/nvm.sh." >&2
            exit 1
        fi
        # shellcheck disable=SC1090
        . "$NVM_DIR/nvm.sh"
    fi

    nvm install --lts
    nvm use --lts
    if ! node_toolchain_ready; then
        echo "ERROR: Node.js/npm installation completed, but the tools are still unavailable." >&2
        exit 1
    fi
}

# Preflight all runtimes before installing or changing anything.
step "Checking Python (3.11+)..."
PYTHON=""
for candidate in python3 python; do
    if candidate_version=$($candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null); then
        PYTHON="$candidate"
        py_version="$candidate_version"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.11+ is missing. Install Python, then rerun setup." >&2
    exit 1
fi
major="${py_version%%.*}"; minor="${py_version##*.}"
if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 11 ]; }; then
    echo "ERROR: Python $py_version found; 3.11+ is required." >&2
    exit 1
fi
echo "  Python $py_version OK"

# Only after preflight, install the missing frontend runtime if needed.
if [ "$skip_frontend" = false ]; then
    step "Checking Node.js and npm..."
    if ! node_toolchain_ready; then
        install_node_toolchain
    fi
fi

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
    step "Installing frontend dependencies (npm ci)..."
    (cd frontend && npm ci)
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
