#!/usr/bin/env bash
# One-command setup for Hash Cracker (Linux / macOS / Git Bash on Windows).
# Downloads/installs everything needed to run the project:
#   Python venv + package (with optional extras), Node deps, frontend build,
#   and (Phase 11) optionally the Rust backend with its own CLI.
#
# Usage:  ./setup.sh [--skip-frontend] [--backend python|rust|both]
#         Bare-Enter at the backend prompt installs Python (previous default).

set -euo pipefail

skip_frontend=false
backend=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-frontend) skip_frontend=true ;;
        --backend=*) backend="${1#--backend=}" ;;
        --backend)
            shift
            backend="${1:-}"
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: ./setup.sh [--skip-frontend] [--backend python|rust|both]" >&2
            exit 2
            ;;
    esac
    shift
done
if [ -n "$backend" ] && [ "$backend" != "python" ] && [ "$backend" != "rust" ] && [ "$backend" != "both" ]; then
    echo "Unknown backend: $backend" >&2
    echo "Usage: ./setup.sh [--skip-frontend] [--backend python|rust|both]" >&2
    exit 2
fi

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
if [ "$skip_frontend" = false ] && [ "$backend" != "rust" ]; then
    step "Checking Node.js and npm..."
    if ! node_toolchain_ready; then
        install_node_toolchain
    fi
fi

# --- Backend choice (Phase 11) ------------------------------------------------
# The operator picks which backend(s) to install: python (default), rust,
# or both. Non-interactive runs must pass --backend explicitly.
if [ -z "$backend" ]; then
    if [ -t 0 ]; then
        echo
        printf "Which backend should be installed? [1] Python [2] Rust [3] Both (Enter=Python): "
        read -r choice
        case "${choice:-1}" in
            1|"") backend="python" ;;
            2) backend="rust" ;;
            3) backend="both" ;;
            *)
                echo "Unknown choice: $choice" >&2
                exit 2
                ;;
        esac
    else
        echo "Non-interactive setup requires an explicit backend: --backend python|rust|both" >&2
        exit 2
    fi
fi

install_python_backend() {
    # --- 2. Virtual environment ---
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

    # --- 3. Python package + extras ---
    step "Installing the package with all extras (dev, encrypt, adaptive)..."
    "$venv_python" -m pip install --upgrade pip -q
    "$venv_python" -m pip install -e ".[dev,encrypt,adaptive]" -q
    step "Python dependencies installed."

    # Linux-only user command (unchanged behavior).
    if [ "$(uname -s)" = "Linux" ]; then
        user_bin="$HOME/.local/bin"
        launcher="$user_bin/hashcrack"
        mkdir -p "$user_bin"
        printf '#!/usr/bin/env bash\nexec %q -m hash_cracker "$@"\n' "$venv_python" > "$launcher"
        chmod 755 "$launcher"
        case ":$PATH:" in
            *":$user_bin:"*) ;;
            *)
                shell_name="$(basename "${SHELL:-bash}")"
                case "$shell_name" in
                    zsh) shell_profile="$HOME/.zshrc" ;;
                    bash) shell_profile="$HOME/.bashrc" ;;
                    *) shell_profile="$HOME/.profile" ;;
                esac
                path_line='export PATH="$HOME/.local/bin:$PATH"'
                if ! [ -f "$shell_profile" ] || ! grep -F -q "$path_line" "$shell_profile"; then
                    printf '\n# User-local command-line tools\n%s\n' "$path_line" >> "$shell_profile"
                fi
                echo "[setup] Added $user_bin to PATH in $shell_profile."
                echo "[setup] Open a new terminal or run: source $shell_profile"
                ;;
        esac
        step "Installed the local command: hashcrack"
    fi

    # --- 4. Node + frontend ---
    if [ "$skip_frontend" = true ]; then
        step "Skipping frontend build (--skip-frontend)."
    else
        step "Installing frontend dependencies (npm ci)..."
        (cd frontend && npm ci)
        step "Building the dashboard (npm run build)..."
        (cd frontend && npm run build)
    fi

    # --- 5. Verify ---
    step "Verifying the installation..."
    "$venv_python" -m pytest tests/ -q || {
        echo "WARNING: some tests failed — the tool may still run, but report issues." >&2
    }
}

install_rust_backend() {
    step "Checking the Rust toolchain..."
    cargo_bin=""
    if command -v cargo >/dev/null 2>&1; then
        cargo_bin="$(command -v cargo)"
    elif [ -x "$HOME/.cargo/bin/cargo" ]; then
        cargo_bin="$HOME/.cargo/bin/cargo"
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    if [ -z "$cargo_bin" ]; then
        step "Rust toolchain missing; installing rustup with the stable toolchain..."
        if command -v curl >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        elif command -v wget >/dev/null 2>&1; then
            wget -qO- https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        else
            echo "ERROR: curl or wget is required to install the Rust toolchain automatically." >&2
            return 1
        fi
        export PATH="$HOME/.cargo/bin:$PATH"
        cargo_bin="$HOME/.cargo/bin/cargo"
    fi
    if ! "$cargo_bin" --version >/dev/null 2>&1; then
        echo "ERROR: the Rust toolchain could not be provisioned; install rustup manually (https://rustup.rs) and rerun setup." >&2
        return 1
    fi
    echo "  $($cargo_bin --version) OK"

    step "Building the Rust backend (cargo build --release)..."
    (cd rust && "$cargo_bin" build --release)
    for name in hashcrack-rs hashcrack-rs.exe; do
        if [ -x "rust/target/release/$name" ]; then
            step "Rust backend installed: rust/target/release/$name"
            return 0
        fi
    done
    echo "ERROR: the Rust backend build did not produce the hashcrack-rs binary." >&2
    return 1
}

python_failed=false
rust_failed=false
if [ "$backend" = "python" ] || [ "$backend" = "both" ]; then
    install_python_backend || python_failed=true
fi
if [ "$backend" = "rust" ] || [ "$backend" = "both" ]; then
    install_rust_backend || rust_failed=true
fi
if [ "$python_failed" = true ] || [ "$rust_failed" = true ]; then
    echo >&2
    [ "$python_failed" = true ] && echo "ERROR: the Python backend installation failed." >&2
    [ "$rust_failed" = true ] && echo "ERROR: the Rust backend installation failed." >&2
    exit 1
fi

echo
echo "Setup complete!"
echo
if [ "$backend" = "rust" ]; then
    echo "Run the dashboard:   ./serve.sh --backend rust  (http://127.0.0.1:8765)"
    echo "Run the CLI:         hashcrack-rs --help"
elif [ "$backend" = "both" ]; then
    echo "Run the dashboard:   ./serve.sh            (asks: Python or Rust)"
    echo "Run the CLI:         hashcrack --help | hashcrack-rs --help"
else
    echo "Run the dashboard:   ./serve.sh            (http://127.0.0.1:8765)"
    echo "Run the CLI:         hashcrack --help (from any directory)"
fi
echo
echo "Authorized local auditing only — no remote targets, no network access."
