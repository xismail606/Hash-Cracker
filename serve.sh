#!/usr/bin/env bash
# Launches the local web dashboard with the chosen backend (Phase 11):
#   Python (Flask) or Rust. The script asks when both are installed and
#   stdin is a TTY; --backend python|rust skips the prompt for scripts/CI.
#
# Usage:  ./serve.sh                     (asks when both installed; default port 8765)
#         ./serve.sh 9000
#         ./serve.sh --backend rust [port]
#         ./serve.sh [port] --backend python
set -euo pipefail

port="8765"
backend=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --backend=*) backend="${1#--backend=}" ;;
        --backend)
            shift
            backend="${1:-}"
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                port="$1"
            else
                echo "Unknown argument: $1" >&2
                echo "Usage: ./serve.sh [--backend python|rust] [port]" >&2
                exit 2
            fi
            ;;
    esac
    shift
done
if [ -n "$backend" ] && [ "$backend" != "python" ] && [ "$backend" != "rust" ]; then
    echo "Unknown backend: $backend" >&2
    echo "Usage: ./serve.sh [--backend python|rust] [port]" >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"

# Backend detection: Python venv vs the Rust release binary.
python_bin=""
if [ -x "$root/.venv/bin/python" ]; then
    python_bin="$root/.venv/bin/python"
elif [ -x "$root/.venv/Scripts/python.exe" ]; then
    python_bin="$root/.venv/Scripts/python.exe"
fi
for name in hashcrack-rs hashcrack-rs.exe; do
    if [ -x "$root/rust/target/release/$name" ]; then
        rust_bin="$root/rust/target/release/$name"
        break
    fi
done
rust_bin="${rust_bin:-}"

if [ -z "$backend" ]; then
    if [ -n "$python_bin" ] && [ -n "$rust_bin" ] && [ -t 0 ]; then
        echo "Which backend should serve the dashboard?"
        printf "  [1] Python  [2] Rust  (Enter=Python): "
        read -r choice
        case "${choice:-1}" in
            1|"") backend="python" ;;
            2) backend="rust" ;;
            *)
                echo "Unknown choice: $choice" >&2
                exit 2
                ;;
        esac
    elif [ -n "$python_bin" ]; then
        backend="python"
        if [ -n "$rust_bin" ]; then
            echo "[serve] Non-interactive run with both backends installed; serving Python."
        fi
    elif [ -n "$rust_bin" ]; then
        backend="rust"
        echo "[serve] Python backend not found; serving with Rust (run ./setup.sh --backend python if this is unexpected)."
    else
        echo "Neither backend is installed. Run setup first:" >&2
        echo "  ./setup.sh --backend python    (Python backend)" >&2
        echo "  ./setup.sh --backend rust      (Rust backend)" >&2
        exit 1
    fi
fi

case "$backend" in
    python)
        if [ -z "$python_bin" ]; then
            echo "The Python backend is not installed. Run: ./setup.sh --backend python" >&2
            exit 1
        fi
        exec "$python_bin" -m hash_cracker serve --port "$port"
        ;;
    rust)
        if [ -z "$rust_bin" ]; then
            echo "The Rust backend is not installed. Run: ./setup.sh --backend rust" >&2
            exit 1
        fi
        exec "$rust_bin" serve --port "$port"
        ;;
esac
