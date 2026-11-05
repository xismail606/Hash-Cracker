#!/usr/bin/env bash
# Launches the local web dashboard with the project's virtual environment,
# so ./serve.sh works without activating .venv first (Linux/macOS).
#
# Usage:  ./serve.sh              (default port 8765)
#         ./serve.sh 9000
set -euo pipefail

port="${1:-8765}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# venv layout differs by platform: bin/python on Linux/macOS,
# Scripts/python.exe on Windows (e.g. when run from Git Bash).
if [ -x "$root/.venv/bin/python" ]; then
    python_bin="$root/.venv/bin/python"
elif [ -x "$root/.venv/Scripts/python.exe" ]; then
    python_bin="$root/.venv/Scripts/python.exe"
else
    python_bin=""
fi

if [ -z "$python_bin" ]; then
    echo "The project virtual environment was not found at .venv/." >&2
    echo "Create it first (one-time setup):" >&2
    echo "  python3 -m venv .venv" >&2
    echo "  .venv/bin/python -m pip install -e ." >&2
    echo "  cd frontend && npm install && npm run build && cd .." >&2
    exit 1
fi

exec "$python_bin" -m password_audit serve --port "$port"
