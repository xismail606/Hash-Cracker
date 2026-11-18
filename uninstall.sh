#!/usr/bin/env bash
# Remove the local Hash Cracker installation created by setup.sh.
# Usage: ./uninstall.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
user_bin="$HOME/.local/bin"
launcher="$user_bin/hashcrack"

echo "This will remove the Hash Cracker launcher and installed dependencies."
echo "Project files and audit history in $HOME/.hash_cracker will be kept."
read -r -p "Continue? (y/N) " answer
case "$answer" in
    y|Y|yes|YES|Yes) ;;
    *) echo "Uninstall cancelled."; exit 0 ;;
esac

if [ -f "$launcher" ]; then
    rm -- "$launcher"
    echo "Removed command launcher: $launcher"
fi

# setup.sh adds this exact line when it adds ~/.local/bin to PATH.
path_line='export PATH="$HOME/.local/bin:$PATH"'
for shell_profile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$shell_profile" ] && grep -F -q "$path_line" "$shell_profile"; then
        tmp_profile="$(mktemp "${shell_profile}.XXXXXX")"
        awk -v line="$path_line" '$0 != line' "$shell_profile" > "$tmp_profile"
        cat "$tmp_profile" > "$shell_profile"
        rm -- "$tmp_profile"
        echo "Removed the Hash Cracker PATH entry from $shell_profile"
    fi
done

for target in "$root/.venv" "$root/frontend/node_modules"; do
    if [ -d "$target" ]; then
        rm -rf -- "$target"
        echo "Removed $target"
    fi
done

echo "Uninstall complete. Audit history and project files were kept."
# Phase 11: the Rust backend lives in the project tree (rust/target); the
# rustup toolchain (~/.cargo, ~/.rustup) is a user-local install that other
# Rust projects may share - remove it manually only if desired:
#   rustup self uninstall
