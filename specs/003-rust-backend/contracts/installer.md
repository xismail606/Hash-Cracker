# Contract: Install & serve scripts (setup.sh/setup.ps1, serve.sh/serve.ps1)

Both script flavors implement identical behavior. The prompts are the operator-facing feature; overrides keep scripts/CI non-interactive.

## setup.sh / setup.ps1

- New flag `--backend <python|rust|both>` (and `--skip-frontend` stays). When absent **and stdin is a TTY**, prompt: `Which backend should be installed? [1] Python [2] Rust [3] Both` — bare Enter ⇒ **Python** (preserves today's default). When absent and non-interactive, fail with usage help rather than guessing. Invalid value → usage error exit 2.
- **Python path** (unchanged behavior): venv + `pip install -e .` + frontend build steps as today.
- **Rust path**: (1) toolchain check — `cargo` present and usable, else provision rustup stable user-locally (POSIX: `rustup-init` via `https://sh.rustup.rs -y --default-toolchain stable`; Windows: download `rustup-init.exe` from `https://win.rustup.rs/x86_64` and run `-y --default-toolchain stable`), mirroring the existing Node.js provisioning pattern including its clear failure message on network/tool failure; (2) `cargo build --release` in `rust/`; (3) install the binary where the serve scripts expect it (`rust/target/release/hashcrack-rs.exe` / `hashcrack-rs`).
- **Both**: python path then rust path. A failed Rust path must not undo the Python install (and vice versa); the script reports which side failed.
- Choosing an already-installed backend is a no-op refresh (re-run of that path), never a removal of the other.
- Exit codes: 0 success; 2 usage; 1 failure (message names the failed step and backend).

## serve.sh / serve.ps1

- New flag `--backend <python|rust>`; remaining positional port argument unchanged (`./serve.sh [port]`, combined forms allowed in either order).
- Backend detection: Python = venv python found (existing logic); Rust = release binary found at `rust/target/release/hashcrack-rs(.exe)`.
- When `--backend` absent **and stdin is a TTY** and **both** backends installed: prompt `Which backend should serve the dashboard? [1] Python [2] Rust` (bare Enter ⇒ Python). When absent and only one installed: start it with a note (`Rust backend not installed; serving with Python.` / `Python backend not found; serving with Rust (run ./setup.sh --backend rust first if this is unexpected).`). When neither: fail with the existing setup instructions plus the Rust line.
- With `--backend` given: no prompt; if that backend is missing, fail with a message telling which setup command installs it (exit 1). Non-interactive + no flag + both installed ⇒ Python without prompting (explicit note).
- Launch: Python ⇒ existing `python -m hash_cracker serve --port N`; Rust ⇒ `hashcrack-rs serve --port N`. Both bind 127.0.0.1 and serve the same static build.

## uninstall.sh / uninstall.ps1 (touchpoint only)

Must remain functional: extend removal notes to mention the Rust toolchain/binary as optional extras (no forced removal).
