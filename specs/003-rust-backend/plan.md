# Implementation Plan: Rust Backend (Phase 11)

**Branch**: none — working tree only (branch creation skipped per operator instruction: no git operations this round) | **Date**: 2026-11-18 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-rust-backend/spec.md`

## Summary

Add a functionally equivalent second backend written in Rust alongside the existing Python backend. The Rust workspace re-implements the engine (23-format catalog, dictionary/brute-force/hashlist modes, rules, budgets, pause/resume, benchmark), the CLI surface, and the exact Flask REST contract so the existing React dashboard runs unchanged against either backend. Both backends share one SQLite history store (plus a backend-attribution column) and the same Fernet/scrypt plaintext-encryption scheme, so runs, unlock, and export work across backends. The setup scripts gain an install-choice prompt (Python / Rust / Both, with automatic Rust toolchain provisioning); the serve scripts gain a backend-choice prompt with a non-interactive override. Phase 11 continues the established numbering: tasks run T077 onward.

## Technical Context

**Language/Version**: Rust (stable, edition 2021) — installed on demand by the setup scripts via rustup; Python 3.11+ (existing, unchanged except additive attribution support in `history.py` and record-attribution call sites)

**Primary Dependencies** (Rust crates): `axum` + `tokio` (HTTP server), `tower-http` (static support helpers), `serde`/`serde_json` (JSON), `clap` v4 derive (CLI), `rusqlite` (SQLite, `bundled` feature), `md-5`, `sha1`, `sha2`, `ripemd`, `md-4`, `des` (LM), `bcrypt`, `sha-crypt` (sha512crypt), `fernet` + `scrypt` (encryption-at-rest compatibility), `rayon` (worker pool), `time` or `chrono` (millisecond-UTC timestamps), `uuid`, `tempfile`. Crate availability for `phpass` is verified during implementation (fallback: small in-crate portable-phpass implementation validated against Passlib vectors).

**Storage**: shared SQLite database `~/.hash_cracker/history.db` (schema extended additively with a `backend` attribution column via the existing `MIGRATION_COLUMNS` pattern); `<db dir>/paused_jobs/<job_id>.json` sidecar for restart-recoverable paused jobs; `history_meta` rows `enc_salt`/`enc_verify` for encryption.

**Testing**: `cargo test` (unit + integration, in-crate), plus a Python-side pytest compatibility shim that runs cross-backend parity vectors (shared DB read/write, unlock across backends); existing pytest suite must keep passing.

**Target Platform**: Windows and Linux/macOS (Git Bash) — loopback-only local server, port 8765 default.

**Project Type**: CLI + local web service (second backend instance of an existing tool).

**Performance Goals**: fast-hash dictionary throughput at least equal to the Python backend on the same machine (SC-007); expected to exceed it materially since the Rust engine uses threads over the Python spawn-based process pool; API responses comparable latency.

**Constraints**: exact behavioral parity (statuses, budget accounting, attempt math, format identifiers, ambiguity groups, API JSON shapes, CSRF semantics, CSV column order, timestamp format `YYYY-MM-DDTHH:MM:SS.mmmZ`); loopback-only binding; single dashboard job at a time (409 otherwise); 256 MiB upload cap; budget 1–10,000,000; workers 1–8; offline tool (no network calls); no git operations anywhere in this round.

**Scale/Scope**: 23 hash formats, 4 rule presets, 4 charset presets, 14 API routes, 6 CLI subcommands, 4 script files (setup/serve × sh/ps1), one Rust workspace with engine + server + CLI binaries.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

The project constitution file is the unfilled Spec Kit template (no ratified principles). Gates therefore fall back to the project's established working practices (documented in v1/v2 plans and the operator's standing instructions):

- **Test-first**: each Rust module lands with vector tests (RFC 1320, RFC 3174 family, hashcat example hashes, Passlib adaptive vectors) before engine integration — matches the v1/v2 practice. PASS.
- **Safety boundaries unchanged**: local-only processing, loopback-only server, bounded candidate work, honest identification, retention warning — all preserved verbatim in the Rust backend contract. PASS.
- **No git operations** (operator instruction, FR-213): branch creation skipped; all artifacts in the working tree. PASS (documented deviation from default speckit flow).
- **Guard skills**: clean-code-guard, test-guard, docs-guard run on the produced code/tests/docs during implementation. PASS.

Post-Phase-1 re-check: design stays within the same gates — the shared-store/encryption parameters are pinned byte-for-byte in `contracts/storage.md` so cross-backend compatibility is testable. PASS.

## Project Structure

### Documentation (this feature)

```text
specs/003-rust-backend/
├── plan.md              # This file ($speckit-plan command output)
├── research.md          # Phase 0 output: crate/toolchain decisions
├── data-model.md        # Phase 1 output: shared store, sidecar, attribution
├── quickstart.md        # Phase 1 output: end-to-end validation guide
├── contracts/           # Phase 1 output
│   ├── api.md           # REST contract the Rust server must match exactly
│   ├── cli.md           # CLI surface contract (parity surface)
│   ├── storage.md       # SQLite schema, sidecar JSON, encryption parameters
│   └── installer.md     # setup/serve script behavioral contract (sh + ps1)
└── tasks.md             # Phase 2 output ($speckit-tasks command)
```

### Source Code (repository root)

```text
rust/                             # NEW — the second backend (Cargo workspace)
├── Cargo.toml                    # workspace manifest (members below)
├── crates/
│   ├── hc-core/                  # engine: formats, hashing, candidates, bruteforce,
│   │   │                         # rules, engine loops, budget accounting, benchmark
│   │   └── src/
│   ├── hc-history/               # shared SQLite store, Fernet/scrypt encryption,
│   │   │                         # CSV/JSON export, paused-jobs sidecar
│   │   └── src/
│   ├── hc-server/                # axum server: exact REST contract + static serving
│   │   └── src/
│   └── hc-cli/                   # clap CLI binary `hashcrack-rs` (identify, audit,
│       └── src/                  # history, export, benchmark, serve)
tests/                            # existing pytest suite (unchanged) + new parity shim
├── test_rust_parity.py           # cross-backend parity tests (pytest, optional skip)
setup.sh / setup.ps1              # MODIFIED — backend-choice prompt (python/rust/both)
serve.sh / serve.ps1              # MODIFIED — backend-choice prompt + --backend override
src/hash_cracker/history.py       # MODIFIED — additive `backend` attribution column
frontend/                         # unchanged (served by either backend)
```

**Structure Decision**: a new self-contained Cargo workspace at `rust/` mirrors how `src/hash_cracker` encapsulates the Python backend — neither backend imports from the other; they share only the SQLite store, the sidecar format, and the API contract (all pinned in `contracts/`). Four crates keep the engine testable without a server and the server testable without a TTY. Script edits stay in the existing four files rather than adding wrappers, honoring "the installer file that exists".

## Complexity Tracking

> No constitution violations. The one intentional deviation — skipping git branch creation during specify — is operator-mandated (FR-213), not a design complexity.
