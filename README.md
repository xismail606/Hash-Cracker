<!-- ===================== HEADER ===================== -->
<div align="center">
  <img 
    src="https://capsule-render.vercel.app/api?type=waving&color=gradient&text=Hash%20Cracker&height=140&section=header"
    alt="Hash Cracker Header"
    width="100%"
  />
</div>

# Hash Cracker

[![CI](https://github.com/xismail606/hash-cracker/actions/workflows/ci.yml/badge.svg)](https://github.com/xismail606/hash-cracker/actions/workflows/ci.yml)

A Python-based offline hash-cracking and password-auditing project. It identifies supported hash formats, compares a target against either a supplied dictionary or a bounded brute-force search, provides both a CLI and local web dashboard, and stores audit results in SQLite.

> **Project status: Implemented.** All 33 v1 tasks and the v2 feature expansion (salted formats, hashlists, mutation rules, benchmark, pause/resume, dashboard export/ETA, plaintext withholding/encryption, RIPEMD-160 and adaptive formats) are complete, backed by a 145-test pytest suite and CI. See the [quickstart](specs/001-offline-password-audit/quickstart.md) for setup and validated scenarios.

## Project Overview

The project demonstrates hash structure analysis, candidate generation, multiprocessing, CLI and web interface development, and local audit reporting. It is designed for authorized assessment of hashes and candidate inputs controlled by the operator. Hash checks run locally; the application does not attempt logins or contact remote targets.

Both interfaces call the same Python audit engine. The engine supports:

- **Dictionary mode**: compare the target against each entry in a finite local wordlist, with optional mutation rules (leetspeak, digit suffixes, …).
- **Hashlist mode**: audit many targets (one per line in a hashlist file) against one candidate stream in a single pass.
- **Benchmark**: per-algorithm candidates/second on this machine (`benchmark` command).
- **Pause/resume** dashboard jobs, **ETA** display, CSV/JSON **export from the dashboard**, and an option to **withhold plaintext** or **encrypt it at rest** (passphrase-based).
- **Brute-force mode**: generate candidates from a selected character set and length range, stopping at a configured candidate budget.
- **Dashboard Auto-fit**: fills charset, length, and budget fields with a complete search space within the 10,000,000-candidate hard limit. It cannot infer the plaintext length; ambiguous algorithms still require a manual choice.

## Supported Hashes

| Algorithm   | Format                     | Support                        |
| ----------- | -------------------------- | ------------------------------ |
| LM          | 16 hexadecimal characters  | Yes                            |
| MD5         | 32 hexadecimal characters  | Yes                            |
| NTLM        | 32 hexadecimal characters  | Yes                            |
| MD4         | 32 hexadecimal characters  | Yes                            |
| SHA-1       | 40 hexadecimal characters  | Yes                            |
| SHA-224     | 56 hexadecimal characters  | Yes                            |
| SHA-256     | 64 hexadecimal characters  | Yes                            |
| SHA-384     | 96 hexadecimal characters  | Yes                            |
| SHA-512     | 128 hexadecimal characters | Yes                            |
| RIPEMD-160  | 40 hexadecimal characters  | Yes (pure-Python, hashcat 600) |
| SHA-512/224 | 56 hexadecimal characters  | Yes                            |
| SHA-512/256 | 64 hexadecimal characters  | Yes                            |
| bcrypt      | full hash string ($2…)     | Yes (slow — see note)          |
| sha512crypt | full hash string ($6$…)    | Yes (slow — see note)          |
| phpass      | full hash string ($P$…)    | Yes (slow — see note)          |

Hash length and character structure help identify a format, but do not always prove the algorithm. MD5, NTLM, and MD4 share the same 32-character hexadecimal shape. The tool reports all three and requires an explicit selection. NTLM uses Passlib's `nthash`; LM uses Passlib's `lmhash` and compares only the first 8-byte DES block (16 hex), matching the format hashcat uses — a 16-hex LM target identifies passwords by their first seven characters. MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 use Python's `hashlib`; MD4 reuses the pure-Python MD4 implementation from the NTLM fallback (validated against RFC 1320 test vectors). RIPEMD-160 is a dependency-free pure-Python implementation validated against the official test vectors. Adaptive formats (bcrypt, sha512crypt, phpass) verify against the full stored hash string via Passlib and are extremely slow — keep their brute-force budgets small (the `benchmark` command reports real per-algorithm throughput). Eight salted fast-hash formats are also supported (`md5($pass.$salt)`, `md5($salt.$pass)`, `sha1($pass.$salt)`, `sha1($salt.$pass)`, `sha256($pass.$salt)`, `sha256($salt.$pass)`, `sha512($pass.$salt)`, `sha512($salt.$pass)`) — pass the known salt with `--salt` (CLI) or the dashboard salt field.

## Features in Scope

- Automatic structure-based hash assessment with explicit selection for ambiguous shapes.
- Dictionary and bounded brute-force candidate modes.
- Multiprocessing to use multiple CPU cores, with a user-visible worker limit from 1 through 8.
- Candidate progress, total attempts, elapsed time, worker count, match/no-match status, and recovered plaintext.
- Both a CLI and local web dashboard.
- SQLite history including successful `plaintext : hash` pairs, attempts, elapsed time, algorithm, mode, workers, status, and timestamp.
- CSV/JSON export of local audit history.
- Local-only web application and local-only input processing.

## Workload Limits and Safety

- Brute-force runs require an explicit character set and minimum/maximum lengths.
- The default candidate budget is 1,000,000; the hard maximum is 10,000,000 candidates per run.
- Worker count defaults to 4 and cannot exceed 8.
- Wordlist uploads through the web dashboard are limited to 256 MiB; the CLI can use a larger local file.
- The web application binds to `127.0.0.1`, and state-changing browser requests use same-origin/CSRF protection.
- Successful plaintext/hash pairs are saved to local SQLite because the project brief requires them. The operator receives a sensitive-data warning before a run.
- Only hashes and candidate inputs the operator is authorized to assess should be used. The project does not support login attempts, remote targets, or external data transfer.

## Technology Stack

| Technology                       | Role                                                                                                      |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Python 3.11+**                 | Hash analysis, audit engine, candidate processing, multiprocessing, CLI, Flask backend, and SQLite access |
| **`hashlib`**                    | MD5, SHA-1/224/256/384/512, SHA-512/224, and SHA-512/256 candidate hashing                                |
| **Passlib**                      | NTLM and LM candidate hashing; bcrypt, sha512crypt, and phpass verification                               |
| **Pure-Python MD4 / RIPEMD-160** | Dependency-free fallback implementations validated against official test vectors                          |
| **Flask**                        | Local web server and JSON API                                                                             |
| **Astro**                        | Build the dashboard as static assets                                                                      |
| **React**                        | Interactive hash, audit, progress, and result components                                                  |
| **JavaScript**                   | Browser-side API requests and progress updates                                                            |
| **Tailwind CSS**                 | Dashboard styling                                                                                         |
| **SQLite**                       | Local audit history and result reporting                                                                  |
| **Node.js/npm**                  | Frontend dependency installation and build                                                                |

### Go and Python

Go and Python can be used together, but the current plan does not use Go. Python already owns the core, CLI, and Flask server; adding a Go backend would introduce a second service and cross-language coordination without a requirement in the assignment.

## How the Application Works

1. The user submits a target hash through the CLI or dashboard.
2. The identifier checks its character structure and length, then lists compatible algorithms. If the shape is ambiguous, the user must select one.
3. The user chooses dictionary, brute-force, or hashlist mode and provides the mode-specific inputs.
4. The Python engine processes candidates with a bounded process pool, reporting progress and attempts.
5. Processing stops on a match, cancellation, or candidate budget.
6. SQLite records the run metadata. A successful run includes the recovered plaintext and target hash for reporting.

```mermaid
flowchart LR
    CLI[Python CLI] --> CORE[Shared Python audit engine]
    UI[Astro and React dashboard] --> API[Loopback Flask API]
    API --> CORE
    CORE --> DICT[Local wordlist]
    CORE --> BF[Bounded brute-force generator]
    CORE --> DB[(Local SQLite history)]
```

## Usage Guide

After running the setup script on Windows or Linux, the `hashcrack` command
works from any directory. With a manual install, activate `.venv` first.
macOS users can run `.venv/bin/hashcrack` after installing into the venv.
Exit codes:
**0** success, **1** invalid input, **2** cancelled/interrupted, **3** storage
failure. Run `hashcrack --help` for the full option list.

Examples:

```bash
hashcrack identify 8743b52063cd84097a65d1633f5c74f5
hashcrack audit HASH --algorithm sha256 --mode brute-force --charset lower,digits --min-length 1 --max-length 4
```

The dashboard remains tied to the project: start it from the project folder
with `./serve.sh` on Linux/macOS or `.\serve.ps1` on Windows.

### 1. Identify a hash

```bash
hashcrack identify 8743b52063cd84097a65d1633f5c74f5
# → 32-hex shapes are ambiguous: MD5 / NTLM / MD4 — choose explicitly
hashcrack identify 127e6fbf...  # 64-hex: SHA-256 or SHA-512/256
hashcrack identify b89eaac7...  # 40-hex: SHA-1 or RIPEMD-160
hashcrack identify 299bd128c1101fd6  # 16-hex: LM
hashcrack identify '$2a$05$...'  # prefix-recognized: bcrypt
```

Supported shapes: LM (16), MD5/NTLM/MD4 (32, ambiguous), SHA-1/RIPEMD-160 (40,
ambiguous), SHA-224/SHA-512-224 (56, ambiguous), SHA-256/SHA-512-256 (64,
ambiguous), SHA-384 (96), SHA-512 (128). Adaptive formats (bcrypt `$2…`,
sha512crypt `$6$…`, phpass `$P$…`) are recognized by prefix — the full stored
hash string is the target.

### 2. Dictionary audit (wordlist)

Create a local UTF-8 wordlist — one candidate per line — and audit a target
against it:

```bash
# words.txt contains: hashcat, password, 123456, ...
hashcrack audit 8743b52063cd84097a65d1633f5c74f5 \
    --algorithm md5 --mode dictionary --wordlist words.txt --workers 4
```

Behavior: only line endings are stripped; duplicates are attempted in order;
blank lines count as attempts; invalid UTF-8 bytes are replaced (never fatal).
A match prints the plaintext/hash pair and stores it in local SQLite after
the retention acknowledgement (`--yes` skips the interactive prompt,
`--no-store-plaintext` records the match without the plaintext).

### 3. Brute-force audit (bounded)

```bash
hashcrack audit 8743b52063cd84097a65d1633f5c74f5 \
    --algorithm md5 --mode brute-force \
    --charset lower,digits --min-length 1 --max-length 4 \
    --max-candidates 10000 --workers 4
```

- `--charset` accepts presets (`lower`, `upper`, `digits`, `symbols`) and
  literal text, comma-separated (e.g. `lower,digits` or `abc123`)
- Stops at a match, the budget (default 1,000,000; hard max 10,000,000), or
  Ctrl+C; a truncated space reports `budget_exhausted`
- Pick a realistic budget with `hashcrack benchmark`

In the dashboard, **Auto-fit** applies its recommendation to the controls: it
selects `lower,digits` (or `upper` for an identified LM target), sets minimum
length to 1, chooses the largest fully covered length range under the
10,000,000 hard cap, and sets the candidate budget to that range's full size.
It does not determine the target plaintext's actual length. If a hash shape
matches multiple algorithms, the algorithm remains unselected until you
choose one.

Brute force does not reverse a hash or consult a wordlist. It enumerates every
string formed from the selected character set, shortest length first, hashes
each candidate with the selected algorithm, and compares the result locally.
The candidates are processed by CPU worker processes. The search covers the
full selected length range only when it fits inside the candidate budget;
otherwise it stops at the budget. The number of possibilities grows
exponentially with the character-set size and maximum length.

### 4. Salted formats

```bash
hashcrack audit 3d83c8e717ff0e7ecfe187f088d69954 \
    --algorithm md5_pass_salt --salt 343141 \
    --mode dictionary --wordlist words.txt
```

Eight salted formats (hashcat modes 10/20/110/120/1410/1420/1710/1720) take
the known salt stored alongside the hash; `--salt` is required for them and
rejected for unsalted formats.

### 5. Hashlist — many targets, one pass

```text
# targets.txt — one per line; prefix the ambiguous 32-hex shapes
md5:8743b52063cd84097a65d1633f5c74f5
127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
ntlm:b4b9b02e6f09a9bd760f388b67351e2b
```

```bash
hashcrack audit --hashlist targets.txt \
    --mode dictionary --wordlist words.txt
```

Each candidate is hashed once per distinct target algorithm and probed against
all targets; the CLI prints a per-target result table and history stores one
record per target plus a batch summary.

### 6. Rules — wordlist mutations

```bash
hashcrack audit a13b856f261e2a517ed184e777a6128a \
    --algorithm md5 --mode dictionary --wordlist words.txt \
    --rules append_digits_0_99
```

Presets: `capitalize`, `upper`, `lower`, `leetspeak`, `append_digits_0_99`,
`append_years`, `all`. The expanded stream (original word first, then
variants) respects the candidate budget exactly.

### 7. History and reports

```bash
hashcrack history                 # newest first
hashcrack history --limit 10
hashcrack export report.csv --format csv
hashcrack export report.json --format json
```

Successful matches include the plaintext/hash pair. Encrypted rows show
`<encrypted>` until `history --unlock` (or `--passphrase`) is provided.

### 8. Benchmark

```bash
hashcrack benchmark --seconds 1
```

Prints per-algorithm candidates/second on this machine to guide budget
choices (informational; never stored).

### 9. Dashboard

```bash
.\serve.ps1              # from the project folder on Windows; ./serve.sh on Linux/macOS
```

Open `http://127.0.0.1:8765`. The dashboard offers hash identification with
algorithm chips, salted-format selection with a salt field, hashlist upload,
both audit modes with mutation rules, workers 1–8, live progress with ETA,
pause/resume, cancellation, per-target result tables, audit history with
CSV/JSON export and clear-all, and a /changelog release-history page linked
in the navbar.

> **Always open the dashboard through the Flask server** — the JSON API exists only there. The built page opened through any other server shows a "Flask backend not detected" banner instead of failing silently. For frontend development, start the Flask server first so `npm run dev`/`npm run preview` can proxy `/api` to port 8765.

JSON routes:

- `POST /api/identify` — assess a hash and return compatible algorithms.
- `POST /api/audits` — start a dictionary, brute-force, salted, or hashlist audit.
- `GET /api/audits/{job_id}` — retrieve progress, per-target results, and outcome.
- `POST /api/audits/{job_id}/pause` / `resume` — checkpoint and continue a job.
- `POST /api/audits/{job_id}/cancel` — cancel the active job.
- `GET /api/history` — list local audit records.
- `POST /api/history/clear` — permanently delete all local audit records.
- `POST /api/history/unlock` — provide the encryption passphrase.
- `GET /api/export?format=csv|json` — download the full history.
- `GET /api/session` — CSRF token for state-changing requests.

See the [CLI contract](specs/001-offline-password-audit/contracts/cli.md) and
[web contract](specs/001-offline-password-audit/contracts/web.md) for the full
contracts.

## Implementation Plan: Ten Phases

The work is organized into ten phases: the four required v1 phases from the
supplied student project guide (Phases 1–4), followed by six v2 expansion
phases (Phases 5–10). Every task across both plans is implemented and checked
off. The [v1 task plan](specs/001-offline-password-audit/tasks.md) contains
**33 tasks (T001–T033)** and the [v2 task plan](specs/002-feature-expansion/tasks.md)
contains **43 tasks (T034–T076)**, each mapped to files and dependencies.

### Phase 1: Hash Identification & Structure Analysis Module — T001–T007

| Task | Work                                                                                  |
| ---- | ------------------------------------------------------------------------------------- |
| T001 | Configure Python project metadata and Flask/Passlib dependencies.                     |
| T002 | Define supported formats, digest lengths, normalization, and candidate algorithms.    |
| T003 | Implement MD5/SHA-256 with `hashlib` and NTLM with Passlib.                           |
| T004 | Require explicit selection when one input shape matches multiple supported formats.   |
| T005 | Add the CLI `identify` command and input errors.                                      |
| T006 | Add the Flask JSON identification endpoint.                                           |
| T007 | Document supported hash shapes and the MD5/NTLM ambiguity in the interface contracts. |

### Phase 2: Multi-Threaded Dictionary & Brute-Force Cracking Engine — T008–T015

| Task | Work                                                                            |
| ---- | ------------------------------------------------------------------------------- |
| T008 | Stream wordlists and read them in bounded chunks.                               |
| T009 | Generate brute-force candidates from explicit character sets and length limits. |
| T010 | Implement a shared comparison worker for MD5, SHA-256, and NTLM.                |
| T011 | Add bounded multiprocessing, 1–8 workers, cancellation, and chunk scheduling.   |
| T012 | Enforce a 1,000,000 default candidate budget and 10,000,000 hard maximum.       |
| T013 | Track attempts, elapsed time, worker count, progress, state, and match.         |
| T014 | Add CLI arguments for modes and their inputs.                                   |
| T015 | Document input rules and synthetic validation cases.                            |

### Phase 3: CLI / Web Dashboard Interface — T016–T025

| Task | Work                                                                                                                       |
| ---- | -------------------------------------------------------------------------------------------------------------------------- |
| T016 | Connect CLI audits to the shared engine and print progress and results.                                                    |
| T017 | Warn and require acknowledgement before storing successful plaintext/hash pairs.                                           |
| T018 | Implement loopback-only Flask serving and CSRF protection.                                                                 |
| T019 | Add web job start, status, and cancellation routes.                                                                        |
| T020 | Validate wordlist upload limits and clean up temporary files.                                                              |
| T021 | Set up Astro, React, Tailwind, and frontend build scripts.                                                                 |
| T022 | Build dashboard controls for hash identification, algorithm ambiguity, mode, charset, limits, and workers.                 |
| T023 | Connect audit requests, progress polling, cancellation, plaintext/hash results, and the pre-run retention acknowledgement. |
| T024 | Style forms, progress, warnings, and results with Tailwind.                                                                |
| T025 | Build and package static frontend assets served by Flask; document local launch.                                           |

### Phase 4: Result Storage & Audit Logging — T026–T033

| Task | Work                                                                                        |
| ---- | ------------------------------------------------------------------------------------------- |
| T026 | Create SQLite schema and local connection handling.                                         |
| T027 | Save target hash, algorithm, mode, status, worker count, attempts, duration, and timestamp. |
| T028 | Save successful plaintext/hash pairs and show the sensitive-data warning.                   |
| T029 | Connect CLI terminal outcomes to SQLite.                                                    |
| T030 | Add history listing and CSV/JSON export.                                                    |
| T031 | Add dashboard history and successful result display.                                        |
| T032 | Document records, database location, exports, and retention warning.                        |
| T033 | Walk through the phase validation scenarios with synthetic data and refine the quickstart.  |

### Phase 5: Salted Fast Hashes — T034–T042 (v2)

| Task | Work                                                                                                   |
| ---- | ------------------------------------------------------------------------------------------------------ |
| T034 | Add the `SALTED_ALGORITHMS` registry (name → base digest, salt position) and salted-format validation. |
| T035 | Add position-aware salted digest adapters.                                                             |
| T036 | Pass the run salt through `run_audit` and the comparison worker.                                       |
| T037 | Add `--salt` to the audit command and wire it through CLI validation.                                  |
| T038 | Add the salt field to `POST /api/audits` and dashboard validation.                                     |
| T039 | Add the salt input to the dashboard form (shown for salted formats).                                   |
| T040 | Store the salt in `audit_runs` with an additive schema migration.                                      |
| T041 | Update the CLI and web contracts for salted formats.                                                   |
| T042 | Validate salted formats against hashcat example hashes and update the quickstart.                      |

### Phase 6: Hashlist Multi-Target Audits — T043–T051 (v2)

| Task | Work                                                                                                          |
| ---- | ------------------------------------------------------------------------------------------------------------- |
| T043 | Add hashlist parsing (`algorithm:hash` optional prefix, skip blanks and `#` comments, whole-file validation). |
| T044 | Implement the multi-target worker (targets dict keyed by digest, single hashing pass, per-target matches).    |
| T045 | Add `--hashlist PATH` to the audit command (mutually exclusive with a positional hash).                       |
| T046 | Add hashlist upload and per-target result tracking to the web API.                                            |
| T047 | Render the per-target results table (hash, algorithm, status, plaintext) in the dashboard.                    |
| T048 | Add the `audit_batches` table and per-target result rows with an additive migration.                          |
| T049 | Include batch results in CSV/JSON export.                                                                     |
| T050 | Update the CLI and web contracts for hashlist mode.                                                           |
| T051 | Validate the three-target synthetic scenario and update the quickstart.                                       |

### Phase 7: Rules & Mutations — T052–T057 (v2)

| Task | Work                                                                                                  |
| ---- | ----------------------------------------------------------------------------------------------------- |
| T052 | Create `rules.py` with the preset registry (capitalize, upper, lower, leetspeak, digit/year appends). |
| T053 | Wrap dictionary batch sources with rule expansion (budget counts expanded candidates).                |
| T054 | Add `--rules PRESET` to the audit command (dictionary mode).                                          |
| T055 | Add the rules preset select to the dashboard (dictionary mode).                                       |
| T056 | Document rule presets and budget semantics in the contracts.                                          |
| T057 | Validate the mutated-match scenario and update the quickstart.                                        |

### Phase 8: Tooling & UX — T058–T066 (v2)

| Task | Work                                                                                         |
| ---- | -------------------------------------------------------------------------------------------- |
| T058 | Create `benchmark.py` (wall-clock slice per algorithm) and the `benchmark` CLI command.      |
| T059 | Implement pause/resume (offset checkpoint, wordlist byte-position validation, pool release). |
| T060 | Add the pause and resume API routes.                                                         |
| T061 | Add the pause/resume button state machine in the dashboard.                                  |
| T062 | Add `GET /api/export?format=csv\|json` and dashboard download buttons.                       |
| T063 | Compute and display ETA (attempts/second × remaining) in CLI progress and the dashboard.     |
| T064 | Add the `--no-store-plaintext` CLI flag and dashboard checkbox (withheld marker in history). |
| T065 | Make Auto-fit LM-aware (upper-only alphabet suggestion when the identified algorithm is LM). |
| T066 | Update the CLI and web contracts for all phase-8 features.                                   |

### Phase 9: Security & Quality — T067–T073 (v2)

| Task | Work                                                                                                                                          |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| T067 | Write `tests/test_algorithms.py` (shape mapping, ambiguity, normalization) and `tests/test_hashing.py` (RFC 1320 vectors + hashcat examples). |
| T068 | Write `tests/test_bruteforce.py` (charset resolution, budget boundaries) and `tests/test_candidates.py` (chunking, hashlist parsing).         |
| T069 | Write `tests/test_engine.py` — golden tests for attempt accounting.                                                                           |
| T070 | Write `tests/test_web.py` (Flask test client: session/CSRF, identify, audit, uploads, history, pause/resume, export).                         |
| T071 | Add the GitHub Actions CI workflow running pytest on Windows and Ubuntu, and the `pytest` dev dependency.                                     |
| T072 | Add optional at-rest encryption of stored plaintexts (Fernet, passphrase-derived key, unlock in CLI and dashboard).                           |
| T073 | Update the README and quickstart for the test suite, CI badge, and encryption mode.                                                           |

### Phase 10: Research — T074–T076 (v2, quarantined)

Research tasks landed only after hashcat-example validation and phase-9 test
coverage; rejected candidates are documented in the [v2 plan](specs/002-feature-expansion/plan.md).

| Task | Work                                                                                                            |
| ---- | --------------------------------------------------------------------------------------------------------------- |
| T074 | Research RIPEMD-160 (pure-Python implementation, 40-hex, adds ambiguity with SHA-1) — merged with validation.   |
| T075 | Research adaptive formats (bcrypt, sha512crypt, phpass via Passlib) with slow-format budget semantics — merged. |
| T076 | Research SHA-512/224 and SHA-512/256 (`hashlib.new` availability check) — merged.                               |

## Repository Layout (implemented)

```text
README.md
CHANGELOG.md
LICENSE.md
pyproject.toml
setup.ps1 / setup.sh          # one-command setup (Windows / Linux-macOS)
serve.ps1 / serve.sh          # dashboard launch shortcuts
.github/workflows/ci.yml      # pytest on Windows + Ubuntu
src/password_audit/
├── __init__.py
├── __main__.py
├── algorithms.py             # format registry, shapes, salted/adaptive tables
├── hashing.py                # digest adapters (hashlib, Passlib, salted, MD4, RIPEMD-160)
├── ripemd160.py              # pure-Python RIPEMD-160 implementation
├── candidates.py             # wordlist streaming, chunks, hashlist parsing
├── bruteforce.py             # charset/length candidate generator
├── rules.py                  # mutation rule presets
├── benchmark.py              # per-algorithm throughput measurement
├── engine.py                 # multiprocessing audit engine, pause/resume
├── history.py                # SQLite history, exports, encryption
├── cli.py                    # argparse CLI (identify, audit, history, export, benchmark, serve)
├── web.py                    # loopback Flask JSON API + static serving
└── static/                   # Astro output served by Flask (gitignored, built by npm run build)
frontend/
├── package.json
├── astro.config.mjs
└── src/
    ├── pages/index.astro
    ├── components/
    │   ├── AuditDashboard.jsx
    │   ├── Navbar.jsx
    │   ├── Footer.jsx
    │   ├── ParticleBackground.jsx
    │   └── ChangelogModal.jsx
    └── styles/global.css
tests/                        # pytest suite
specs/
├── 001-offline-password-audit/
│   ├── spec.md
│   ├── plan.md
│   ├── research.md
│   ├── data-model.md
│   ├── quickstart.md
│   ├── tasks.md
│   └── contracts/
│       ├── cli.md
│       └── web.md
└── 002-feature-expansion/
    ├── spec.md
    ├── plan.md
    └── tasks.md
```

This layout is implemented; `static/` holds the Astro build output (gitignored) and is created by `npm run build`.

## Setup

Requirements: Python 3.11+, a modern browser, and internet access for the first setup. The setup scripts install the latest Node.js LTS release and npm automatically when the frontend toolchain is missing or too old (using nvm on Linux/macOS and winget on Windows). Windows may request administrator approval for winget; App Installer/winget must be available. Audit operations are designed to run offline. The application runs on **Windows, Linux, and macOS**.

### One-command setup (recommended)

Download the repository and run the setup script for your platform — it installs Python dependencies (with all extras), Node dependencies, and builds the dashboard:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

```bash
# Linux / macOS / Git Bash
./setup.sh
```

Both scripts are idempotent (safe to re-run), install the frontend toolchain if needed, use the frontend lockfile for a repeatable install, and run the test suite at the end. They install a user-local `hashcrack` launcher so the CLI works from any directory without activating `.venv`; open a new terminal if setup added the launcher directory to PATH. If you only need the CLI/backend, `setup.ps1 -SkipFrontend` / `./setup.sh --skip-frontend` skips the frontend installation and build.

### Manual setup

#### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Set-Location frontend
npm install
npm run build
Set-Location ..
```

Shortcut: `.\serve.ps1` starts the dashboard on the venv's interpreter without activating it (`.\serve.ps1 -Port 9000` chooses a port).

### Linux / macOS (bash)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
cd frontend && npm install && npm run build && cd ..
```

Shortcut: `./serve.sh` starts the dashboard on the venv's interpreter without activating it (`./serve.sh 9000` chooses a port).

The canonical CLI command is `hashcrack` on all platforms. On Linux and Windows, setup makes it available from any directory; on macOS, use `.venv/bin/hashcrack` or activate `.venv` first. Use `./serve.sh` or `.\serve.ps1` from the project folder to start the dashboard. See the CLI contract for options and exit codes.

## Performance and Validation

The `benchmark` command measures per-algorithm candidates per second on the current machine so budgets can be sized accordingly. Brute-force search is bounded by its configured candidate budget. The pytest suite (`tests/`, 145 tests) checks identification, dictionary and brute-force matching, hashlists, rules, progress accounting, pause/resume, export, plaintext withholding, encryption, and history behavior with synthetic hashes and candidate data.

## Current Status

- The specification, design documents, contracts, and both task plans are complete; all 33 v1 tasks and the v2 expansion tasks (T034–T076) are implemented and marked done in their `tasks.md` files.
- The Python package (`src/password_audit/`) provides hash identification (including salted, adaptive, RIPEMD-160, and SHA-512/224+/256 formats), dictionary/brute-force/hashlist auditing, mutation rules, multiprocessing, the benchmark command, pause/resume, the CLI, the Flask API, and SQLite history with optional at-rest encryption.
- The Astro/React/Tailwind dashboard builds into `src/password_audit/static/` and is served by the loopback Flask server; it adds pause/resume, ETA, CSV/JSON export, plaintext-withholding and encryption controls, and history unlock.
- Behavior is checked by the 145-test pytest suite running on Windows and Ubuntu via GitHub Actions CI.

## License

The repository includes the [MIT License](LICENSE.md). Replace `Team-606` in that file with the copyright owner's name or organization before publication.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) — or the clock icon in the dashboard navbar —
for the full release history (v1.0.0 initial release, v1.1.0 format expansion,
v2.0.0 feature expansion).

## Project Documents

- [Specification](specs/001-offline-password-audit/spec.md)
- [Implementation plan](specs/001-offline-password-audit/plan.md)
- [Technical decisions](specs/001-offline-password-audit/research.md)
- [Data model](specs/001-offline-password-audit/data-model.md)
- [v1 task plan (Phases 1–4)](specs/001-offline-password-audit/tasks.md)
- [Quickstart and validation scenarios](specs/001-offline-password-audit/quickstart.md)
- [CLI contract](specs/001-offline-password-audit/contracts/cli.md)
- [Web contract](specs/001-offline-password-audit/contracts/web.md)

v2 expansion documents:

- [Specification](specs/002-feature-expansion/spec.md)
- [Implementation plan](specs/002-feature-expansion/plan.md)
- [Task breakdown (Phases 5–10)](specs/002-feature-expansion/tasks.md)

## Feature Expansion (v2) — Phases 5–10, Implemented

The v2 round planned in [specs/002-feature-expansion/](specs/002-feature-expansion/) is complete: salted fast-hash formats, hashlist multi-target audits, rule-based mutations, tooling/UX upgrades (benchmark, pause/resume, dashboard export, ETA, plaintext withholding), a pytest suite with CI, optional plaintext encryption at rest, and the researched formats (RIPEMD-160, adaptive bcrypt/sha512crypt/phpass, SHA-512/224 and SHA-512/256). See its [spec](specs/002-feature-expansion/spec.md), [plan](specs/002-feature-expansion/plan.md), and [task breakdown](specs/002-feature-expansion/tasks.md) (T034–T076).

  <!-- ===================== FOOTER ===================== -->
  <div align="center">
    <img 
      src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=100&section=footer"
      width="100%"
    />
  </div>
