# Feature Specification: Rust Backend (Phase 11)

**Feature Branch**: `003-rust-backend`

**Created**: 2026-11-18

**Status**: Draft (planning then implementation)

**Input**: Operator request to add a backend implementation of the tool written in Rust **alongside** the existing Python backend — neither replaces the other; both remain installable and runnable, with the installer and the server launcher asking which one to use.

## Purpose

The tool currently runs on a single backend implementation. This round adds a second, functionally equivalent backend implementation so the operator can choose which one to install and which one to run at every touchpoint: setup, server launch, and CLI. The choice is per-use, not per-machine — one installation can hold both backends side by side, and every entry point (installer, server launcher, dashboard, CLI) must honor it. This round is **Phase 11**, continuing the numbering established by v1 (Phases 1–4) and v2 (Phases 5–10), with tasks numbered from **T077**.

## User Scenarios & Testing

### User Story 1 — Install either backend or both (Priority: P1)

An operator runs the existing setup script. The script asks which backend to install: the Python backend, the Rust backend, or both. Choosing Python keeps today's behavior (virtual environment + package + frontend build). Choosing Rust checks for the Rust toolchain and installs it if missing (mirroring how the script already installs Node.js when missing), then builds the Rust workspace and installs the Rust CLI. Choosing both performs both paths. A previously installed backend is never removed by installing the other.

**Why this priority**: Installation is the first touchpoint; without a working install path for the second backend, nothing else can be exercised.

**Independent test**: Run the setup script three times choosing each option; after the Python choice only the Python CLI is available, after the Rust choice only the Rust CLI is available, after Both both are available — and each install completes without manual toolchain steps.

**Acceptance Scenarios**:

1. **Given** a machine with no Rust toolchain, **When** the operator chooses the Rust install, **Then** the toolchain is provisioned automatically and the Rust CLI and server binary build and install successfully.
2. **Given** the Python backend already installed, **When** the operator re-runs setup and chooses Rust only, **Then** the Python installation is untouched and the Rust CLI is added.
3. **Given** an operator who just presses Enter at the prompt, **When** setup runs, **Then** the default choice installs the Python backend (preserving current behavior).

---

### User Story 2 — Choose the backend when starting the server (Priority: P1)

An operator launches the dashboard with the existing serve script. The script asks which backend to run the server with: Python or Rust. An explicit override argument (e.g. `--backend rust`) skips the prompt — required for non-interactive use. Whichever backend is chosen serves the same built dashboard on the same default port with the same API surface.

**Why this priority**: The server choice is the operator's daily-visible switch between the two implementations.

**Independent test**: Start the server with each choice; the dashboard loads and identifies a hash through the API in both cases, and the override flag starts the chosen backend without prompting.

**Acceptance Scenarios**:

1. **Given** both backends installed, **When** the serve script runs interactively, **Then** it asks which backend to use and launches the chosen one.
2. **Given** a non-interactive environment (script or CI), **When** the serve script runs with the backend override, **Then** no prompt appears and the requested backend starts.
3. **Given** only one backend installed, **When** the serve script runs without an override, **Then** it starts the installed backend directly (with a note) instead of failing.

---

### User Story 3 — Identical auditing capability through the second backend (Priority: P1)

An auditor who already knows how to use the tool gets the same auditing capability from the second backend: hash identification with the same supported format catalog and the same ambiguity resolution, dictionary mode, bounded brute-force mode, hashlist multi-target audits, mutation rules, candidate budget accounting, pause/resume, benchmark, and plaintext withholding/encryption — all behaving equivalently for identical inputs.

**Why this priority**: The second backend is only worth installing if it can do the same job; equivalence is the core promise of this round.

**Independent test**: Feed the same targets (using published example vectors for every supported format) to both backends in each mode; every run ends with the same status (match/no-match/budget_exhausted), the same matched candidate, and the same attempt accounting.

**Acceptance Scenarios**:

1. **Given** a target hash of any supported format, **When** identification runs on either backend, **Then** the same compatible-algorithm list (including ambiguity choices) is produced.
2. **Given** identical wordlist, rules preset, and candidate budget, **When** a dictionary audit runs on both backends, **Then** both report the same outcome with the same attempt totals.
3. **Given** a job paused mid-run on the second backend, **When** it is resumed, **Then** it continues from the recorded offset without re-counting attempts, exactly as on the first backend.

---

### User Story 4 — Same dashboard, either backend (Priority: P2)

The dashboard frontend is built once and served by either backend. The web API contract (sessions, formats, identify, audit submit/status/cancel/pause/resume, history, unlock, export, clear) is identical on both backends, so the operator switches backends without relearning anything or rebuilding the frontend.

**Why this priority**: The dashboard is the primary interface; contract parity is what makes the backend switch invisible.

**Independent test**: Point the built dashboard at each backend in turn and exercise the full workflow (identify → audit → pause → resume → history → export) against both; every screen behaves the same.

**Acceptance Scenarios**:

1. **Given** the built frontend, **When** served by the second backend, **Then** every dashboard action works with the same requests and response shapes as the first backend.
2. **Given** a run submitted through one backend, **When** the operator switches backends and opens history, **Then** the run is visible there too (shared audit store).

---

### User Story 5 — CLI parity (Priority: P2)

The operator gets a second CLI binary mirroring the existing CLI's command surface — identify, audit, history, export, benchmark, serve — with the same flags and the same human-readable and machine-readable outputs, so scripts written against one CLI work with the other by swapping the command name.

**Why this priority**: The CLI is the automation surface; parity lets the choice of backend extend to scripted workflows.

**Independent test**: Run every subcommand with identical arguments on both CLIs; outputs match in structure (same sections/fields, same JSON shape) for identical inputs.

**Acceptance Scenarios**:

1. **Given** the same audit arguments, **When** run through either CLI, **Then** the run summary shows the same fields (algorithm, status, attempts, duration) with matching values.
2. **Given** the machine-readable output flag, **When** either CLI emits it, **Then** the JSON structures are equivalent.

---

### User Story 6 — Cross-backend history and encryption (Priority: P2)

Both backends read and write the same audit history store. Records written by one backend are readable by the other, including encrypted plaintext: the unlock passphrase works identically regardless of which backend recorded the run. Audit records note which backend produced them so the operator can tell runs apart in history and reports.

**Why this priority**: A split history would defeat the audit trail; encryption must not become a per-backend silo.

**Independent test**: Record an encrypted run with one backend, unlock and export it with the other; the plaintext and metadata match.

**Acceptance Scenarios**:

1. **Given** an encrypted match recorded by one backend, **When** the other backend unlocks history with the same passphrase, **Then** the plaintext is displayed correctly.
2. **Given** runs from both backends, **When** history is listed, **Then** each record shows which backend produced it.

---

### User Story 7 — Honest performance and quality gates (Priority: P3)

The second backend reports its own benchmark numbers and is covered by its own automated test suite (algorithm vectors, candidate generation, engine accounting, API behavior). Performance differences are honest and measurable — the second backend is expected to be at least as fast as the first on fast-hash dictionary work, but never at the cost of behavioral parity.

**Why this priority**: A faster backend is a headline benefit of adding it, but correctness and parity gate the value.

**Independent test**: Run the second backend's test suite and benchmark; vectors pass for every supported format and the benchmark prints per-algorithm throughput on the local machine.

**Acceptance Scenarios**:

1. **Given** the standard format vectors, **When** the second backend's suite runs, **Then** every supported format passes.
2. **Given** the benchmark command, **When** run through the second backend's CLI, **Then** per-algorithm throughput is reported with the same output shape as the first backend's.

## Edge Cases

- Missing toolchain: choosing the Rust install on a machine without its toolchain provisions it automatically; if provisioning fails (no network, restricted permissions), the script fails with a clear message and the other backend remains untouched.
- Non-interactive runs: every new prompt (install choice, server backend choice) has a flag/argument override so scripted and CI usage never hangs waiting for input.
- One backend installed: the server launcher runs the installed backend with a note instead of failing; choosing an uninstalled backend at the prompt explains what to run to install it.
- Same port, two servers: starting a second server on an occupied port fails with the standard "port in use" message regardless of backend.
- Shared history store: both backends access the same SQLite store concurrently where the store allows it; a lock contention error surfaces as a clear retryable message rather than data loss.
- Encrypted history: the encryption scheme is identical across backends — a passphrase created for one backend unlocks runs recorded by the other; no per-backend key derivation differences.
- Format parity: the second backend supports exactly the same format catalog (all 23 formats, including salted, RIPEMD-160, adaptive bcrypt/sha512crypt/phpass, and SHA-512/224/256) with the same identifiers, names, and ambiguity resolution; a format supported by one and not the other is treated as a parity bug.
- Budget accounting: mutated candidates and hashlist expansion count toward the budget identically on both backends; `budget_exhausted` status semantics match.
- Plaintext withholding: no-plaintext runs record the same withheld marker on both backends.
- Windows and Linux: install, serve, CLI, and server behavior are equivalent on both platforms (both script flavors kept in sync).

## Requirements

- **FR-201**: The setup scripts MUST ask which backend to install — Python, Rust, or Both — with Python as the default when the prompt is answered with a bare Enter.
- **FR-202**: The Rust install path MUST provision the Rust toolchain automatically when missing, mirroring the existing Node.js provisioning pattern, then build and install the Rust CLI and server binary.
- **FR-203**: Installing one backend MUST NOT remove or break the other; both can be installed side by side on one machine.
- **FR-204**: The serve scripts MUST ask which backend to run the server with — Python or Rust — and MUST accept an explicit override argument that skips the prompt.
- **FR-205**: When only one backend is installed, the serve scripts MUST start it with a note instead of prompting uselessly; when neither is installed they MUST fail with setup instructions.
- **FR-206**: The second backend MUST implement the full auditing capability of the first: hash identification for the entire supported format catalog, dictionary mode, bounded brute-force mode, hashlist multi-target audits, mutation rules, candidate budgets, pause/resume, benchmark, plaintext withholding, and optional plaintext encryption at rest.
- **FR-207**: The second backend MUST expose the same web API contract (session, formats, identify, audit submit/status/cancel/pause/resume, history, unlock, export, clear, frontend asset serving) so the built dashboard runs unchanged against either backend, on the same default port.
- **FR-208**: The second backend MUST provide a CLI binary mirroring the first CLI's subcommands (identify, audit, history, export, benchmark, serve) with the same flags and output structure, under its own command name.
- **FR-209**: Both backends MUST share the same audit history store; records MUST be readable by either backend and MUST record which backend produced them.
- **FR-210**: Plaintext encryption MUST use the same scheme and passphrase handling on both backends so unlock and export work across backends.
- **FR-211**: Identical inputs MUST produce equivalent outcomes on both backends: same status, same matched plaintext (when not withheld), same attempt accounting, same identification results.
- **FR-212**: The second backend MUST ship its own automated test suite covering format vectors, candidate generation and rules, engine accounting, and API behavior, and both backends' suites MUST pass.
- **FR-213**: No git operations (branch, commit, push) are part of this feature's workflow; all work lands in the working tree only.

### Key Entities

- **Backend choice**: the operator's selection at install time (Python / Rust / Both) and at server start (Python / Rust), persisted implicitly by what was installed and explicitly overridable per launch.
- **Backend CLI binary**: the second backend's command-line entry point, separate name, same surface.
- **Audit record** (existing): gains a backend attribution note so history can distinguish which implementation produced each run.
- **Audit history store** (existing): remains the single shared store for both backends, unchanged schema semantics.

## Success Criteria

- **SC-001**: An operator can install either backend — or both — by answering one prompt, with no manual toolchain steps, on Windows and Linux.
- **SC-002**: An operator can start the dashboard against either backend by answering one prompt or passing one flag, and the dashboard behaves identically in both cases.
- **SC-003**: For every supported format and every mode, identical inputs yield identical outcomes (status, matched plaintext, attempts) on both backends — validated by automated parity checks on published example vectors.
- **SC-004**: A run recorded by one backend is visible, unlockable, and exportable through the other backend.
- **SC-005**: Every CLI subcommand and flag available on one backend's CLI exists on the other's, with equivalent output structure.
- **SC-006**: Both backends' automated test suites pass on Windows and Linux, covering all supported formats.
- **SC-007**: The second backend's cracking throughput on fast-hash dictionary work is at least equal to the first backend's on the same machine, measured by each backend's benchmark on identical inputs.

## Assumptions

- **Full parity is in scope**: the second backend mirrors the complete current capability set (all 23 formats, salted variants, adaptive formats, rules, hashlists, benchmark, pause/resume, encryption, export) — this is the operator's stated intent ("the tool's backend", not a subset).
- **One server at a time per port**: the two backends are not expected to run simultaneously on the same port; the choice is per launch.
- **Frontend unchanged**: the React dashboard is built once and served by both backends; no dashboard changes are required beyond what attribution display needs (if any).
- **Prompt defaults preserve current behavior**: bare-Enter at the install prompt chooses Python; the serve prompt defaults to Python as well, with an explicit note whenever a non-default backend is selected or auto-fallback is used.
- **Toolchain provisioning follows the Node pattern**: the setup scripts already auto-install Node.js; the Rust path provisions its toolchain the same way, user-local, with clear failure messages.
- **No git operations**: speckit normally creates a feature branch during specify; this round skips that step entirely per operator instruction, and all speckit artifacts live in the working tree.
