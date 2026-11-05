# Tasks: Hash Cracker

**Input**: Design documents in `specs/001-offline-password-audit/`

**Prerequisites**: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md), [data-model.md](data-model.md), [contracts/cli.md](contracts/cli.md), [contracts/web.md](contracts/web.md)

**Organization**: The task phases follow the four phases in the supplied student execution guide. The tasks include both CLI and website interfaces, as requested later by the user.

**Validation**: Task descriptions include manual synthetic-data validation scenarios; automated test-writing tasks are not included unless separately requested.

## Task Format

Every implementation task uses `- [ ] T### [P?] Description with file path`.

- `[P]` means the task can be performed in parallel because it works on different files and has no incomplete prerequisite.
- Task IDs are sequential across all four project phases.

## Phase 1: Hash Identification & Structure Analysis Module

**Goal**: Recognize MD5, SHA-256, and NTLM shapes, validate inputs, and surface ambiguity instead of guessing.

**Phase validation**: Synthetic 32-character MD5 and NTLM hashes both display as ambiguous candidates; a 64-character hex digest displays SHA-256; malformed values are rejected.

- [ ] T001 Add Python package metadata and Flask/Passlib runtime dependencies in `pyproject.toml`.
- [ ] T002 Define supported algorithm names, lengths, normalization, and structural candidates in `src/password_audit/algorithms.py`.
- [ ] T003 Implement MD5 and SHA-256 digest adapters with `hashlib`, and the NTLM adapter with Passlib's `nthash` in `src/password_audit/hashing.py`.
- [ ] T004 Require explicit algorithm selection when a hash shape matches more than one supported format in `src/password_audit/algorithms.py`.
- [ ] T005 Implement the `identify` CLI command and actionable invalid-input messages in `src/password_audit/cli.py`.
- [ ] T006 Implement `POST /api/identify` and JSON response validation in `src/password_audit/web.py`.
- [ ] T007 Document the supported hash shapes and MD5/NTLM ambiguity in `specs/001-offline-password-audit/contracts/cli.md` and `specs/001-offline-password-audit/contracts/web.md`.

**Checkpoint**: Supported hash formats are identified honestly and both interfaces can present their compatible algorithm choices.

## Phase 2: Multi-Threaded Dictionary & Brute-Force Cracking Engine

**Goal**: Compare dictionary and generated candidates to one selected target with multiprocessing, progress reporting, and explicit workload bounds.

**Phase validation**: Use synthetic values to verify dictionary match/no-match, a bounded brute-force match, attempts, elapsed time, worker count, budget stop, and cancellation.

- [ ] T008 Implement UTF-8 dictionary streaming, line handling, and bounded candidate chunks in `src/password_audit/candidates.py`.
- [ ] T009 Implement candidate generation from selected character sets and configured minimum/maximum lengths in `src/password_audit/bruteforce.py`.
- [ ] T010 Implement a shared candidate-to-digest comparison worker for MD5, SHA-256, and NTLM in `src/password_audit/engine.py`.
- [ ] T011 Implement a bounded process pool with worker counts 1–8, default 4, chunk submission, and cancellation in `src/password_audit/engine.py`.
- [ ] T012 Enforce a default candidate budget of 1,000,000 and a hard maximum of 10,000,000 brute-force candidates per run in `src/password_audit/bruteforce.py` and `src/password_audit/engine.py`.
- [ ] T013 Track attempts, elapsed time, effective workers, progress, terminal state, and matched plaintext in `src/password_audit/engine.py`.
- [ ] T014 Implement CLI argument validation for dictionary/brute-force mode, charset, length range, worker count, and candidate budget in `src/password_audit/cli.py`.
- [ ] T015 Document dictionary and brute-force input rules and safe synthetic validation scenarios in `specs/001-offline-password-audit/quickstart.md`.

**Checkpoint**: Both candidate modes use the same bounded comparison engine and stop on match, budget, or cancellation.

## Phase 3: CLI / Web Dashboard Interface

**Goal**: Provide both requested interfaces with shared audit behavior, live progress, and recovered plaintext results.

**Phase validation**: Run matching synthetic dictionary and brute-force cases through CLI and browser; confirm equivalent mode, algorithm, attempt, time, result, and error behavior.

- [ ] T016 Connect CLI audit commands to the shared engine and print progress, attempts, elapsed time, mode, workers, and terminal results in `src/password_audit/cli.py`.
- [ ] T017 Print a clear sensitive-result warning and require acknowledgement before an audit can persist a plaintext/hash pair in `src/password_audit/cli.py`.
- [ ] T018 Implement Flask startup on `127.0.0.1`, port selection, static-asset serving, and same-origin/CSRF protection in `src/password_audit/web.py`.
- [ ] T019 Implement the one-active-job lifecycle and `POST /api/audits`, `GET /api/audits/{job_id}`, and cancellation routes in `src/password_audit/web.py`.
- [ ] T020 Validate dictionary uploads up to 100 MiB and remove temporary files after validation failure, completion, cancellation, or shutdown in `src/password_audit/web.py`.
- [ ] T021 Initialize Astro, React, Tailwind, and `dev`/`build`/`preview` scripts in `frontend/package.json` and `frontend/astro.config.mjs`.
- [ ] T022 Build the dashboard controls for hash, algorithm, dictionary/brute-force mode, charset, lengths, budget, and workers in `frontend/src/components/AuditDashboard.jsx` and `frontend/src/pages/index.astro`.
- [ ] T023 Connect dashboard requests, progress polling, cancellation, plaintext/hash result display, and pre-run retention acknowledgement to the Flask API in `frontend/src/components/AuditDashboard.jsx`.
- [ ] T024 Style form controls, progress, warnings, and result/error states with Tailwind in `frontend/src/styles/global.css`.
- [ ] T025 Configure Astro's static build output for Flask, package the assets, and document local launch in `frontend/astro.config.mjs`, `pyproject.toml`, and `specs/001-offline-password-audit/contracts/web.md`.

**Checkpoint**: CLI and web dashboard both offer the two audit modes, bounded workers, live progress, and result display; the server is local-only.

## Phase 4: Result Storage & Audit Logging

**Goal**: Persist local audit history and successful plaintext/hash pairs with timing and attempt totals for reporting.

**Phase validation**: Complete synthetic match and no-match runs in both interfaces; inspect SQLite and CSV/JSON exports for the requested fields.

- [ ] T026 Create SQLite schema and local database connection handling in `src/password_audit/history.py`.
- [ ] T027 Persist each run's target hash, algorithm, mode, status, worker count, attempts, elapsed time, and timestamp in `src/password_audit/history.py`.
- [ ] T028 Persist the successful plaintext/hash pair locally and surface the sensitive-data warning in `src/password_audit/history.py` and `src/password_audit/cli.py`.
- [ ] T029 Connect CLI match/no-match/interrupted outcomes to the SQLite history service in `src/password_audit/cli.py`.
- [ ] T030 Add local history viewing and CSV/JSON report export in `src/password_audit/history.py` and `src/password_audit/cli.py`.
- [ ] T031 Add dashboard history and successful result display backed by SQLite in `src/password_audit/web.py` and `frontend/src/components/AuditDashboard.jsx`.
- [ ] T032 Document fields, local database location, export behavior, and plaintext retention warning in `specs/001-offline-password-audit/contracts/cli.md` and `README.md`.
- [ ] T033 Walk through all four phases' synthetic-data scenarios and update the expected CLI/web behavior in `specs/001-offline-password-audit/quickstart.md`.

**Checkpoint**: Successful matches and run summaries are stored locally and can be reviewed/exported for credential-policy reporting.

## Dependency Order

1. Complete Phase 1 before running hash comparisons.
2. Complete the candidate readers, generator, and digest adapters in Phase 2 before the CLI and web interfaces call the engine.
3. Phase 3 connects both interfaces to the validated shared engine.
4. Phase 4 persists terminal results from both interfaces and adds reporting.

## Parallel Opportunities

- T002 and T003 can proceed in parallel after project metadata is established.
- T005 and T006 use different interface files after algorithm assessment behavior is defined.
- T008 and T009 can proceed in parallel; T010 and T011 integrate the candidate sources after both are ready.
- T021 and T022 establish frontend dependencies and UI structure separately from Flask route work.
- T026 can proceed alongside CLI/web wiring because it owns the database service module.

## Implementation Notes

- Python provides the core, CLI, Flask API, and SQLite access. Astro/React/JavaScript/Tailwind provide the dashboard.
- Use `hashlib` for MD5 and SHA-256; use Passlib's `nthash` support for NTLM.
- The assignment calls Phase 2 “Multi-Threaded”; the planned implementation uses multiprocessing for CPU-bound work, which is allowed by the supplied stack description.
- All runs use local inputs and one operator-selected hash. No remote login testing or external target support is included.
- Successful plaintext/hash pairs are stored because the project brief requests them; warn the operator before the audit begins.
