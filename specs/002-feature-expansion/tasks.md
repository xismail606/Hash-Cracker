# Tasks: Feature Expansion (v2)

**Input**: [spec.md](spec.md), [plan.md](plan.md) in this directory; builds on the completed v1 tree (specs/001-offline-password-audit).

**Organization**: Five implementation phases plus one research phase, following the same format as v1's task plan. Task IDs continue from v1 (T001–T033 are done).

**Validation**: Each phase ends with hashcat-example or synthetic validation scenarios; phase 9 turns recurring manual checks into automated pytest coverage. Test-writing tasks in phase 9 are included here because the operator requested quality work in this expansion.

## Task Format

Every implementation task uses `- [ ] T### [P?] Description with file path`. `[P]` means the task can proceed in parallel (different files, no incomplete prerequisite).

## Phase 5: Salted Fast Hashes

**Goal**: Audit salted fast-hash formats (hashcat modes 10, 20, 110, 120, 1410, 1420, 1710, 1720) with an operator-supplied salt in both interfaces.

**Phase validation**: hashcat salted examples (modes 10 and 1410, plaintext `hashcat`) audit to MATCH with the example salt via CLI and dashboard; a wrong salt yields no_match; the salt appears in the history record.

- [x] T034 Add the `SALTED_ALGORITHMS` registry (name → base digest, salt position) and salted-format validation to `src/password_audit/algorithms.py`.
- [x] T035 Add position-aware salted digest adapters to `src/password_audit/hashing.py`.
- [x] T036 Pass the run salt through `run_audit` and the worker in `src/password_audit/engine.py`.
- [x] T037 Add `--salt` to the audit command and wire it through validation in `src/password_audit/cli.py`.
- [x] T038 Add the salt field to `POST /api/audits` and dashboard validation in `src/password_audit/web.py`.
- [x] T039 Add the salt input to the dashboard form (shown for salted formats) in `frontend/src/components/AuditDashboard.jsx`.
- [x] T040 Store the salt in `audit_runs` with an additive schema migration in `src/password_audit/history.py`.
- [x] T041 [P] Update the CLI and web contracts for salted formats in `specs/001-offline-password-audit/contracts/cli.md` and `specs/001-offline-password-audit/contracts/web.md`.
- [x] T042 Validate salted formats against hashcat example hashes (modes 10, 20, 110, 120, 1410, 1420, 1710, 1720) and update the quickstart in `specs/001-offline-password-audit/quickstart.md`.

**Checkpoint**: A salted hashcat example audits to MATCH with its salt through both interfaces; wrong salt gives no_match.

## Phase 6: Hashlist Multi-Target Audits

**Goal**: One candidate stream compared against many targets in a single run, with per-target results and batch reporting.

**Phase validation**: A three-line hashlist (MD5, SHA-256, NTLM, all `hashcat`) with a matching wordlist yields three per-target matches plus one run summary; total attempts equal the sum of per-target attempts.

- [x] T043 Add hashlist parsing (`algorithm:hash` optional prefix, skip blanks and `#` comments, whole-file validation) to `src/password_audit/candidates.py`.
- [x] T044 Implement the multi-target worker (targets dict keyed by digest, single hashing pass, per-target match reporting) in `src/password_audit/engine.py`.
- [x] T045 Add `--hashlist PATH` to the audit command (mutually exclusive with a positional hash) in `src/password_audit/cli.py`.
- [x] T046 Add hashlist upload and per-target result tracking to `POST /api/audits`, `GET /api/audits/{job_id}` in `src/password_audit/web.py`.
- [x] T047 Render the per-target results table (hash, algorithm, status, plaintext) in `frontend/src/components/AuditDashboard.jsx`.
- [x] T048 Add the `audit_batches` table and per-target result rows with an additive migration in `src/password_audit/history.py`.
- [x] T049 Include batch results in CSV/JSON export in `src/password_audit/history.py`.
- [x] T050 [P] Update the CLI and web contracts for hashlist mode in `specs/001-offline-password-audit/contracts/cli.md` and `specs/001-offline-password-audit/contracts/web.md`.
- [x] T051 Validate the three-target synthetic scenario and update the quickstart in `specs/001-offline-password-audit/quickstart.md`.

**Checkpoint**: One wordlist pass audits three targets of mixed algorithms with exact per-target attempt accounting.

## Phase 7: Rules & Mutations

**Goal**: Deterministic mutation presets multiply wordlist coverage inside the existing candidate budget.

**Phase validation**: A two-line wordlist with the "append digits 0–99" preset produces `hash0…hash99` style candidates; total attempts respect the budget exactly; a match found only via a mutated candidate (e.g. `hashcat1` from wordlist line `hashcat`) is reported with its mutated plaintext.

- [x] T052 Create `src/password_audit/rules.py` with the preset registry (capitalize, upper, lower, append digits 0–N, prepend digits, leetspeak, append year) operating on candidate batches.
- [x] T053 Wrap dictionary batch sources with rule expansion in `src/password_audit/engine.py` (budget counts expanded candidates).
- [x] T054 Add `--rules PRESET` to the audit command (dictionary mode) in `src/password_audit/cli.py`.
- [x] T055 Add the rules preset select to the dashboard (dictionary mode) in `frontend/src/components/AuditDashboard.jsx`.
- [x] T056 [P] Document rule presets and budget semantics in `specs/001-offline-password-audit/contracts/cli.md` and `specs/001-offline-password-audit/contracts/web.md`.
- [x] T057 Validate the mutated-match scenario and update the quickstart in `specs/001-offline-password-audit/quickstart.md`.

**Checkpoint**: Mutated-only matches are found, exactly accounted, and budget-respecting.

## Phase 8: Tooling & UX

**Goal**: Benchmark, pause/resume, dashboard export, ETA, no-plaintext mode, and LM-aware auto-fit.

**Phase validation**: `benchmark` prints per-algorithm candidates/second twice with consistent results; a paused web job resumes and completes with contiguous attempt accounting; dashboard export downloads valid CSV; a no-plaintext match stores no plaintext but a clear withheld marker.

- [x] T058 Create `src/password_audit/benchmark.py` (2 s wall-clock slice per algorithm via the existing worker) and the `benchmark` CLI command in `src/password_audit/cli.py`.
- [x] T059 Implement pause/resume (offset checkpoint, dictionary byte position validation, pool release) in `src/password_audit/engine.py`.
- [x] T060 Add `POST /api/audits/{job_id}/pause` and resume handling in `src/password_audit/web.py`.
- [x] T061 Add the pause/resume button state machine in `frontend/src/components/AuditDashboard.jsx`.
- [x] T062 Add `GET /api/export?format=csv|json` in `src/password_audit/web.py` and download buttons in `frontend/src/components/AuditDashboard.jsx`.
- [x] T063 Compute and display ETA (attempts/second × remaining) in CLI progress and the dashboard in `src/password_audit/cli.py` and `frontend/src/components/AuditDashboard.jsx`.
- [x] T064 Add the `--no-store-plaintext` CLI flag and dashboard checkbox (run-level, withheld marker in history) in `src/password_audit/cli.py`, `src/password_audit/engine.py`, `src/password_audit/history.py`, and `frontend/src/components/AuditDashboard.jsx`.
- [x] T065 Make Auto-fit LM-aware and apply charset, length, and candidate-budget values to the dashboard form in `frontend/src/components/AuditDashboard.jsx`.
- [x] T066 [P] Update the CLI and web contracts for all phase-8 features in `specs/001-offline-password-audit/contracts/cli.md` and `specs/001-offline-password-audit/contracts/web.md`.

**Checkpoint**: Both interfaces gain benchmark, pause/resume, export, ETA, and plaintext-withholding without losing exact accounting.

## Phase 9: Security & Quality

**Goal**: Automated pytest coverage with CI, plus optional app-level plaintext encryption.

**Phase validation**: `pytest` passes locally on Windows; CI passes on windows-latest and ubuntu-latest; an encrypted history stores no cleartext plaintext and unlocks with the correct passphrase.

- [x] T067 [P] Write `tests/test_algorithms.py` (shape mapping, ambiguity, normalization) and `tests/test_hashing.py` (RFC 1320 vectors + hashcat examples for all nine formats) .
- [x] T068 [P] Write `tests/test_bruteforce.py` (charset resolution, budget boundaries, generation order) and `tests/test_candidates.py` (chunking, blank lines, hashlist parsing).
- [x] T069 Write `tests/test_engine.py` — golden tests for current attempt accounting (single/batch, match offset, budget exhaustion, cancellation) before multi-target changes land in T044.
- [x] T070 Write `tests/test_web.py` (Flask test client: session/CSRF, identify, audit start, upload limits, history, clear, pause/resume, export).
- [x] T071 Add `.github/workflows/ci.yml` running pytest on windows-latest and ubuntu-latest, and add the `pytest` dev dependency to `pyproject.toml`.
- [x] T072 Add optional at-rest encryption of `matched_plaintext` (Fernet, passphrase-derived key, unlock prompt in CLI, unlock field in dashboard) in `src/password_audit/history.py`, `src/password_audit/cli.py`, and `frontend/src/components/AuditDashboard.jsx`.
- [x] T073 [P] Update README and the quickstart for the test suite, CI badge, and encryption mode.

**Checkpoint**: The core behaviors are regression-protected on two platforms; plaintext-at-rest is operator-controlled.

## Phase 10: Research (optional, quarantined)

**Goal**: Prove or reject the remaining format families without destabilizing the core. Each task lands only with hashcat-example validation and phase-9 tests.

- [x] T074 [P] Research RIPEMD-160 (pure-Python implementation, 40-hex, adds ambiguity with SHA-1) — report or merge with validation.
- [x] T075 [P] Research adaptive formats (bcrypt, sha512crypt, phpass via Passlib) with a dedicated slow-format mode and drastically reduced budget semantics.
- [x] T076 [P] Research SHA-512/224 and SHA-512/256 (`hashlib.new` availability check per platform) — merge only if available everywhere v1 targets.

**Checkpoint**: Only validated, tested formats reach the supported list; rejected research is documented in plan.md.

## Dependency Order

1. Phase 9 tests (T067–T070) **should start first** — they lock in current v1 behavior as the regression baseline before phases 5–8 change the engine.
2. Phase 5 (salted) is independent of phase 8 tooling; phase 6 (hashlist) builds on the phase-5 worker signature if both are in flight.
3. Phase 7 (rules) wraps dictionary sources and depends on nothing beyond v1.
4. Phase 8 depends on phase 6 (per-target results feed export) but otherwise parallelizes.
5. Phase 10 strictly follows phase 9.

## Parallel Opportunities

- T034/T035 (registry + adapters) proceed together after the registry shape is agreed.
- T043 (hashlist parser) and T052 (rules) are independent.
- T067–T070 test files are independent of each other.
- Contract/doc updates ([P] tasks) can batch at each phase's end.

## Implementation Notes

- Salted formats keep hashcat naming (`md5_pass_salt`, etc.) mapped to display labels like `md5($pass.$salt)`.
- The multi-target worker returns per-batch match lists; a batch may match multiple targets at once.
- Rule expansion happens in the parent process before submission; workers stay pure hashing.
- Pause/resume stores the resume point in the job record, not in history; history rows only exist for terminal states.
- All new state-changing routes go through the existing CSRF gate.
