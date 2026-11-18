# Tasks: Rust Backend (Phase 11)

**Input**: Design documents from `/specs/003-rust-backend/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/ (api, cli, storage, installer), quickstart.md

**Tests**: Included — FR-212/SC-006 explicitly require automated suites for the second backend (cargo tests per crate + a cross-backend pytest parity shim). Vector tests land with the code they cover.

**Organization**: Tasks are grouped by user story (US1–US7 from spec.md) so each story can be implemented and validated independently. Task numbering continues the project convention (v1 = T001–T033, v2 = T034–T076) from **T077**.

**Constraint**: **No git operations anywhere in this round** (FR-213) — no branch, commit, or push steps exist in this plan; all work stays in the working tree.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US7)
- Include exact file paths in descriptions

## Path Conventions

- Rust workspace: `rust/` (crates `hc-core`, `hc-history`, `hc-server`, `hc-cli`)
- Python backend (additive only): `src/hash_cracker/`
- Scripts: `setup.sh`, `setup.ps1`, `serve.sh`, `serve.ps1`, `uninstall.sh`, `uninstall.ps1`
- Tests: `rust/crates/*/tests/` (cargo) + `tests/test_rust_parity.py` (pytest)

---

## Phase 11.1: Setup (Shared Infrastructure)

**Purpose**: Cargo workspace skeleton and dependency baseline

- [X] T077 Create the Cargo workspace at rust/: rust/Cargo.toml (workspace, edition 2021, members crates/hc-core, hc-history, hc-server, hc-cli, release profile), stub lib.rs/main.rs per crate, and rustfmt/clippy defaults
- [X] T078 [P] Add workspace dependencies per research.md (axum, tokio, tower-http, serde, serde_json, clap v4 derive, rusqlite bundled, md-5, sha1, sha2, ripemd, md-4, des, bcrypt, sha-crypt, fernet, scrypt, time, uuid, tempfile) and make `cargo check` pass
- [X] T079 [P] Verify a maintained phpass crate exists on crates.io; if not, record the decision to implement portable phpass in rust/crates/hc-core/src/adaptive.rs as a research.md D5 addendum

---

## Phase 11.2: Foundational (Blocking Prerequisites)

**Purpose**: Format registry, hashing, candidate sources, and the shared store — no story can start without these

**⚠ CRITICAL**: No user story work can begin until this phase is complete

- [X] T080 Implement the format registry in rust/crates/hc-core/src/formats.rs: exact ALGORITHM_NAMES order (23 ids), labels, kinds (fast/salted/adaptive), digest lengths, ambiguity groups (16→lm; 32→md5,ntlm,md4,lm; 40→sha1,ripemd160; 56→sha224,sha512_224; 64→sha256,sha512_256; 96→sha384; 128→sha512), SALTED map, adaptive prefixes ($2, $6$, $P$) with unit tests against the pinned catalog
- [X] T081 [P] Implement hashing adapters in rust/crates/hc-core/src/hashing.rs: md5/sha1/sha224/sha256/sha384/sha512/sha512_224/sha512_256/ripemd160, md4 (RFC 1320 vector), ntlm (MD4 over UTF-16LE), lm (des crate, KGS!@#$%, odd-parity keys, 16-hex prefix comparison semantics), salted pass+salt/salt+pass UTF-8 digests, with RFC/hashcat vector tests in rust/crates/hc-core/tests/
- [X] T082 [P] Implement adaptive verification in rust/crates/hc-core/src/adaptive.rs (bcrypt crate, sha-crypt sha512_crypt, phpass path per T079) validated against Passlib-generated vectors in rust/crates/hc-core/tests/
- [X] T083 [P] Implement identification in rust/crates/hc-core/src/identify.rs: adaptive-prefix first, strict lowercase-hex + length group lookup, offending-chars error (≤8), unknown-length error listing supported lengths, explicit-selection validation — matching contracts/api.md §identify, with tests
- [X] T084 [P] Implement candidate sources in rust/crates/hc-core/src/candidates.rs: dictionary streaming (utf-8 errors=replace, only \r\n/\n stripped, batch 8192, best-effort line count), hashlist parsing (blank lines/# comments skipped, algorithm:hash prefix, bare 32-hex rejected, salted/adaptive rejected, line-numbered errors, empty rejected) with tests
- [X] T085 [P] Implement brute-force generation in rust/crates/hc-core/src/bruteforce.rs: charset presets (lower/upper/digits/symbols with string.punctuation exactly), resolve_charset (presets + literals, dedup, comma-not-literal), per-length lexicographic product order, total_space computation, validation (min≥1, max≥min, budget 1–10,000,000) with tests
- [X] T086 [P] Implement rules in rust/crates/hc-core/src/rules.rs: presets capitalize/upper/lower/leetspeak (a→4 e→3 i→1 o→0 s→5)/append_digits_0_99/append_years/all (deduped union), original-word-first order, budget-truncating expansion iterator with tests
- [X] T087 Implement the shared store in rust/crates/hc-history/src/store.rs: exact DDL from contracts/storage.md, additive migrations via PRAGMA table_info + ALTER TABLE (including backend TEXT), record_run/list_runs (limit 100, run_id DESC)/clear_runs, CSV+JSON export with the pinned column order, millisecond-UTC timestamps, legacy ~/.password_audit rename, on temp-DB tests including cross-migration with a Python-created database fixture

**Checkpoint**: Foundation ready — engine work can begin; `cargo test` green for all foundational crates

---

## Phase 11.3: User Story 3 — Identical auditing capability through the second backend (Priority: P1) — MVP

**Goal**: The Rust engine audits with identical behavior to Python: formats, modes, rules, budgets, statuses, pause/resume offsets, benchmark; surfaced through a working `hashcrack-rs` CLI for identify/audit/benchmark

**Independent Test**: Feed the same targets (published example vectors for every supported format) to both CLIs in each mode; every run ends with the same status, matched candidate, and attempt totals

### Implementation for User Story 3

- [X] T088 [US3] Implement the single-target engine in rust/crates/hc-core/src/engine.rs: bounded worker threads (workers 1–8, default 4), batch 8192, in-flight cap max(workers*2, 4), candidate-level attempt math (match ⇒ offset+match_index+1; completion ⇒ max(attempts, offset+batch_size); truncation to budget remaining), budget_is_limit semantics (budget_exhausted only when space remains), statuses match/no_match/cancelled/budget_exhausted/paused/interrupted/invalid_input, cancel + pause events checked between batch submissions — with attempt-math and status tests
- [X] T089 [US3] Implement the hashlist engine in rust/crates/hc-core/src/engine.rs (run_hashlist_audit): one shared candidate stream, per-algorithm digest maps plus 16-hex LM prefix map, candidate-based shared budget, all-matched early stop, per-target results (match/no_match/paused, match_at_attempt) — with tests
- [X] T090 [US3] Implement resume support in rust/crates/hc-core/src/engine.rs: resume_state {attempts_base, skip_source} generation, re-stream + discard offsets, hashlist matched_plaintext/matched_attempt maps, wordlist byte-size change validation helper — with tests
- [X] T091 [US3] Implement benchmark in rust/crates/hc-core/src/benchmark.rs: measure_algorithm/measure_all (sample benchmark-sample-candidate-0001 + growing numeric suffix, wall-clock slice) — with a deterministic smoke test
- [X] T092 [US3] Implement the hc-cli binary in rust/crates/hc-cli/src/main.rs: clap surface per contracts/cli.md for identify/audit/benchmark (--hashlist, --rules, --algorithm, --mode, --wordlist, --salt, --charset, --min-length/--max-length, --max-candidates, --workers, --database), retention warning [yes/no] with --yes override, human output sections (Mode/Algorithm/Hashlist/Workers/Charset/Lengths/Budget/Rules → Status/Attempts/Elapsed/Workers/Targets/Plaintext/Hash/Batch), stderr progress throttled 0.25 s with rate+ETA, exit codes 0/1/2/3 — with CLI integration tests against a temp DB

**Checkpoint**: User Story 3 independently functional — `hashcrack-rs identify/audit/benchmark` produce parity-verified results; this is the MVP increment

---

## Phase 11.4: User Story 4 — Same dashboard, either backend (Priority: P2)

**Goal**: The built React dashboard runs unchanged against the Rust server: same routes, JSON shapes, CSRF semantics, job lifecycle, static serving

**Independent Test**: Point the built dashboard at each backend and exercise identify → audit → pause → resume → history → export; every screen behaves the same

### Implementation for User Story 4

- [X] T093 [US4] Implement the axum server skeleton in rust/crates/hc-server/src/main.rs + app.rs: loopback-only bind on 127.0.0.1:8765 (configurable port), router with all 14 routes, uniform {"error": ...} responses, GET /api/session (token + Set-Cookie pa_csrf SameSite=Strict Path=/ no HttpOnly), CSRF middleware for state-changing POSTs (Origin/Referer same-host check, X-CSRF-Token == pa_csrf cookie, /api/identify exempt) — with oneshot integration tests
- [X] T094 [P] [US4] Implement GET /api/formats and POST /api/identify in rust/crates/hc-server/src/routes.rs with byte-exact JSON shapes per contracts/api.md — with contract tests
- [X] T095 [US4] Implement audit submission in rust/crates/hc-server/src/jobs.rs: multipart parsing with 256 MiB cap (413 fixed message), field validation with the exact error strings, single-slot 409 message, 202 {"job_id","state":"validating"}, upload staging via tempfile, runner thread transitioning validating→running→terminal — with tests
- [X] T096 [US4] Implement polling and job results in rust/crates/hc-server/src/jobs.rs: GET /api/audits/<id> shapes (single vs hashlist vs cancelled-from-paused), budget null semantics, interrupted/storage_error strings, 404 unknown job — with tests
- [X] T097 [US4] Implement pause/resume/cancel in rust/crates/hc-server/src/jobs.rs: pause event → drained pool → paused + sidecar persistence (paused_jobs/<job_id>.json + moved uploads, 0600/0700 POSIX), resume validation ("gone"/"changed"/invalid stored params messages), cancel of live and threadless jobs, startup restore of newest sidecar with 7-day cleanup — with tests covering the full state machine
- [X] T098 [P] [US4] Implement static serving in rust/crates/hc-server/src/static_files.rs: GET / (index.html, no-cache/no-store/must-revalidate), asset resolution under static/ with directory→index.html clean-URL convention, /assets path support, 503 build-hint message, 404 {"error": "Not found."} — with tests

**Checkpoint**: User Stories 3 AND 4 both work independently — dashboard fully usable against the Rust server

---

## Phase 11.5: User Story 5 — CLI parity (Priority: P2)

**Goal**: `hashcrack-rs` mirrors the full `hashcrack` surface: history, export, serve, same outputs and exit codes

**Independent Test**: Run every subcommand with identical arguments on both CLIs; outputs match in structure and JSON export equality

### Implementation for User Story 5

- [X] T099 [US5] Implement history and export subcommands in rust/crates/hc-cli/src/main.rs: history table (ID/Started (UTC)/Status/Alg/Mode/Attempts/Elapsed/W/Hash / plaintext, <encrypted> placeholder), --limit/--passphrase/--unlock with the passphrase source chain (flag → PASSWORD_AUDIT_PASSPHRASE → prompt), wrong-passphrase exit 3 message; export PATH --format csv|json with contract-pinned column order — with tests
- [X] T100 [US5] Implement the serve subcommand in rust/crates/hc-cli/src/main.rs reusing hc-server (--port, loopback) and run a full CLI parity sweep: flag-for-flag diff against hashcrack --help for all subcommands, JSON export equality on a shared fixture DB — with parity test notes in rust/crates/hc-cli/tests/

**Checkpoint**: CLI parity complete — scripts written against hashcrack work with hashcrack-rs by name swap

---

## Phase 11.6: User Story 6 — Cross-backend history and encryption (Priority: P2)

**Goal**: One history store, one encryption scheme, attribution visible — runs readable/unlockable across backends

**Independent Test**: Record an encrypted run with one backend, unlock and export it with the other; plaintext and metadata match

### Implementation for User Story 6

- [X] T101 [US6] Implement encryption-at-rest in rust/crates/hc-history/src/encryption.rs: scrypt (N=16384, r=8, p=1, dklen=32, 16-byte salt) + Fernet tokens, history_meta enc_salt/enc_verify (verify token = encrypt(b"ok")), enc1: prefix handling, "<encrypted>"/"<decryption failed>" placeholders, encrypted_count — validated against Python-produced ciphertext fixtures in rust/crates/hc-history/tests/
- [X] T102 [US6] Wire unlock surfaces: POST /api/history/unlock in hc-server (passphrase required message, 403 Wrong passphrase., in-memory key cache) and hashcrack-rs history --unlock — with tests
- [X] T103 [US6] Add backend attribution on the Python side: src/hash_cracker/history.py MIGRATION_COLUMNS gains ("backend", "TEXT"), record_run backend param (default "python"), AuditRecord/export field, EXPORT_COLUMNS order per contracts/storage.md, /api/history + export include backend; update affected pytest assertions (additive only)
- [X] T104 [US6] Add backend attribution on the Rust side: hc-history record_run backend="rust", store/export/API fields — with tests
- [X] T105 [US6] Create tests/test_rust_parity.py: cross-backend pytest shim (skips with a clear message when rust/target/release binary is absent) — same-DB record written by Python read by Rust and vice versa, encrypted record from one unlocked by the other, CSV export byte-equality on a shared fixture, backend attribution assertions

**Checkpoint**: History, unlock, and export work across backends; both suites green

---

## Phase 11.7: User Story 1 — Install either backend or both (Priority: P1)

**Goal**: setup.sh/setup.ps1 ask Python / Rust / Both (default Python) with automatic Rust toolchain provisioning

**Independent Test**: Run setup with each choice; after Rust only hashcrack-rs is added, after Both both exist, Python install never broken

### Implementation for User Story 1

- [X] T106 [US1] Extend setup.sh: --backend python|rust|both flag + interactive prompt (bare Enter ⇒ python, non-interactive without flag ⇒ usage error exit 2), Rust path (cargo check → rustup provisioning mirroring the Node pattern with clear failure messages → cargo build --release → binary in place), Both = python then rust with independent failure reporting, no-clobber of the other backend, exit codes 0/1/2
- [X] T107 [P] [US1] Extend setup.ps1 with the identical behavior (PowerShell flavor: rustup-init.exe from https://win.rustup.rs/x86_64 -y --default-toolchain stable, venv/binary detection per platform)

**Checkpoint**: User Story 1 independently testable — install matrix works on Windows and Git Bash

---

## Phase 11.8: User Story 2 — Choose the backend when starting the server (Priority: P1)

**Goal**: serve.sh/serve.ps1 ask Python or Rust (default Python) with --backend override and single-backend fallback notes

**Independent Test**: Start the server with each choice and the override flag; the dashboard loads and identifies a hash through the API in both cases; non-interactive runs never prompt

### Implementation for User Story 2

- [X] T108 [US2] Extend serve.sh: --backend python|rust (either argument order with the port), interactive prompt only when both installed and stdin is a TTY (bare Enter ⇒ python), single-installed-backend note-and-start fallback, neither-installed failure with setup instructions (incl. the Rust line), --backend with missing backend ⇒ exit 1 message naming the setup command, launch hashcrack-rs serve --port N; add uninstall.sh removal-note touchpoint
- [X] T109 [P] [US2] Extend serve.ps1 with the identical behavior plus uninstall.ps1 note (PowerShell flavor)

**Checkpoint**: All user stories functional — install → serve → audit → history flow works end to end on both backends

---

## Phase 11.9: Polish & Cross-Cutting Concerns (User Story 7 + delivery hygiene)

**Purpose**: Full-format verification, performance honesty, documentation, guards, final validation

- [X] T110 [US7] Complete the full format-vector sweep in rust/crates/hc-core/tests/ (hashcat example hashes for all 23 formats incl. salted and adaptive) and API contract fixtures in rust/crates/hc-server/tests/ (pinned JSON shapes for every route)
- [X] T111 [US7] Run the benchmark parity check (SC-007): hashcrack-rs benchmark vs hashcrack benchmark on this machine, record results in specs/003-rust-backend/quickstart.md §7; fast-hash dictionary throughput must be ≥ Python's
- [X] T112 [P] Update documentation: README Phase 11 section (Rust backend coexistence, new prompts, hashcrack-rs), frontend unchanged note, attribution field note in the history docs
- [X] T113 Execute specs/003-rust-backend/quickstart.md scenarios 1–7 end to end and fix any gaps found
- [X] T114 Run the guard skills on the round's output (clean-code-guard on rust/ + script diffs, test-guard on cargo tests + test_rust_parity.py, docs-guard on README/spec/docs changes) and address every finding
- [X] T115 Final sweep: cargo test, pytest (full suite incl. test_rust_parity.py), clippy clean, both servers validated on a fresh port; confirm zero git operations were performed

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (11.1)**: no dependencies — start immediately
- **Foundational (11.2)**: depends on Setup — BLOCKS all user stories
- **US3 (11.3)**: depends on Foundational — the engine MVP
- **US4 (11.4)**: depends on US3 (engine + store must exist for jobs to run)
- **US5 (11.5)**: depends on US3 (CLI exists) and US4 (serve reuses the server)
- **US6 (11.6)**: depends on Foundational store (T087) and US4 server (for unlock endpoints)
- **US1 (11.7)**: depends on the Rust workspace building (T078) — script tasks launch real binaries
- **US2 (11.8)**: depends on US1 (detected install layout) and US4/US5 (both serve paths exist)
- **Polish (11.9)**: depends on all desired stories being complete

### User Story Dependencies

- **US3**: independent after Foundational — the MVP slice
- **US4**: integrates US3's engine; independently testable via the API surface
- **US5**: integrates US3/US4; independently testable via CLI diff
- **US6**: integrates store + both servers; independently testable via cross-backend fixtures
- **US1/US2**: thin script layers; independently testable via install matrix + launch matrix

### Within Each Story

- Registry/hashing before engine; engine before server jobs; server before CLI serve; store before encryption; scripts last (they orchestrate finished binaries)
- Contract tests accompany each endpoint; vector tests accompany each format

### Parallel Opportunities

- Phase 11.2: T081–T086 all [P] (independent modules)
- Phase 11.4: T094 and T098 [P] against the server skeleton
- Phase 11.5/11.6: store/encryption modules parallel to server polish
- Phase 11.7/11.8: T107/T109 [P] mirror-script tasks once the POSIX flavor is decided
- Phase 11.9: T112 [P] documentation alongside T111

---

## Parallel Example: Phase 11.2

```bash
# Launch all independent foundational modules together:
Task: "Implement hashing adapters in rust/crates/hc-core/src/hashing.rs (T081)"
Task: "Implement adaptive verification in rust/crates/hc-core/src/adaptive.rs (T082)"
Task: "Implement identification in rust/crates/hc-core/src/identify.rs (T083)"
Task: "Implement candidate sources in rust/crates/hc-core/src/candidates.rs (T084)"
Task: "Implement brute-force generation in rust/crates/hc-core/src/bruteforce.rs (T085)"
Task: "Implement rules in rust/crates/hc-core/src/rules.rs (T086)"
```

---

## Implementation Strategy

### MVP First (US3 only)

1. Complete Phase 11.1 + 11.2 (foundation)
2. Complete Phase 11.3 (US3) → **STOP and VALIDATE**: `hashcrack-rs` audits with parity vs `hashcrack`
3. The tool is usable end-to-end via the Rust CLI even before the server/scripts exist

### Incremental Delivery

1. Foundation → US3 (MVP) → validate parity vectors
2. US4 → dashboard works against either backend → validate with the built frontend
3. US5 + US6 → full CLI parity + shared encrypted history
4. US1 + US2 → installer/launcher prompts complete the operator story
5. Polish → vectors, benchmark honesty, docs, guards, quickstart sweep

### Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to spec user story for traceability
- **No git operations at any step** (FR-213) — replaces the usual per-task commit guidance
- Stop at any checkpoint to validate the story independently
- Avoid: vague tasks, same-file conflicts, cross-story dependencies that break independence
