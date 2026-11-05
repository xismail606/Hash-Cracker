# Feature Specification: Feature Expansion (v2 Plan)

**Feature Branch**: `002-feature-expansion`

**Created**: 2026-11-05

**Status**: Draft (planning only — no implementation started)

**Input**: Operator request to plan all proposed additions and improvements to the completed v1 Hash Cracker tool, grouped from the operator's review of the post-v1 suggestion list.

## Purpose

v1 (specs/001-offline-password-audit) delivered a working offline audit tool with nine supported hash formats, dictionary and bounded brute-force modes, a CLI and local dashboard, and SQLite history. This second plan organizes the next round of work into five phases that deepen real auditing capability without changing v1's safety boundaries: local-only processing, bounded candidate work, loopback-only dashboard, and honest algorithm identification.

## User Scenarios & Testing

### User Story 1 — Audit salted hashes (Priority: P1)

An auditor supplies a target hash **and its known salt** (e.g. `md5($pass.$salt)` in hashcat mode 10) and audits it with dictionary or bounded brute-force mode exactly as with unsalted formats.

**Why**: Salted fast hashes make up the largest useful block of hashcat's catalog (modes 10–180). Without them the tool cannot audit common legacy web/database password stores.

**Independent test**: Use hashcat's salted example hashes (which contain the salt after the colon); verify a dictionary audit with the correct salt finds `hashcat`, and that a wrong salt produces an honest no_match.

### User Story 2 — Audit many hashes in one run (Priority: P1)

An auditor submits a hashlist (one hash per line) and one wordlist; the tool reports a per-hash result table showing which entries matched and which did not.

**Why**: Real credential-policy audits cover an entire system's password store, not one hash at a time. Re-running the same dictionary per hash wastes most of the work.

**Independent test**: A three-line hashlist (one MD5, one SHA-256, one NTLM, all `hashcat`) audited with a wordlist containing `hashcat` produces three match records plus the run summary.

### User Story 3 — Multiply wordlist effectiveness with rules (Priority: P2)

An auditor selects a mutation preset (capitalization, digit suffixes, leetspeak, common years) and the tool audits the wordlist **and its mutations** inside the same candidate budget.

**Why**: Real passwords are rarely stored verbatim; simple mutations crack a large share of real-world hits without a bigger wordlist.

**Independent test**: A two-line wordlist (`hash`, `cat`) with an "append digits 0–99" preset produces candidates such as `hash12` and `cat99`; the total evaluated count respects the configured budget and attempt accounting stays exact.

### User Story 4 — Practical tooling in both interfaces (Priority: P2)

An operator can benchmark per-algorithm throughput on their machine, pause and resume a dashboard job, export history from the dashboard, see an ETA during progress, and choose at run level to keep plaintext out of the database.

**Why**: These convert the tool from a demo into a daily-driver auditing utility.

**Independent test**: `benchmark` prints per-algorithm hashes/second; a paused web job resumes and finishes with correct attempt accounting; dashboard export downloads a valid CSV; a no-plaintext run records a match row with an empty plaintext field and a clear note.

### User Story 5 — Trustworthy, maintainable core (Priority: P2)

An automated pytest suite covers hashing vectors, brute-force generation, engine accounting, and web API behavior; the operator may optionally encrypt stored plaintexts with a passphrase.

**Why**: v1 has no automated tests; every algorithm addition so far was verified manually. Encryption addresses the standing risk of plaintext credential data sitting in a local SQLite file.

**Independent test**: `pytest` passes on Windows and Linux CI; an encrypted-history run stores ciphertext in the DB and the CLI prompts for the passphrase to display results.

### User Story 6 — Extended format research (Priority: P3, optional)

If research succeeds, the tool adds RIPEMD-160 (pure Python), adaptive formats (bcrypt/sha512crypt/phpass via Passlib with a dedicated low-budget mode), and SHA-512/224 / SHA-512/256.

**Why**: Completes the unsalted fast-hash catalog and unlocks common Unix formats; each is a self-contained experiment that must not destabilize the core.

**Independent test**: Each new format passes hashcat example-hash validation and regression checks before merging.

## Edge Cases

- Salted runs: a wrong salt never matches; the salt is stored in history alongside the target hash so reports can reproduce the audit; salts containing non-UTF-8 bytes are rejected with a clear message.
- Hashlists: blank lines and comments (`#`) in a hashlist file are skipped; an invalid line fails validation of the whole file before any processing; duplicate hashes are preserved as separate targets; a 32-hex line must still resolve its MD5/NTLM/MD4 ambiguity — hashlist files may carry an explicit `algorithm:hash` prefix per line.
- Rules: mutated candidates count toward the candidate budget; the budget can truncate the mutation space, and the run status `budget_exhausted` reflects that; rule expansion never changes the wordlist file itself.
- Pause/resume: a paused job releases its worker pool; resume continues from the recorded offset without re-counting attempts; resuming a dictionary run after the wordlist file changed on disk is rejected with a clear message.
- No-plaintext mode: match rows still record algorithm, attempts, timing, and a `plaintext withheld` marker; the dashboard result panel shows the match without the plaintext.
- Encrypted history: without the passphrase, matches are visible as metadata only; wrong passphrases fail cleanly; losing the passphrase makes stored plaintext unrecoverable (documented).
- Benchmark: measures CPU-bound throughput on the local machine only; results are informational and never persisted to history.

## Requirements

- **FR-101**: Salted fast-hash formats MUST be supported for a user-supplied salt, initially covering `md5($pass.$salt)`, `md5($salt.$pass)`, `sha1($pass.$salt)`, `sha1($salt.$pass)`, `sha256($pass.$salt)`, `sha256($salt.$pass)`, `sha512($pass.$salt)`, and `sha512($salt.$pass)`; the salt MUST be stored in the audit record.
- **FR-102**: The tool MUST accept a hashlist file (one target per line, optional `algorithm:` prefix) and audit every target in a single candidate pass, reporting per-target results.
- **FR-103**: The tool MUST apply mutation presets to dictionary candidates, with the candidate budget applied to the expanded stream.
- **FR-104**: The tool MUST provide a `benchmark` command reporting per-algorithm candidates/second on the local machine.
- **FR-105**: Dashboard jobs MUST support pause and resume with exact attempt accounting.
- **FR-106**: The dashboard MUST offer history export (CSV/JSON) and display an ETA during progress.
- **FR-107**: An operator MUST be able to start a run in no-plaintext mode, in which case the match record omits the plaintext.
- **FR-108**: An automated test suite MUST cover hashing vectors, candidate generation, engine accounting, and the web API, and MUST pass on Windows and Linux.
- **FR-109**: The operator MAY enable at-rest encryption of stored plaintexts, keyed by an operator passphrase entered when needed.
- **FR-110**: All v1 safety boundaries remain unchanged: local-only processing, loopback-only dashboard, bounded candidates, bounded workers, no external transmission.

## Success Criteria

- SC-201: Salted hashcat example hashes (modes 10, 20, 110, 120, 1410, 1420, 1710, 1720) audit to plaintext `hashcat` with the example salts through both interfaces.
- SC-202: A three-target hashlist audit produces three per-target results plus one run summary, with total attempts equal to the sum of per-target attempts.
- SC-203: Rule expansion is deterministic, budget-respecting, and exactly accounted.
- SC-204: Benchmark output matches observed throughput within a ±20% sanity band across two consecutive runs.
- SC-205: The pytest suite passes in CI on windows-latest and ubuntu-latest.
- SC-206: With no-plaintext mode on, no history row contains a plaintext value; with encryption on, no plaintext is stored in cleartext in the database file.

## Assumptions

- v1 is complete and deployed (all 33 tasks done); v2 work happens on top of the current tree.
- Salted runs keep the one-candidate-one-hash comparison model; the salt is a per-run constant supplied by the operator.
- Adaptive formats (bcrypt et al.) need per-run cost calibration and a much smaller effective budget; they are quarantined in a research phase until proven.
- DB encryption uses application-level cryptography keyed by a passphrase; SQLCipher is out of scope for a student toolchain.
- No changes to v1's loopback, budget, worker, or offline constraints.
