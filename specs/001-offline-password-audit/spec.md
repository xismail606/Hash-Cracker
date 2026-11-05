# Feature Specification: Hash Cracker

**Feature Branch**: `001-offline-password-audit`

**Created**: 2026-11-05

**Status**: Draft

**Input**: User-provided project brief: build a Python-based offline hash-cracking and password-auditing utility with hash identification, dictionary and bounded brute-force modes, CLI and web interfaces, multiprocessing, and local result history.

## User Scenarios & Testing

### User Story 1 - Identify a hash format (Priority: P1)

An authorized auditor submits a hash and sees the supported algorithms whose formats match its length and character structure. When multiple algorithms share the same structure, the tool reports the ambiguity and asks for an explicit selection.

**Why this priority**: The selected algorithm determines how every candidate is encoded and hashed; a mistaken automatic guess would invalidate the audit result.

**Independent Test**: Submit synthetic MD5, SHA-256, and NTLM hashes plus malformed values; verify that SHA-256 is recognized by shape and that 32-character hexadecimal values are reported as ambiguous between MD5, NTLM, and MD4.

**Acceptance Scenarios**:

1. **Given** a 64-character hexadecimal hash, **When** the user requests identification, **Then** the tool lists SHA-256 as the compatible supported format.
2. **Given** a 32-character hexadecimal hash, **When** the user requests identification, **Then** the tool lists both MD5 and NTLM and requires the user to choose one.
3. **Given** a malformed or unsupported value, **When** the user requests identification, **Then** the tool explains the input problem and does not start an audit.

---

### User Story 2 - Crack a supplied hash with dictionary or brute-force mode (Priority: P1)

An authorized auditor chooses a local dictionary or a bounded brute-force search, supplies the required inputs, and sees whether a plaintext candidate matches the target hash.

**Why this priority**: Candidate comparison is the central project capability described in the assignment.

**Independent Test**: Use synthetic hashes and short candidate sets to verify a dictionary match, a brute-force match, a no-match result, the configured candidate limit, and the number of attempted candidates.

**Acceptance Scenarios**:

1. **Given** a supported hash and a local dictionary containing its plaintext, **When** dictionary mode completes, **Then** the tool reports the matching plaintext, attempts, and elapsed time.
2. **Given** a supported hash and a configured character set and length range containing its plaintext, **When** brute-force mode completes, **Then** the tool reports the match without exceeding the configured candidate budget.
3. **Given** a dictionary with no match or a brute-force range exhausted without a match, **When** the audit completes, **Then** the tool reports no match and the exact number of candidates attempted.
4. **Given** invalid mode-specific options or an exceeded candidate budget, **When** the user starts an audit, **Then** the tool rejects or safely stops the run and reports its final state.

---

### User Story 3 - Use the CLI or local web dashboard (Priority: P1)

An auditor runs the same supported identification and audit modes from either the CLI or the local dashboard, sets worker limits, and monitors live progress.

**Why this priority**: The brief requests an interactive command-line interface or web dashboard; the project will provide both for the requested deliverable.

**Independent Test**: Run a synthetic dictionary and brute-force audit through the CLI and through the dashboard; compare algorithm selection, progress, attempts, result, and error behavior.

**Acceptance Scenarios**:

1. **Given** a valid CLI audit request, **When** the command runs, **Then** it displays the selected mode, worker count, progress, attempts, elapsed time, and terminal result.
2. **Given** a valid web audit request, **When** the run starts, **Then** the dashboard displays live progress and the recovered plaintext for a successful match.
3. **Given** a request from another origin or a non-loopback network client, **When** it attempts to reach or mutate a web audit, **Then** the local dashboard denies the request.
4. **Given** a web wordlist upload larger than 100 MiB, **When** the user submits it, **Then** the dashboard rejects it before candidate processing.

---

### User Story 4 - Store results and review audit history (Priority: P2)

An auditor reviews previous runs and exports local reports containing successful plaintext/hash pairs, elapsed time, and total attempts for credential-policy review.

**Why this priority**: Durable local records provide the reporting and policy-review value specified by the assignment.

**Independent Test**: Complete one synthetic match and one no-match run; verify that SQLite records both run summaries and that the successful result includes its plaintext/hash pair, attempt count, and duration.

**Acceptance Scenarios**:

1. **Given** a successful match, **When** the run is saved, **Then** local history records the plaintext, target hash, algorithm, attempts, elapsed time, mode, and timestamp.
2. **Given** a completed no-match run, **When** it is saved, **Then** history records its target hash, algorithm, attempts, elapsed time, mode, and no-match status.
3. **Given** a history request, **When** the user lists or exports records, **Then** the report contains the recorded audit metadata and identifies successful matches.

## Edge Cases

- MD5, NTLM, and MD4 digests all use 32 hexadecimal characters; structure alone cannot distinguish them.
- SHA-256 digests use 64 hexadecimal characters; malformed lengths and non-hex characters are rejected.
- Uppercase hexadecimal input is normalized for comparisons while the submitted representation can be retained in the audit record.
- Dictionary files with blank lines, duplicate entries, invalid UTF-8, or a final line without a newline are handled consistently and documented.
- Brute-force mode requires a selected character set, minimum and maximum lengths, and a maximum-candidate budget. The budget prevents accidental unbounded searches.
- The multiprocessing worker count is bounded from 1 through 8. The user can stop a run, and the tool stops scheduling new candidate chunks.
- A missing, unreadable, or oversized web upload is rejected before processing; temporary uploads are removed on failure, completion, cancellation, and shutdown.
- Database errors and interruptions are reported as incomplete/failed runs, never as successful matches.
- Successful plaintext/hash pairs are sensitive audit data. The app displays a warning before storing them in the local database and keeps the database local.
- The web server only listens on loopback and does not make external requests.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST accept one target hash at a time for a local offline audit that the operator is authorized to perform.
- **FR-002**: The system MUST inspect hash length and character structure and report compatible algorithms; it MUST NOT claim that shape alone uniquely proves an algorithm when formats overlap.
- **FR-003**: The system MUST support explicit algorithm selection when a hash shape is ambiguous, including the MD5/NTLM 32-hex overlap.
- **FR-004**: Dictionary mode MUST compare the target against entries from a finite local wordlist supplied by the operator.
- **FR-005**: Brute-force mode MUST generate candidates only from a user-selected character set and configured minimum/maximum length, and MUST stop at a configured candidate budget.
- **FR-006**: The initial supported algorithms MUST include MD5, SHA-256, and NTLM. The system MUST clearly reject formats outside the supported set. (Extended post-v1 at the operator's request: SHA-1, SHA-224, SHA-384, SHA-512, MD4, and LM — all unsalted, single-pass formats; salted and adaptive formats remain out of scope.)
- **FR-007**: The system MUST use bounded multiprocessing for candidate comparison, allow a worker limit from 1 through 8, and report effective workers, attempts, progress, and elapsed time.
- **FR-008**: The system MUST provide a CLI for hash, algorithm, mode, wordlist or brute-force options, worker count, and history/report operations.
- **FR-009**: The system MUST provide a local web dashboard for hash input, mode selection, progress monitoring, and result display.
- **FR-010**: The web application MUST bind to loopback only, reject cross-origin state-changing requests, and MUST NOT transmit audit data to external services.
- **FR-011**: The web application MUST accept wordlist uploads up to 100 MiB and remove temporary copies after completion, cancellation, validation failure, or shutdown.
- **FR-012**: The system MUST store audit history locally in SQLite, including algorithm, mode, status, total attempts, elapsed time, timestamp, and target hash.
- **FR-013**: For successful matches, the system MUST automatically record the recovered plaintext and corresponding target hash in local history for reporting. Before candidate processing begins, the system MUST warn that successful results are sensitive credential data and require the operator to acknowledge local retention.
- **FR-014**: The system MUST distinguish match, no-match, invalid input, cancelled/interrupted, candidate-budget-exceeded, and storage-failure outcomes.

### Key Entities

- **Hash Assessment**: Submitted value, normalized digest, supported algorithm candidates, and ambiguity state.
- **Audit Request**: Target digest, selected algorithm, dictionary or brute-force mode, candidate-source settings, worker count, and candidate budget.
- **Candidate Source**: Either a finite local wordlist or a generated sequence bounded by the selected charset, lengths, and candidate budget.
- **Audit Run**: Timestamp, target hash, algorithm, mode, status, total attempts, elapsed time, worker count, and optional matched plaintext.
- **Audit History Record**: Persisted local run details, including plaintext/hash pair for a successful match.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Supported hash test values (MD5, SHA-256, NTLM, and the extended set: SHA-1, SHA-224, SHA-384, SHA-512, MD4, LM) are classified as compatible formats; 32-character hexadecimal values are always shown as ambiguous between MD5, NTLM, and MD4 until explicitly selected.
- **SC-002**: Dictionary mode correctly identifies a known matching entry and reports exact attempts and elapsed time on a synthetic wordlist of 100,000 entries.
- **SC-003**: Brute-force mode finds a synthetic test secret when its charset and length are included, and never evaluates more candidates than the configured budget.
- **SC-004**: Both interfaces expose the same algorithm selection, audit modes, worker limits, and terminal result states.
- **SC-005**: 100% of successful synthetic matches are recorded in local history with plaintext/hash pair, algorithm, attempt count, elapsed time, and timestamp.
- **SC-006**: The dashboard is accessible only on loopback and rejects oversized uploads before processing.

## Assumptions

- This is an authorized offline educational audit tool. It does not test remote logins or accept remote targets.
- Both CLI and local web dashboard will be included, following the user's later preference.
- Python 3.11+ will provide the core engine, CLI, Flask server, and SQLite access. Astro/React/JavaScript/Tailwind will provide the browser UI.
- MD5 and SHA-256 use Python `hashlib`; NTLM candidate hashing requires a dedicated Python implementation because NTLM uses MD4 over UTF-16LE input.
- Brute-force mode will have a bounded default budget of 1,000,000 candidates and a hard maximum of 10,000,000 per run; the selected charset and length range remain explicit.
- Worker count will default to 4 and have a hard maximum of 8.
- Successful plaintext/hash pairs are intentionally stored in local SQLite because the project brief explicitly requests them; the user receives a warning before an audit is saved.
- Web wordlist uploads are limited to 100 MiB; the CLI can read larger local files.
- The project contains no implementation yet; commands and structures are planned contracts.
