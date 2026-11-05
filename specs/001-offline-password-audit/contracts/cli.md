# CLI Contract: Hash Cracker

The commands below are the planned v1 interface; final option spelling is confirmed during implementation.

## Commands

```text
python -m password_audit identify HASH
python -m password_audit audit HASH --algorithm NAME --mode dictionary --wordlist PATH [--workers N]
python -m password_audit audit HASH --algorithm NAME [--salt VALUE] --mode dictionary --wordlist PATH [--workers N]
python -m password_audit audit HASH --algorithm NAME [--salt VALUE] --mode brute-force --charset PRESET_OR_TEXT --min-length N --max-length N [--max-candidates N] [--workers N]
python -m password_audit history [--database PATH]
python -m password_audit export PATH [--format csv|json]
python -m password_audit serve [--port PORT]
```

## Identify

- Accept one hash string.
- Recognize the supported format shapes: LM (16 hex), MD5 (32 hex), NTLM (32 hex), MD4 (32 hex), SHA-1 (40 hex), SHA-224 (56 hex), SHA-256 (64 hex), SHA-384 (96 hex), and SHA-512 (128 hex).
- Report MD5/NTLM/MD4 as ambiguous for a 32-character hexadecimal input and require the operator to choose before auditing.
- Reject malformed or unsupported shapes with a clear message.
- Do not start candidate processing.

### Hashlist (Multi-Target)

- `--hashlist PATH` audits many targets in one candidate pass (mutually
  exclusive with a positional HASH). Lines carry an explicit
  `algorithm:hash` prefix (e.g. `md5:8743b520…`) or a bare hash whose shape
  resolves to exactly one supported format; bare 32-hex lines are rejected
  because MD5/NTLM/MD4 cannot be proven by shape. Blank lines and `#`
  comments are skipped; the whole file is validated before processing.
- Salted formats are not supported in hashlists (no per-target salt).
- The run reports a per-target result table; history stores one record per
  target plus a batch summary under a shared batch ID.

### Rules (Dictionary Mutations)

- `--rules PRESET` expands dictionary candidates with deterministic
  mutations. Presets: `capitalize`, `upper`, `lower`, `leetspeak`,
  `append_digits_0_99`, `append_years`, `all` (default: `none`).
- The candidate budget governs the expanded stream; a truncated expansion
  reports `budget_exhausted`. Original words are attempted first, then their
  variants; matches found via a mutated candidate report the mutated
  plaintext.

### Salted Formats

- Eight salted fast-hash formats are supported with an operator-supplied salt:
  `md5_pass_salt` (hashcat 10), `md5_salt_pass` (20), `sha1_pass_salt` (110),
  `sha1_salt_pass` (120), `sha256_pass_salt` (1410), `sha256_salt_pass` (1420),
  `sha512_pass_salt` (1710), and `sha512_salt_pass` (1720).
- They require `--salt VALUE` (the known salt stored alongside the hash) and
  reject `--salt` on unsalted formats. Shape identification lists only the
  unsalted base formats; salted formats are selected explicitly by name.
- The salt is stored in the audit record so reports can reproduce the audit.

### LM

- The LM format is the first 8-byte DES block of the LAN Manager hash (16 hex characters), matching the format hashcat uses for mode 3000.
- The first block depends only on the first seven characters of a candidate, so a 16-hex LM target identifies passwords by their first seven characters; a full 32-hex LM digest is out of scope.

## Audit Modes

### Dictionary

- Requires one target hash and a readable, finite local wordlist.
- Reads UTF-8 candidates in bounded chunks and removes line endings only.
- Preserves duplicate lines and candidate order for attempt accounting.
- Blank lines become empty-string candidates and count as attempts; bytes that are not valid UTF-8 are decoded with replacement characters so one malformed line cannot abort the run.
- MD4 hashes the candidate's UTF-8 bytes (hashcat mode 900); NTLM hashes its UTF-16LE encoding. LM uppercases the candidate internally and uses only its first seven characters.

### Brute Force

- Requires an algorithm, a non-empty selected charset, minimum and maximum candidate lengths, and a candidate budget.
- Supported preset alphabets: lowercase letters, uppercase letters, digits, and printable ASCII symbols; the operator may combine presets or supply a custom alphabet. Charset names and literal text are comma-separated (for example `lower,digits` or `abc123`); comma itself is not available as a literal character.
- Default maximum candidate budget is 1,000,000; absolute maximum is 10,000,000 per run.
- Stops when a match is found, the candidate budget is reached, or the operator cancels. A run that stops at the budget with search space remaining reports `budget_exhausted`; a fully covered space reports `no_match`.

## Workers and Results

- Uses multiprocessing with a default of 4 workers and an accepted range of 1 through 8.
- Reports mode, selected algorithm, effective workers, progress, attempts, elapsed time, and terminal status.
- Displays recovered plaintext and target hash for successful matches.
- Before processing, prints a warning and requires acknowledgement that successful plaintext/hash pairs will be written to local history.
- Does not transmit hashes, candidates, or results to external services.

## History and Export

- SQLite history includes target hash, algorithm, mode, status, attempts, elapsed time, worker count, and timestamps.
- Successful matches include the recovered plaintext so the report contains the requested plaintext/hash pair.
- Supports local history listing and CSV/JSON export.
- Database and export paths are local filesystem paths.
- The default database location is `~/.password_audit/history.db`; every command that touches history accepts `--database PATH` (including `audit`, `history`, and `export`) to use another local file.
- `history [--limit N]` lists records newest first; `export PATH [--format csv|json]` writes all records with columns run_id, started_at, completed_at, target_hash, algorithm, mode, status, attempts, elapsed_ms, worker_count, and matched_plaintext.
- Before an audit starts, the CLI prints the sensitive-data retention warning and requires typing `yes`; `--yes` acknowledges non-interactively for scripted use. If the operator declines, the audit does not start.
- Storage failures after a finished audit are reported with exit code 3 and the run's terminal status is still printed; the run is not silently lost.

## Serve

- Serves the built Astro frontend and Flask API on `127.0.0.1` only.
- Prints the local URL and never accepts a host/bind-address override.
- Defaults to port 8765; `--port` may choose another available local port.

## Benchmark

- `benchmark [--seconds S] [--algorithms a,b]` measures per-algorithm
  in-process hashing throughput (candidates/second) on this machine to help
  pick realistic brute-force budgets. Results are informational and are not
  stored in history.

## Pause / Resume (dashboard)

- Dashboard jobs can pause (`POST /api/audits/{id}/pause`) and resume
  (`POST /api/audits/{id}/resume`) with exact attempt accounting; pause is
  refused for rule-expanded and hashlist runs. Resuming a dictionary run
  verifies the uploaded wordlist is unchanged.

## Plaintext Handling

- `--no-store-plaintext` (CLI) and the dashboard checkbox record the match
  metadata without the recovered plaintext (`plaintext_withheld` marker).
- `--encrypt` (CLI) encrypts stored plaintexts with a passphrase-derived key
  (scrypt + Fernet); `history --unlock` decrypts them for display, and the
  dashboard offers the same unlock. Losing the passphrase makes stored
  plaintext unrecoverable. Requires the optional `encrypt` extra.

## Exit Status

| Code | Meaning |
|---:|---|
| 0 | Match, no match, or candidate budget reached and recorded successfully |
| 1 | Invalid input, unsupported format, or inaccessible wordlist |
| 2 | Cancelled or interrupted run |
| 3 | Local history or report persistence failure |

## Boundaries

- Offline local hashes and candidate sources only.
- No login attempts, remote targets, or remote wordlists.
- Brute-force generation is limited by an explicit charset, length range, and candidate budget.
- Successful plaintext/hash pairs are retained locally as required by the project brief; operators must be warned before the run begins.
