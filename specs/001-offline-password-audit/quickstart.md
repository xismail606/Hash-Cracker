# Quickstart: Hash Cracker

Setup and validation guide for the implemented tool. All scenarios use synthetic hashes and disposable local candidate data; every audit runs offline on this machine.

## Prerequisites

- Python 3.11+ (`python3` on Linux/macOS)
- Node.js and npm compatible with the Astro project (frontend build only)
- A modern web browser
- Local disk space for the SQLite database and temporary wordlist uploads
- Runs on Windows, Linux, and macOS

## Setup

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Set-Location frontend
npm install
npm run build
Set-Location ..
```

Linux / macOS (bash):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
cd frontend && npm install && npm run build && cd ..
```

Shortcut that skips activation on both platforms: `.\serve.ps1` (Windows) or `./serve.sh` (Linux/macOS) starts the dashboard on the venv's interpreter.

The Python package includes Flask and Passlib (NTLM). The Astro build writes the dashboard into `src/password_audit/static/`, which the Flask server serves. Internet access is needed only for installation; audits themselves are local.

## Identify Hash Formats

```text
python -m password_audit identify HASH
```

Verified behavior:

- Supported shapes: 16 hex → LM, 32 hex → MD5/NTLM/MD4 (ambiguous), 40 hex → SHA-1, 56 hex → SHA-224, 64 hex → SHA-256, 96 hex → SHA-384, 128 hex → SHA-512.
- 32 hexadecimal characters are reported as ambiguous between MD5, NTLM, and MD4; the audit refuses to start until one of them is selected with `--algorithm`.
- Malformed values (non-hex characters, wrong lengths) are rejected with an actionable message and no candidate processing starts.

## Dictionary Mode

Create a temporary wordlist containing synthetic values and use a hash computed from one of those values.

```text
python -m password_audit audit HASH --algorithm sha256 --mode dictionary --wordlist PATH --workers 4
```

Input rules (implemented in `candidates.py`):

- Only line terminators are stripped; other whitespace is part of the candidate.
- Duplicate entries are preserved and attempted in file order.
- Blank lines become empty-string candidates and count as attempts.
- Invalid UTF-8 bytes are decoded with replacement characters; the run continues.

Verified behavior: the tool reports match/no-match, attempts, effective worker count, and elapsed time. A successful match prints the plaintext/hash result and records it in local SQLite after the retention warning is acknowledged (`--yes` skips the interactive prompt). Verified synthetic runs: SHA-256 match (attempts = the matching entry's position), MD5 no-match (attempts = all entries), NTLM match via Passlib `nthash`.

## Salted Formats

Salted fast hashes take the known salt as a run parameter:

```text
python -m password_audit audit 3d83c8e717ff0e7ecfe187f088d69954 --algorithm md5_pass_salt --salt 343141 --mode dictionary --wordlist PATH
```

Verified behavior: hashcat salted examples (modes 10 and 1410, plaintext `hashcat`) audit to MATCH with the example salt; a wrong salt gives an honest no_match; omitting `--salt` for a salted format fails before processing; the salt is stored in the history record.

## Brute-Force Mode

Use a short synthetic test secret and a small charset/length range that includes it.

```text
python -m password_audit audit HASH --algorithm md5 --mode brute-force --charset lower,digits --min-length 1 --max-length 4 --max-candidates 10000 --workers 4
```

Input rules (implemented in `bruteforce.py`):

- `--charset` accepts preset names (`lower`, `upper`, `digits`, `symbols`) and literal characters, comma-separated; duplicates are removed and the resolved alphabet is shown before the run.
- Lengths start at 1; maximum length must be greater than or equal to minimum length.
- The budget defaults to 1,000,000 and cannot exceed the hard maximum of 10,000,000 candidates per run.

Verified behavior: candidates are generated in increasing length and lexicographic order; processing stops at a match, cancellation, or the candidate budget. Verified synthetic runs: `abc` found at attempt 1,371 with `lower,digits` (attempt counts match the deterministic generation order), and a no-match run against a smaller budget stops with status `budget_exhausted` at exactly the budget count (e.g. 1,000 candidates).

## Local Web Dashboard

```text
python -m password_audit serve [--port 8765]
```

Open the printed localhost URL. The dashboard offers hash identification, algorithm selection for ambiguous shapes, both audit modes, worker counts 1–8, live progress polling every 0.5 s, cancellation, result display, and the history table. Verified behavior:

- `GET /api/session` issues a CSRF token; `POST` routes without it return 403, and requests with a foreign `Origin` return 403.
- A second audit start while one is running returns HTTP 409.
- Wordlist uploads above 100 MiB are rejected before processing; the temporary copy is deleted.
- The server binds only to `127.0.0.1`.
- Temporary wordlist uploads are deleted after completion, cancellation, validation failure, and graceful shutdown.

## History and Reports

```text
python -m password_audit history [--limit N]
python -m password_audit export report.csv --format csv
python -m password_audit export report.json --format json
```

Verified behavior: records include algorithm, mode, target hash, status, attempts, elapsed time, worker count, and timestamp. Successful matches include the plaintext/hash pair required by the assignment. The default database is `~/.password_audit/history.db`; pass `--database PATH` to use a different local file.

## Validation Scenarios

All scenarios below were walked through with synthetic data during implementation:

- Identify MD5, SHA-256, and NTLM synthetic hashes; verify the MD5/NTLM ambiguity blocks an audit until an algorithm is chosen.
- Run dictionary mode with matching and non-matching synthetic wordlists; verify exact attempt counts.
- Run brute-force mode with a matching short secret; verify the attempt count equals the candidate's position in the deterministic generation order.
- Run brute-force mode with a budget below the search space; verify `budget_exhausted` at exactly the budget.
- Verify NTLM hashing via Passlib `nthash` (MD4 over UTF-16LE) and the built-in MD4 fallback (validated against the RFC 1320 test vectors).
- Verify the web API rejects malformed hashes, missing CSRF tokens, cross-origin mutations, and uploads above 100 MiB.
- Verify cancellation from the dashboard returns a `cancelled` state and a fresh job can start afterwards.
- Verify the database stores match pairs, attempts, elapsed time, algorithm, mode, status, and worker count; verify CSV/JSON export contains those fields.

## Completion Criteria

- Hash identification reports supported candidates and never guesses through the MD5/NTLM overlap.
- Dictionary and brute-force modes return correct synthetic match/no-match outcomes.
- Candidate and worker limits are enforced in both interfaces.
- CLI and dashboard display progress, attempts, elapsed time, and results.
- Successful plaintext/hash pairs and audit metadata are available from local SQLite history.
- All audit processing works without external network access.
