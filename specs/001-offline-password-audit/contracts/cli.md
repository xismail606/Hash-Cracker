# CLI Contract: Hash Cracker

The commands below are the planned v1 interface; final option spelling is confirmed during implementation.

## Commands

```text
python -m password_audit identify HASH
python -m password_audit audit HASH --algorithm NAME --mode dictionary --wordlist PATH [--workers N]
python -m password_audit audit HASH --algorithm NAME --mode brute-force --charset PRESET_OR_TEXT --min-length N --max-length N [--max-candidates N] [--workers N]
python -m password_audit history [--database PATH]
python -m password_audit export PATH [--format csv|json]
python -m password_audit serve [--port PORT]
```

## Identify

- Accept one hash string.
- Recognize the supported format shapes: MD5 (32 hex), NTLM (32 hex), and SHA-256 (64 hex).
- Report MD5/NTLM as ambiguous for a 32-character hexadecimal input and require the operator to choose before auditing.
- Reject malformed or unsupported shapes with a clear message.
- Do not start candidate processing.

## Audit Modes

### Dictionary

- Requires one target hash and a readable, finite local wordlist.
- Reads UTF-8 candidates in bounded chunks and removes line endings only.
- Preserves duplicate lines and candidate order for attempt accounting.

### Brute Force

- Requires an algorithm, a non-empty selected charset, minimum and maximum candidate lengths, and a candidate budget.
- Supported preset alphabets: lowercase letters, uppercase letters, digits, and printable ASCII symbols; the operator may combine presets or supply a custom alphabet.
- Default maximum candidate budget is 1,000,000; absolute maximum is 10,000,000 per run.
- Stops when a match is found, the candidate budget is reached, or the operator cancels.

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

## Serve

- Serves the built Astro frontend and Flask API on `127.0.0.1` only.
- Prints the local URL and never accepts a host/bind-address override.
- Defaults to port 8765; `--port` may choose another available local port.

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
