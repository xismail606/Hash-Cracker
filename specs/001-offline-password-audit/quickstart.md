# Quickstart: Hash Cracker

This is the planned setup and validation guide for the implementation. It uses synthetic hashes and disposable local candidate data only. The application code does not exist yet, so these commands are not runnable until the implementation tasks are complete.

## Prerequisites

- Python 3.11+
- Node.js and npm compatible with the Astro project
- A modern web browser
- Local disk space for the SQLite database and temporary wordlist uploads

## Planned Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Set-Location frontend
npm install
npm run build
Set-Location ..
```

The Python package will include Flask and Passlib for NTLM support. Frontend dependencies will be installed by npm. Internet access may be needed for installation; audits themselves are local.

## Identify Hash Formats

```text
python -m password_audit identify HASH
```

Expected behavior:

- 64 hexadecimal characters are reported as compatible with SHA-256.
- 32 hexadecimal characters are reported as ambiguous between MD5 and NTLM; select the algorithm before auditing.
- Malformed values are rejected without starting candidate processing.

## Dictionary Mode

Create a temporary wordlist containing synthetic values and use a synthetic hash created from one of those values.

```text
python -m password_audit audit HASH --algorithm sha256 --mode dictionary --wordlist PATH --workers 4
```

Expected behavior: the tool reports match/no-match, attempts, effective worker count, and elapsed time. A successful match prints the plaintext/hash result and records it in local SQLite after the retention warning is acknowledged.

## Brute-Force Mode

Use a short synthetic test secret and a small charset/length range that includes it.

```text
python -m password_audit audit HASH --algorithm md5 --mode brute-force --charset lower,digits --min-length 1 --max-length 4 --max-candidates 10000 --workers 4
```

Expected behavior: candidates are generated from the selected alphabet and length range; processing stops at a match, cancellation, or the candidate budget. The attempt count never exceeds the configured budget.

## Local Web Dashboard

```text
python -m password_audit serve
```

Open the printed localhost URL. Submit the same synthetic cases in dictionary and brute-force modes. Expected behavior: the page shows live progress and results, the server binds only to `127.0.0.1`, and temporary wordlist uploads are deleted after the job ends or is cancelled. Successful plaintext/hash pairs are recorded after the warning is acknowledged.

## History and Reports

```text
python -m password_audit history
python -m password_audit export report.csv --format csv
```

Expected behavior: records include algorithm, mode, target hash, status, attempts, elapsed time, worker count, and timestamp. Successful matches include the plaintext/hash pair required by the assignment.

## Validation Scenarios

- Identify MD5, SHA-256, and NTLM synthetic hashes; verify the MD5/NTLM ambiguity.
- Run dictionary mode with a matching and non-matching synthetic wordlist.
- Run brute-force mode with a matching short secret and a candidate budget that stops before an oversized search.
- Compare single-worker and multi-worker runs while checking the effective worker count and attempt totals.
- Verify cancellation and budget-exhausted status reporting.
- Verify the website rejects malformed input, invalid settings, cross-origin mutations, and uploads above 100 MiB.
- Verify the database stores match pairs, attempts, elapsed time, algorithm, mode, and status.
- Verify temporary web uploads are removed on completion, failure, cancellation, and shutdown.

## Completion Criteria

- Hash identification reports supported candidates and never guesses through the MD5/NTLM overlap.
- Dictionary and brute-force modes return correct synthetic match/no-match outcomes.
- Candidate and worker limits are enforced in both interfaces.
- CLI and dashboard display progress, attempts, elapsed time, and results.
- Successful plaintext/hash pairs and audit metadata are available from local SQLite history.
- All audit processing works without external network access.
