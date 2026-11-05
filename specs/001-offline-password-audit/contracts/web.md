# Web Contract: Local Hash Cracker Dashboard

The dashboard uses Astro, React, JavaScript, and Tailwind CSS. Flask serves the built static frontend and JSON API. The API and CLI call the same Python audit engine.

## Runtime and Binding

- The server binds to `127.0.0.1` and does not offer a LAN/public bind option.
- Hashes, candidate data, and results remain on the local machine; the application makes no external requests.
- State-changing routes require same-origin/CSRF protection.
- One dashboard job may run at a time; the CLI may be used separately.

## Dashboard Form

- Accepts one target hash and displays supported algorithm candidates.
- Requires an explicit MD5 or NTLM choice for 32-character hexadecimal hashes.
- Offers dictionary and brute-force modes.
- Dictionary mode accepts one UTF-8 wordlist upload up to 100 MiB.
- Brute-force mode requires a selected charset, minimum length, maximum length, and candidate budget; the budget defaults to 1,000,000 and cannot exceed 10,000,000.
- Offers worker counts from 1 through 8, defaulting to 4.
- Requires acknowledgement of the local plaintext/hash retention warning before an audit begins.
- Does not display the temporary upload path or candidate values.

## JSON API

- `POST /api/identify` accepts a JSON hash string and returns supported algorithm candidates and ambiguity state.
- `POST /api/audits` accepts a mode-specific request. Dictionary mode uses a multipart wordlist upload; brute-force mode accepts charset, length range, and candidate budget fields.
- `GET /api/audits/{job_id}` returns state, attempts, budget, elapsed time, worker count, and terminal outcome. It returns plaintext and target hash on a successful match, consistent with the project requirements.
- `POST /api/audits/{job_id}/cancel` requests cancellation.
- `GET /api/history` returns local audit records, including successful plaintext/hash pairs.
- State-changing requests require an anti-CSRF token and are available only from the loopback server.

## Progress, Results, and Storage

- Displays current mode, algorithm, effective workers, attempts, progress, elapsed time, and terminal state.
- Shows the recovered plaintext and target hash for successful runs after the required acknowledgement.
- Persists successful plaintext/hash pairs and run metadata in local SQLite.
- Removes temporary wordlist uploads after completion, cancellation, validation failure, and application shutdown.

## Error Behavior

- Rejects malformed hashes, unsupported algorithms, missing files, oversized uploads, invalid charset/length combinations, and out-of-range limits before candidate processing.
- Reports match, no match, budget reached, cancellation/interruption, invalid input, and storage failure distinctly.
- Does not expose candidate values, temporary file paths, or raw exception traces to the browser.

## Out of Scope

- Public hosting, LAN access, remote accounts, external targets, authentication-service testing, and external data transmission.
