# Web Contract: Local Hash Cracker Dashboard

The dashboard uses Astro, React, JavaScript, and Tailwind CSS. Flask serves the built static frontend and JSON API. The API and CLI call the same Python audit engine.

## Runtime and Binding

- The server binds to `127.0.0.1` and does not offer a LAN/public bind option.
- Hashes, candidate data, and results remain on the local machine; the application makes no external requests.
- State-changing routes require same-origin/CSRF protection: `GET /api/session` issues a token (returned in JSON and set as the `pa_csrf` cookie) and `POST` routes must repeat it in the `X-CSRF-Token` header; requests with a foreign `Origin`/`Referer` are rejected.
- One dashboard job may run at a time; the CLI may be used separately. A second start request receives HTTP 409.
- Start the server with `hashcrack serve [--port PORT]` (default port 8765). It serves the Astro build from `src/password_audit/static/`; build it with `npm install && npm run build` inside `frontend/` (Astro writes the output to that static folder). If the build is missing, the server starts and explains how to build the frontend instead of serving a broken page.
- The JSON API exists only on the Flask server. Opening the built page through a static server (`npm run preview`, a plain file host) shows a "Flask backend not detected" banner instead of silently failing; for frontend development, `npm run dev` and `npm run preview` proxy `/api` to `http://127.0.0.1:8765`, so start the Flask server first.

## Dashboard Form

- Accepts one target hash and displays supported algorithm candidates.
- Requires an explicit MD5, NTLM, or MD4 choice for 32-character hexadecimal hashes.
- Offers dictionary and brute-force modes.
- Offers the salted fast-hash formats (`md5($pass.$salt)` … `sha512($salt.$pass)`) in an advanced format select with a required salt field; the backend rejects salted starts without a salt and unsalted formats with one.
- Dictionary mode accepts one UTF-8 wordlist upload up to 256 MiB.
- An optional hashlist upload (same format as the CLI hashlist) audits many targets in one pass; it replaces the single hash field and its per-target results are shown in a results table with the batch ID.
- Dictionary mode offers mutation-rule presets that expand candidates inside the candidate budget.
- A run-level checkbox withholds the recovered plaintext from local history (the match is still recorded with a withheld marker).
- The Auto-fit button identifies the hash and applies brute-force settings to the form: `lower,digits` by default, `upper` for an identified LM target, minimum length 1, the largest fully covered maximum length under the 10,000,000-candidate hard limit, and a candidate budget equal to the full configured search space. It does not infer the plaintext length. For ambiguous shapes it leaves the algorithm unselected.
- Brute-force mode requires a selected charset, minimum length, maximum length, and candidate budget; the budget defaults to 1,000,000 and cannot exceed 10,000,000.
- Offers worker counts from 1 through 8, defaulting to 4.
- Requires acknowledgement of the local plaintext/hash retention warning before an audit begins.
- Does not display the temporary upload path or candidate values.

## JSON API

- `POST /api/identify` accepts a JSON hash string and returns supported algorithm candidates and ambiguity state.
- `POST /api/audits` accepts a mode-specific request. Dictionary mode uses a multipart wordlist upload; brute-force mode accepts charset, length range, and candidate budget fields.
- `GET /api/audits/{job_id}` returns state, attempts, budget, elapsed time, worker count, and terminal outcome. It returns plaintext and target hash on a successful match, consistent with the project requirements.
- `POST /api/audits/{job_id}/cancel` requests cancellation.
- `GET /api/history` returns local audit records, including successful plaintext/hash pairs; encrypted rows show `<encrypted>` until `POST /api/history/unlock` succeeds with the passphrase.
- `GET /api/export?format=csv|json` downloads the full history as an attachment.
- `POST /api/audits/{id}/pause` and `POST /api/audits/{id}/resume` checkpoint and continue single-target jobs (refused for hashlist and rule-expanded runs).
- `POST /api/history/clear` permanently deletes every local audit record (including saved plaintext/hash pairs) and returns the number of removed rows. It is destructive, CSRF-protected, and intended for the dashboard's confirmation dialog; a job that is already running still records its own outcome afterwards.
- State-changing requests require an anti-CSRF token and are available only from the loopback server.

## Progress, Results, and Storage

- Displays current mode, algorithm, effective workers, attempts, progress, elapsed time, and terminal state. Bounded runs show an ETA (attempts/second × remaining) and budget-fraction progress bar while running.
- Pause/resume buttons follow the job state machine (running → pausing → paused → resuming → running); pause requests for hashlist and rule-expanded runs are refused by the API with an explicit error, which the dashboard surfaces.
- The history card offers CSV/JSON download buttons (`GET /api/export`) and shows encrypted rows as `<encrypted>` with a passphrase unlock form until `POST /api/history/unlock` succeeds.
- Shows the recovered plaintext and target hash for successful runs after the required acknowledgement.
- Persists successful plaintext/hash pairs and run metadata in local SQLite (same default database as the CLI, `~/.password_audit/history.db`).
- Removes temporary wordlist uploads after completion, cancellation, validation failure, and application shutdown (graceful shutdown; a force-killed process cannot run its cleanup hook).

## Error Behavior

- Rejects malformed hashes, unsupported algorithms, missing files, oversized uploads, invalid charset/length combinations, and out-of-range limits before candidate processing.
- Reports match, no match, budget reached, cancellation/interruption, invalid input, and storage failure distinctly.
- Does not expose candidate values, temporary file paths, or raw exception traces to the browser.

## Out of Scope

- Public hosting, LAN access, remote accounts, external targets, authentication-service testing, and external data transmission.
