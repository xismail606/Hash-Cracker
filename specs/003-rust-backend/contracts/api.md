# Contract: Web API (parity target for the Rust server)

The Rust server (`hc-server`) MUST produce responses indistinguishable from the Flask app for every request below. Status codes, JSON field names, casing, and error message strings are part of this contract. Global constants: default port **8765**, bind **127.0.0.1** only; upload cap 256 MiB (reject at 257 MiB content); default budget 1,000,000; hard max 10,000,000; workers default 4, max 8; batch 8192; paused-job retention 7 days.

## Error shape

Uniform: `{"error": "<message>"}` with the documented status code. Exceptions: `/api/identify` validation adds `"valid": false`; 413 returns the fixed message below.

## Session & CSRF

- `GET /api/session` → 200 `{"csrf_token": "<urlsafe token>"}` and `Set-Cookie: pa_csrf=<same token>; Path=/; SameSite=Strict` (no HttpOnly, no Max-Age — browser-session cookie).
- Every **POST** except `/api/identify` requires: (1) if `Origin` or `Referer` present, it must contain `//<request host>` else 403 `{"error": "Cross-origin requests are not allowed."}`; (2) `X-CSRF-Token` header exactly equals the `pa_csrf` cookie else 403 `{"error": "Missing or invalid CSRF token."}`.
- No CORS headers, no auth, no server-side session store.

## Static serving

- `GET /` → `static/index.html` with `Cache-Control: no-cache, no-store, must-revalidate`; if missing → 503 `{"error": "The dashboard frontend has not been built yet. Run \`npm install && npm run build\` in the frontend/ directory, then restart the server."}`.
- `GET /<path>` → resolve under `static/`; a directory path appends `index.html` (clean URLs, e.g. `/changelog`); found files `Cache-Control: no-cache`; missing → 404 `{"error": "Not found."}`. `/assets/...` also resolves (Astro asset layout). No SPA rewrite.

## GET /api/formats → 200

```json
{
  "algorithms": [{"name":"md5","label":"MD5","kind":"fast"}, ...],
  "labels": {"md5":"MD5", ...},
  "salted_by_length": {"32":["md5_pass_salt","md5_salt_pass"],"40":["sha1_pass_salt","sha1_salt_pass"],"64":["sha256_pass_salt","sha256_salt_pass"],"128":["sha512_pass_salt","sha512_salt_pass"]},
  "charset_presets": [{"name":"lower","label":"lowercase a-z"},{"name":"upper","label":"uppercase A-Z"},{"name":"digits","label":"digits 0-9"},{"name":"symbols","label":"symbols"}],
  "rules_presets": [{"name":"none","label":"No rules (original words only)"},{"name":"capitalize","label":"Capitalize first letter"},{"name":"upper","label":"UPPERCASE"},{"name":"lower","label":"lowercase"},{"name":"leetspeak","label":"Leetspeak (a→4, e→3, i→1, o→0, s→5)"},{"name":"append_digits_0_99","label":"Append digits 0-99"},{"name":"append_years","label":"Append years 1990-2029"},{"name":"all","label":"All of the above combined"}],
  "max_workers": 8, "default_workers": 4,
  "hard_max_candidates": 10000000, "default_budget": 1000000
}
```

Algorithm array order (23 entries): `md5, sha256, ntlm, sha1, sha224, sha384, sha512, md4, lm, md5_pass_salt, md5_salt_pass, sha1_pass_salt, sha1_salt_pass, sha256_pass_salt, sha256_salt_pass, sha512_pass_salt, sha512_salt_pass, sha512_224, sha512_256, ripemd160, bcrypt, sha512crypt, phpass`. Kinds: `adaptive` = bcrypt/sha512crypt/phpass; `salted` = the 8 `*_pass_salt`/`*_salt_pass`; `fast` = rest. Labels: `MD5, SHA-256, NTLM, SHA-1, SHA-224, SHA-384, SHA-512, MD4, LM, md5($pass.$salt), md5($salt.$pass), sha1($pass.$salt), sha1($salt.$pass), sha256($pass.$salt), sha256($salt.$pass), sha512($pass.$salt), sha512($salt.$pass), SHA-512/224, SHA-512/256, RIPEMD-160, bcrypt, sha512crypt, phpass`.

## POST /api/identify (CSRF-exempt)

Body `{"hash": "<string>"}` (non-string/missing → 400 `{"error": "Request must include a JSON 'hash' string."}`). Trimmed probe:

- Adaptive prefix: `$2`→bcrypt, `$6$`→sha512crypt, `$P$`→phpass → 200 `{"valid": true, "submitted": <trimmed>, "normalized": <trimmed>, "compatible_algorithms": ["<one>"], "ambiguous": false}`.
- Else lowercase; non-hex chars → 400 `{"error": "<message listing up to 8 offending chars>", "valid": false}`.
- Length → candidates: 16→`["lm"]`; 32→`["md5","ntlm","md4","lm"]` (`ambiguous: true`); 40→`["sha1","ripemd160"]`; 56→`["sha224","sha512_224"]`; 64→`["sha256","sha512_256"]`; 96→`["sha384"]`; 128→`["sha512"]`; other → 400 with a message listing supported lengths.

## POST /api/audits (multipart/form-data, CSRF) → 202 `{"job_id": "<32-hex>", "state": "validating"}`

Form fields: `acknowledge_retention` (must be `"true"` else 400 `"You must acknowledge the local plaintext/hash retention warning before starting an audit."`), `mode` (`dictionary`|`brute-force` else 400 `"Mode must be 'dictionary' or 'brute-force'."`), `algorithm` (one of the 23 ids; required iff no hashlist; else 400 `"Unsupported algorithm '<x>'. Supported: <comma list>."`), `hash` (required iff no hashlist), `salt` (required iff salted algorithm: missing → `"Salted format <alg> requires a salt value."`; given on unsalted → `"Algorithm <alg> does not take a salt."`; with hashlist → `"--salt is not supported with hashlists (no per-target salt)."`), `workers` (int 1–8, default 4; `"Worker count must be an integer."` / `"Worker count must be between 1 and 8."`), `rules` (default `none`; dictionary-only else `"Rules apply to dictionary mode only."`; unknown → `"Unknown rules preset '<x>'. Known presets: all, append_digits_0_99, append_years, capitalize, leetspeak, lower, upper."`), `store_plaintext` (only exact `"false"` withholds), `max_candidates` (int; dictionary+rules non-int → `"The candidate budget must be an integer."`), brute-force: `charset` (presets and/or literal chars, comma-separated; comma cannot be literal), `min_length` ≥ 1, `max_length` ≥ min, budget ≤ 10,000,000 — any failure → 400 `"Invalid brute-force settings: charset, length range, and a candidate budget up to 10,000,000 are required."`. Files: `wordlist` (dictionary-only; missing → `"Dictionary mode requires a wordlist upload."`; >256 MiB → 413 `"The wordlist upload exceeds the 256 MiB limit."`), `hashlist` (parsed upfront: blank lines and `#` comments skipped; `algorithm:hash` prefix or bare hash; bare 32-hex rejected as ambiguous; salted/adaptive rejected; empty rejected; any failure → 400 `"Invalid hashlist: <reason>"`).

Conflict: an active job (`validating`/`running`) → 409 `{"error": "Another dashboard audit is already running. Cancel it or wait for it to finish."}` (a restored `paused` job is silently abandoned). One dashboard job at a time.

## GET /api/audits/<job_id> → 200

Unknown → 404 `{"error": "Unknown job ID."}`.

```json
{"job_id":"...","state":"running","mode":"dictionary","algorithm":"md5","workers":4,"attempts":12345,"elapsed_ms":6789,"budget":1000000}
```

`budget` is `null` for plain dictionary without rules. Optional keys present only when set: `"error"`, `"result"`. No progress/ETA field exists — clients derive rate from attempts.

`result` (single): `{"status","attempts","elapsed_ms","workers","matched_plaintext","target_hash","plaintext_withheld"}` (plaintext null when withheld).
`result` (hashlist): adds `"matched_plaintext": null, "target_hash": null, "targets": [{"id","algorithm","hash","status","matched_plaintext","match_at_attempt","plaintext_withheld"}], "plaintext_withheld", "batch_id"` (batch_id = first 8 hex chars, present only after a successful history write). Per-target status: `match` | `no_match` | `paused`.
Cancelled-from-paused: `result = {"status":"cancelled","attempts","elapsed_ms"}`.

States: `validating, running, paused, match, no_match, cancelled, budget_exhausted, interrupted, storage_error`. `interrupted` ⇒ `error: "The audit failed unexpectedly; no result was recorded."`. `storage_error` (single-target match persist failure) ⇒ `error: "A match was found but it could not be recorded in local history (storage error); nothing is displayed."`; non-match persist failure keeps engine status with `error: "The run finished but could not be recorded in local history."` (hashlist: `"The hashlist run finished but could not be recorded in local history."`).

## Job control

- `POST /api/audits/<id>/pause` — only while `running` else 400 `{"error": "Only a running job can be paused."}` → 202 `{"job_id","state":"running","pausing":true}`. Engine stops submitting, drains, tears the pool down; state → `paused`; wordlist/hashlist moved into `<db dir>/paused_jobs/` and `<job_id>.json` written (0600/0700 on POSIX).
- `POST /api/audits/<id>/resume` — only while `paused` else 400 `{"error": "Only a paused job can be resumed."}`. Rebuild source from `run_params`: wordlist missing → 400 `"The uploaded wordlist is gone; re-start the audit."`; byte-size mismatch → 400 `"The wordlist changed since the pause; resume is refused."`; bad stored brute-force params → 400 `"Stored brute-force params are invalid."`; bad stored rule budget → 400 `"Stored rule-expansion budget is invalid."`. Success → 200 `{"job_id","state":"running","resumed":true}`, sidecar deleted.
- `POST /api/audits/<id>/cancel` — sets cancel; → 200 `{"job_id","state":"<current>","cancelling":true}`. Cancelling a threadless (paused/restored) job finalizes synchronously → `{"job_id","state":"cancelled"}` (no `cancelling` key) and deletes sidecar + uploads.
- Startup: restore newest sidecar as a paused job; delete records older than 7 days (keep newest); starting a new audit abandons a restored paused job.

## GET /api/history → 200

```json
{"records":[{"run_id":1,"started_at":"2026-11-18T12:34:56.789Z","completed_at":"...","target_hash":"...","algorithm":"md5","mode":"dictionary","status":"match","attempts":123,"elapsed_ms":456,"worker_count":4,"matched_plaintext":"secret","salt":null,"batch_id":null,"plaintext_withheld":false,"backend":"rust"}],"encrypted_count":0,"sensitive_note":"Successful matches include the recovered plaintext/hash pair stored locally."}
```

Limit 100, newest first (`run_id DESC`). `matched_plaintext` starting `enc1:` counts toward `encrypted_count`; decrypted in place when unlocked; `"<encrypted>"` when locked; `"<decryption failed>"` on row-level failure. `backend` is the new attribution field (see storage contract).

## POST /api/history/unlock (CSRF) — body `{"passphrase": "..."}`

Missing/empty → 400 `{"error": "A passphrase is required."}`; wrong passphrase/crypto error → 403 `{"error": "<message>"}` (e.g. `"Wrong passphrase."`); success → 200 `{"unlocked":true}` (key cached in memory; restart clears it; no lock endpoint).

## GET /api/export?format=csv|json (default csv)

`csv` → `text/csv`, `Content-Disposition: attachment; filename=audit-history.csv`, header exactly: `run_id,started_at,completed_at,target_hash,algorithm,mode,status,attempts,elapsed_ms,worker_count,matched_plaintext,salt,batch_id,plaintext_withheld,backend,target_count` (see storage contract for the attribution column position). `json` → `{"runs":[<history-record shapes>],"batches":[{"batch_id","mode","status","attempts","elapsed_ms","worker_count","started_at","target_count"}]}` with `Content-Disposition: attachment; filename=audit-history.json`, `indent=2`. Export never decrypts.

## POST /api/history/clear (CSRF) → 200 `{"deleted": <n>}`

Deletes all `audit_runs` + `audit_batches` rows, returns combined count; leaves encryption keys and paused-job files untouched. DB error → 500.
