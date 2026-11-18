# Data Model: Rust Backend (Phase 11)

Phase 1 output. The second backend introduces **no new persistent entity classes** — it joins the existing store and sidecar formats and adds one column. Exact DDL/JSON live in `contracts/storage.md`; this file is the map.

## Entities

### Backend choice (per install / per launch)

Not persisted as rows; observable through (a) which binaries exist and (b) the `backend` attribution on records.

- Install-time choice: `python` | `rust` | `both`. Persisted implicitly by what setup installed (venv + package; `rust/target/release` binary copied next to the venv entry points).
- Launch-time choice: `python` | `rust`. Given per serve invocation (prompt or flag); never persisted.

### AuditRun (existing, +1 column)

Shared table `audit_runs` (one row per target; hashlist targets carry `batch_id`).

| Field | Type | Notes |
|---|---|---|
| run_id | INTEGER PK AUTOINCREMENT | shared sequence across backends |
| started_at / completed_at | TEXT | `YYYY-MM-DDTHH:MM:SS.mmmZ` UTC ms |
| target_hash | TEXT NOT NULL | normalized (lowercase hex, or adaptive string) |
| algorithm | TEXT NOT NULL | one of the 23 pinned ids |
| mode | TEXT NOT NULL | `dictionary` \| `brute-force` |
| status | TEXT NOT NULL | `match` \| `no_match` \| `cancelled` \| `budget_exhausted` \| `interrupted` \| `invalid_input` \| `storage_error` \| `paused` |
| attempts / elapsed_ms / worker_count | INTEGER NOT NULL | attempt math pinned in contracts |
| matched_plaintext | TEXT nullable | plaintext \| `enc1:` Fernet token \| NULL when withheld |
| salt | TEXT nullable | operator salt for salted formats |
| batch_id | TEXT nullable | hashlist runs only (8-hex prefix of uuid4) |
| plaintext_withheld | INTEGER (0/1) | boolean flag, not a sentinel string |
| **backend** | **TEXT nullable → always written going forward** | **new**: `python` \| `rust`; NULL = pre-Phase-11 row (displayed as python) |

### AuditBatch (existing)

`audit_batches` — hashlist run summaries (`batch_id` PK, mode/status/attempts/elapsed_ms/worker_count/started_at/target_count). Unchanged.

### HistoryMeta (existing)

`history_meta` key/value: `enc_salt` (16-byte hex), `enc_verify` (Fernet token of `b"ok"`). Both backends use the same rows — first backend to enable encryption creates them; the other must consume them as-is.

### PausedJob sidecar (existing format, new writer)

`<db dir>/paused_jobs/<job_id>.json` + moved upload files. JSON fields (both backends write/read the same): `job_id, target_hash, algorithm, mode, workers, budget, salt, run_params, resume_state, targets, plaintext_withheld, started_at, attempts, elapsed_ms, temp_path, temp_hashlist`. `resume_state` = `{attempts_base, skip_source[, matched_plaintext{target_id:text}, matched_attempt{target_id:int}]}`. Retention: newest kept, older than 7 days deleted. Cross-backend resume (pause in one backend, resume in the other) is **in scope for the shared file format** but only guaranteed when `run_params` are mode-compatible (dictionary: the moved wordlist path; brute-force: charset/lengths/budget) — the server restores only the newest record regardless of which backend wrote it.

## Relationships

- One `audit_batches` row ↔ N `audit_runs` rows via `batch_id`.
- `history_meta` is global per database (not per backend).
- Paused jobs are per job id, stored next to the shared DB — visible to whichever server restarts next.

## Validation rules (parity-critical)

- Attempt accounting: candidate-level count; match ⇒ `offset + match_index + 1`; batch completion ⇒ `max(attempts, offset + batch_size)`; budget truncation before submission; `budget_exhausted` only when `budget_is_limit` (space exists beyond budget).
- Identification: adaptive prefix first (`$2`, `$6$`, `$P$`), else strict lowercase hex + length group; 32-hex always ambiguous (md5, ntlm, md4, lm); salted formats never appear in shape identification.
- Uploads: wordlist required in dictionary mode; ≤ 256 MiB; hashlist parse rules (comments, blanks, `algorithm:hash` prefix, bare 32-hex rejected, no salt, salted/adaptive rejected per line).
- Workers 1–8 (default 4); budget 1–10,000,000 (default 1,000,000; plain dictionary without rules = unbounded/NULL).

## State transitions

Dashboard job: `validating → running → match | no_match | budget_exhausted | cancelled | paused | interrupted | storage_error`; `paused → running` (resume) or `paused → cancelled`. Engine-level `paused` is an in-memory outcome, persisted only via the sidecar. Identical in both backends.
