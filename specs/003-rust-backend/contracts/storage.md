# Contract: Shared storage (SQLite, sidecar, encryption)

Both backends read and write the same artifacts. Byte-level compatibility is required: either backend must handle a database, sidecar file, or ciphertext produced by the other.

## Database

Path: `~/.hash_cracker/history.db` (dir `~/.hash_cracker/`; legacy `~/.password_audit/` renamed on first use when the branded dir is absent). `--database`/`db_path` overrides everywhere.

DDL (exact, both backends run the same `executescript` on connect):

```sql
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    target_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    elapsed_ms INTEGER NOT NULL,
    worker_count INTEGER NOT NULL,
    matched_plaintext TEXT,
    salt TEXT,
    batch_id TEXT,
    plaintext_withheld INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_runs_started ON audit_runs (started_at);
CREATE TABLE IF NOT EXISTS history_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_batches (
    batch_id TEXT PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL,
    attempts INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL,
    worker_count INTEGER NOT NULL, started_at TEXT NOT NULL,
    target_count INTEGER NOT NULL
);
```

**Migrations**: additive only — read `PRAGMA table_info(audit_runs)`, `ALTER TABLE audit_runs ADD COLUMN backend TEXT` when missing. Both backends implement the same mechanism; the Rust backend must also tolerate a database migrated by Python and vice versa (including running either migration first).

**Attribution (`backend` column)**: `record_run` gains `backend` (`"python"` | `"rust"`); NULL exists only on pre-Phase-11 rows and displays as python. `/api/history` records, JSON export, and CSV export include it. **CSV column order** (Python `EXPORT_COLUMNS` updated accordingly): `run_id,started_at,completed_at,target_hash,algorithm,mode,status,attempts,elapsed_ms,worker_count,matched_plaintext,salt,batch_id,plaintext_withheld,backend,target_count` — batch rows leave run-only columns empty, run rows leave `target_count` empty. JSON export: each run record gains `"backend"`; batch rows unchanged.

Timestamps: `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC, millisecond precision) — identical formatting code path in both backends.

Concurrent access: default SQLite locking (no WAL change); a locked database surfaces the existing message style ("Cannot open local history database at {path}: ..."), never silent data loss.

## Plaintext encryption (byte-compatible)

- KDF: scrypt(passphrase UTF-8, salt = 16 random bytes, **N=16384, r=8, p=1, dklen=32**) → 32-byte key.
- Cipher: **Fernet** (AES-128-CBC + HMAC-SHA256, version byte `\x80`, urlsafe-base64 token) keyed with `urlsafe_b64encode(key)`.
- `history_meta` rows: `enc_salt` = 16-byte hex salt; `enc_verify` = Fernet token of plaintext `ok` (created on first unlock; decrypting it verifies the passphrase — failure ⇒ `HistoryError("Wrong passphrase.")` ⇒ CLI exit 3 / API 403).
- Ciphertext: `audit_runs.matched_plaintext` = `"enc1:"` + Fernet token. `is_encrypted_value` = `startswith("enc1:")`. Export never decrypts.
- Dashboard runs never encrypt at write time (withholding is via `plaintext_withheld`/NULL); only CLI `--encrypt` writes ciphertext. Both backends' servers unlock rows via their `/api/history/unlock`.

## Paused-job sidecar

`<db dir>/paused_jobs/<job_id>.json`, chmod 0600 (0700 dir) on POSIX:

```json
{"job_id":"...","target_hash":"...","algorithm":"md5","mode":"dictionary","workers":4,
 "budget":1000000,"salt":null,"run_params":{...},"resume_state":{"attempts_base":123,"skip_source":456},
 "targets":null,"plaintext_withheld":false,"started_at":"...","attempts":123,"elapsed_ms":456,
 "temp_path":"<moved wordlist path>","temp_hashlist":null}
```

- `run_params` (dictionary): the moved wordlist path + captured byte size + rules name; (brute-force): charset string, min/max length, budget.
- `resume_state`: `attempts_base`, `skip_source` (candidate ordinal to skip); hashlist adds `matched_plaintext` and `matched_attempt` maps keyed by target id.
- Uploads move from the staging dir into `paused_jobs/` on pause; deleted on cancel; resume requires existence + exact byte-size match.
- Retention: at startup, delete records older than 7 days except the newest; restore the newest as a paused job (threadless).
- The Rust backend writes and reads this exact JSON (same field names, same shapes) so a pause in either backend is resumable/cancellable by the other.
