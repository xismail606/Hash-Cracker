"""Local SQLite audit history: schema, run records, listing, and exports.

The database stays on the local machine. The default location is
``~/.password_audit/history.db``; callers may pass another local path.
Successful matches persist the recovered plaintext together with the target
hash because the project brief requires the plaintext/hash pair for
credential-policy reporting; operators are warned before a run begins.
"""

from __future__ import annotations

import csv
import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".password_audit" / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at        TEXT NOT NULL,
    completed_at      TEXT,
    target_hash       TEXT NOT NULL,
    algorithm         TEXT NOT NULL,
    mode              TEXT NOT NULL,
    status            TEXT NOT NULL,
    attempts          INTEGER NOT NULL,
    elapsed_ms        INTEGER NOT NULL,
    worker_count      INTEGER NOT NULL,
    matched_plaintext TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_runs_started ON audit_runs (started_at);
CREATE TABLE IF NOT EXISTS history_meta (
    key  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_batches (
    batch_id     TEXT PRIMARY KEY,
    mode         TEXT NOT NULL,
    status       TEXT NOT NULL,
    attempts     INTEGER NOT NULL,
    elapsed_ms   INTEGER NOT NULL,
    worker_count INTEGER NOT NULL,
    started_at   TEXT NOT NULL,
    target_count INTEGER NOT NULL
);
"""

# Columns added after v1; applied additively on connect for existing databases.
MIGRATION_COLUMNS = (
    ("salt", "TEXT"),
    ("batch_id", "TEXT"),
    ("plaintext_withheld", "INTEGER"),
)

EXPORT_COLUMNS = (
    "run_id",
    "started_at",
    "completed_at",
    "target_hash",
    "algorithm",
    "mode",
    "status",
    "attempts",
    "elapsed_ms",
    "worker_count",
    "matched_plaintext",
    "salt",
    "batch_id",
    "plaintext_withheld",
)


class HistoryError(RuntimeError):
    """Raised when the local history database cannot be used."""


@dataclass
class AuditRecord:
    """One persisted audit run."""

    run_id: int
    started_at: str
    completed_at: str | None
    target_hash: str
    algorithm: str
    mode: str
    status: str
    attempts: int
    elapsed_ms: int
    worker_count: int
    matched_plaintext: str | None
    salt: str | None = None
    batch_id: str | None = None
    plaintext_withheld: bool = False

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "target_hash": self.target_hash,
            "algorithm": self.algorithm,
            "mode": self.mode,
            "status": self.status,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
            "worker_count": self.worker_count,
            "matched_plaintext": self.matched_plaintext,
            "salt": self.salt,
            "batch_id": self.batch_id,
            "plaintext_withheld": bool(self.plaintext_withheld),
        }


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def connect(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (and initialize) the local history database."""
    path = Path(db_path).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.executescript(SCHEMA)
        # Apply additive post-v1 columns to databases created before them.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_runs)")}
        for column, column_type in MIGRATION_COLUMNS:
            if column not in existing:
                conn.execute(f"ALTER TABLE audit_runs ADD COLUMN {column} {column_type}")
        conn.commit()
        return conn
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot open local history database at {path}: {exc}") from exc
    except OSError as exc:
        raise HistoryError(f"Cannot create local history directory for {path}: {exc}") from exc


def record_run(
    conn: sqlite3.Connection,
    *,
    target_hash: str,
    algorithm: str,
    mode: str,
    status: str,
    attempts: int,
    elapsed_ms: int,
    worker_count: int,
    started_at: str,
    completed_at: str | None = None,
    matched_plaintext: str | None = None,
    salt: str | None = None,
    batch_id: str | None = None,
    plaintext_withheld: bool = False,
    plaintext_key: bytes | None = None,
) -> int:
    """Persist one audit run; return the new run ID.

    A successful match stores the plaintext/hash pair; non-matching runs
    store run metadata without a plaintext value. Salted formats store the
    salt so reports can reproduce the audit.
    """
    if completed_at is None:
        completed_at = utc_now()
    if plaintext_key is not None and matched_plaintext is not None:
        matched_plaintext = encrypt_stored(conn, plaintext_key, matched_plaintext)
    try:
        cursor = conn.execute(
            """
            INSERT INTO audit_runs (
                started_at, completed_at, target_hash, algorithm, mode,
                status, attempts, elapsed_ms, worker_count, matched_plaintext,
                salt, batch_id, plaintext_withheld
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                started_at,
                completed_at,
                target_hash,
                algorithm,
                mode,
                status,
                attempts,
                elapsed_ms,
                worker_count,
                matched_plaintext,
                salt,
                batch_id,
                1 if plaintext_withheld else 0,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot write the audit record to local history: {exc}") from exc


def list_runs(conn: sqlite3.Connection, limit: int | None = None) -> list[AuditRecord]:
    """Return local audit records, newest first."""
    query = (
        "SELECT run_id, started_at, completed_at, target_hash, algorithm, mode, "
        "status, attempts, elapsed_ms, worker_count, matched_plaintext, salt, batch_id, plaintext_withheld "
        "FROM audit_runs ORDER BY run_id DESC"
    )
    params: tuple = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)
    try:
        rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot read local audit history: {exc}") from exc
    return [AuditRecord(*row) for row in rows]


def clear_runs(conn: sqlite3.Connection) -> int:
    """Delete every local audit record; return the number of removed rows.

    This permanently erases successful plaintext/hash pairs, hashlist summaries,
    and run metadata. The caller confirms the destructive action first.
    """
    try:
        run_cursor = conn.execute("DELETE FROM audit_runs")
        batch_cursor = conn.execute("DELETE FROM audit_batches")
        conn.commit()
        return int(run_cursor.rowcount or 0) + int(batch_cursor.rowcount or 0)
    except sqlite3.Error as exc:
        conn.rollback()
        raise HistoryError(f"Cannot clear local audit history: {exc}") from exc


def record_batch(
    conn: sqlite3.Connection,
    *,
    batch_id: str,
    mode: str,
    status: str,
    attempts: int,
    elapsed_ms: int,
    worker_count: int,
    started_at: str,
    target_count: int,
) -> None:
    """Persist one hashlist run summary; per-target rows live in audit_runs."""
    try:
        conn.execute(
            """
            INSERT INTO audit_batches (
                batch_id, mode, status, attempts, elapsed_ms,
                worker_count, started_at, target_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (batch_id, mode, status, attempts, elapsed_ms, worker_count,
             started_at, target_count),
        )
        conn.commit()
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot write the batch record to local history: {exc}") from exc


def export_batches(conn: sqlite3.Connection) -> list[dict]:
    """Return hashlist run summaries for report export."""
    try:
        rows = conn.execute(
            "SELECT batch_id, mode, status, attempts, elapsed_ms, worker_count, "
            "started_at, target_count FROM audit_batches ORDER BY started_at DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot read batch records: {exc}") from exc
    keys = ("batch_id", "mode", "status", "attempts", "elapsed_ms", "worker_count",
            "started_at", "target_count")
    return [dict(zip(keys, row)) for row in rows]


ENCRYPT_PREFIX = "enc1:"
_ENCRYPT_VERIFY_KEY = "enc_verify"
_ENCRYPT_SALT_KEY = "enc_salt"


def _fernet(key_bytes: bytes):
    """Return a Fernet instance; raises HistoryError if cryptography is missing."""
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise HistoryError(
            "Plaintext encryption requires the optional 'cryptography' package. "
            "Install it with: python -m pip install password-audit[encrypt]"
        ) from exc
    import base64

    return Fernet(base64.urlsafe_b64encode(key_bytes))


def ensure_encryption_salt(conn: sqlite3.Connection) -> bytes:
    """Return (creating if needed) the per-database scrypt salt."""
    row = conn.execute(
        "SELECT value FROM history_meta WHERE key = ?", (_ENCRYPT_SALT_KEY,)
    ).fetchone()
    if row:
        return bytes.fromhex(row[0])
    salt = sqlite3.Binary(secrets.token_bytes(16))
    conn.execute(
        "INSERT OR REPLACE INTO history_meta (key, value) VALUES (?, ?)",
        (_ENCRYPT_SALT_KEY, bytes(salt).hex()),
    )
    conn.commit()
    return bytes(salt)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from a passphrase with scrypt."""
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )


def init_encryption(conn: sqlite3.Connection, passphrase: str) -> bytes:
    """Create or verify the encryption setup; return the derived key.

    The first call stores a random salt plus an encrypted verification token;
    later calls verify the passphrase against that token.
    """
    salt = ensure_encryption_salt(conn)
    key = derive_key(passphrase, salt)
    fernet = _fernet(key)
    row = conn.execute(
        "SELECT value FROM history_meta WHERE key = ?", (_ENCRYPT_VERIFY_KEY,)
    ).fetchone()
    if row is None:
        token = fernet.encrypt(b"ok").decode()
        conn.execute(
            "INSERT OR REPLACE INTO history_meta (key, value) VALUES (?, ?)",
            (_ENCRYPT_VERIFY_KEY, token),
        )
        conn.commit()
    else:
        try:
            if fernet.decrypt(row[0].encode()) != b"ok":
                raise HistoryError("Wrong passphrase.")
        except HistoryError:
            raise
        except Exception as exc:
            raise HistoryError("Wrong passphrase.") from exc
    return key


def encrypt_stored(conn: sqlite3.Connection, key: bytes, plaintext: str) -> str:
    """Encrypt a plaintext for storage; returns a prefixed ciphertext."""
    return ENCRYPT_PREFIX + _fernet(key).encrypt(plaintext.encode("utf-8")).decode()


def decrypt_stored(key: bytes, stored: str) -> str:
    """Decrypt a stored ciphertext; returns the plaintext."""
    return _fernet(key).decrypt(stored[len(ENCRYPT_PREFIX):].encode()).decode("utf-8")


def is_encrypted_value(value: str | None) -> bool:
    return bool(value) and value.startswith(ENCRYPT_PREFIX)


def export_rows(conn: sqlite3.Connection) -> list[dict]:
    """Return all records as dictionaries for report export."""
    return [record.as_dict() for record in list_runs(conn)]


def export_csv(conn: sqlite3.Connection, output_path: str | Path) -> Path:
    """Write the full audit history to a local CSV file; return the path."""
    rows = export_rows(conn)
    target = Path(output_path).expanduser()
    try:
        with open(target, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=EXPORT_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
    except OSError as exc:
        raise HistoryError(f"Cannot write the CSV report to {target}: {exc}") from exc
    return target


def export_json(conn: sqlite3.Connection, output_path: str | Path) -> Path:
    """Write the full audit history to a local JSON file; return the path."""
    rows = export_rows(conn)
    target = Path(output_path).expanduser()
    try:
        with open(target, "w", encoding="utf-8", newline="") as handle:
            json.dump(rows, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        raise HistoryError(f"Cannot write the JSON report to {target}: {exc}") from exc
    return target
