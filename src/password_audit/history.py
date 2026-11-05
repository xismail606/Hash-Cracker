"""Local SQLite audit history: schema, run records, listing, and exports.

The database stays on the local machine. The default location is
``~/.password_audit/history.db``; callers may pass another local path.
Successful matches persist the recovered plaintext together with the target
hash because the project brief requires the plaintext/hash pair for
credential-policy reporting; operators are warned before a run begins.
"""

from __future__ import annotations

import csv
import json
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
"""

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
) -> int:
    """Persist one audit run; return the new run ID.

    A successful match stores the plaintext/hash pair; non-matching runs
    store run metadata without a plaintext value.
    """
    if completed_at is None:
        completed_at = utc_now()
    try:
        cursor = conn.execute(
            """
            INSERT INTO audit_runs (
                started_at, completed_at, target_hash, algorithm, mode,
                status, attempts, elapsed_ms, worker_count, matched_plaintext
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        "status, attempts, elapsed_ms, worker_count, matched_plaintext "
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

    This permanently erases successful plaintext/hash pairs and run metadata.
    The caller is responsible for confirming the destructive action first.
    """
    try:
        cursor = conn.execute("DELETE FROM audit_runs")
        conn.commit()
        return int(cursor.rowcount or 0)
    except sqlite3.Error as exc:
        raise HistoryError(f"Cannot clear local audit history: {exc}") from exc


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
