//! Shared SQLite audit history: schema, additive migrations, run/batch
//! records, exports — byte-compatible with `src/hash_cracker/history.py`
//! (see specs/003-rust-backend/contracts/storage.md).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

/// Default data directory: `~/.hash_cracker`.
pub fn default_data_dir() -> PathBuf {
    dirs_home().join(".hash_cracker")
}

/// Default database path: `~/.hash_cracker/history.db`.
pub fn default_db_path() -> PathBuf {
    default_data_dir().join("history.db")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Error mirroring Python's `HistoryError` (messages are contract-pinned).
#[derive(Debug)]
pub struct HistoryError(pub String);

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HistoryError {}

/// ISO-8601 UTC timestamp with millisecond precision, matching Python's
/// `utc_now()`: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn utc_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    now.format(&format).expect("timestamp format is infallible")
}

/// A new audit run row (one row per target; hashlist targets share `batch_id`).
#[derive(Debug, Clone, Default)]
pub struct NewRun {
    pub target_hash: String,
    pub algorithm: String,
    pub mode: String,
    pub status: String,
    pub attempts: i64,
    pub elapsed_ms: i64,
    pub worker_count: i64,
    pub matched_plaintext: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub salt: Option<String>,
    pub batch_id: Option<String>,
    pub plaintext_withheld: bool,
    /// Which backend produced the run: "python" | "rust".
    pub backend: Option<String>,
}

/// A hashlist run summary row.
#[derive(Debug, Clone, Default)]
pub struct NewBatch {
    pub batch_id: String,
    pub mode: String,
    pub status: String,
    pub attempts: i64,
    pub elapsed_ms: i64,
    pub worker_count: i64,
    pub started_at: Option<String>,
    pub target_count: i64,
}

/// One history record as returned by `list_runs` (the API/export shape).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub run_id: i64,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub target_hash: String,
    pub algorithm: String,
    pub mode: String,
    pub status: String,
    pub attempts: i64,
    pub elapsed_ms: i64,
    pub worker_count: i64,
    pub matched_plaintext: Option<String>,
    pub salt: Option<String>,
    pub batch_id: Option<String>,
    pub plaintext_withheld: bool,
    pub backend: Option<String>,
}

/// One batch summary record (JSON export).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchRecord {
    pub batch_id: String,
    pub mode: String,
    pub status: String,
    pub attempts: i64,
    pub elapsed_ms: i64,
    pub worker_count: i64,
    pub started_at: String,
    pub target_count: i64,
}

/// CSV export column order — pinned by `EXPORT_COLUMNS` in Python
/// (with the Phase 11 `backend` attribution column inserted).
pub const EXPORT_COLUMNS: &[&str] = &[
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
    "backend",
    "target_count",
];

const SCHEMA: &str = "
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
CREATE TABLE IF NOT EXISTS history_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_batches (
    batch_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    elapsed_ms INTEGER NOT NULL,
    worker_count INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    target_count INTEGER NOT NULL
);
";

/// Additive migrations applied on every connect — the full Python
/// `MIGRATION_COLUMNS` list plus the Phase 11 `backend` attribution column,
/// so either backend migrates a database created by the other.
const MIGRATION_COLUMNS: &[(&str, &str)] = &[
    ("salt", "TEXT"),
    ("batch_id", "TEXT"),
    ("plaintext_withheld", "INTEGER"),
    ("backend", "TEXT"),
];

/// Handle to the shared history database.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the history database at `db_path`.
    pub fn open(db_path: &Path) -> Result<Self, HistoryError> {
        let expanded = expand_home(db_path);
        migrate_legacy_dir(&expanded);
        if let Some(parent) = expanded.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                HistoryError(format!(
                    "Cannot create local history directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let conn = Connection::open(&expanded).map_err(|e| {
            HistoryError(format!(
                "Cannot open local history database at {}: {e}",
                expanded.display()
            ))
        })?;
        conn.execute_batch(SCHEMA).map_err(sqlite_err(&expanded))?;
        apply_migrations(&conn).map_err(sqlite_err(&expanded))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert one run row; returns the new `run_id`.
    pub fn record_run(&self, run: &NewRun) -> Result<i64, HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let started = run
            .started_at
            .clone()
            .unwrap_or_else(utc_now);
        let completed = run.completed_at.clone().unwrap_or_else(utc_now);
        conn.execute(
            "INSERT INTO audit_runs
             (started_at, completed_at, target_hash, algorithm, mode, status,
              attempts, elapsed_ms, worker_count, matched_plaintext, salt,
              batch_id, plaintext_withheld, backend)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                started,
                completed,
                run.target_hash,
                run.algorithm,
                run.mode,
                run.status,
                run.attempts,
                run.elapsed_ms,
                run.worker_count,
                run.matched_plaintext,
                run.salt,
                run.batch_id,
                run.plaintext_withheld as i64,
                run.backend,
            ],
        )
        .map_err(sqlite_err_owned())?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert (or replace) one hashlist batch summary row.
    pub fn record_batch(&self, batch: &NewBatch) -> Result<(), HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let started = batch
            .started_at
            .clone()
            .unwrap_or_else(utc_now);
        conn.execute(
            "INSERT OR REPLACE INTO audit_batches
             (batch_id, mode, status, attempts, elapsed_ms, worker_count,
              started_at, target_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                batch.batch_id,
                batch.mode,
                batch.status,
                batch.attempts,
                batch.elapsed_ms,
                batch.worker_count,
                started,
                batch.target_count,
            ],
        )
        .map_err(sqlite_err_owned())?;
        Ok(())
    }

    /// Newest-first run rows (API limit pinned at 100).
    pub fn list_runs(&self, limit: usize) -> Result<Vec<AuditRecord>, HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let mut stmt = conn
            .prepare(
                "SELECT run_id, started_at, completed_at, target_hash, algorithm,
                        mode, status, attempts, elapsed_ms, worker_count,
                        matched_plaintext, salt, batch_id, plaintext_withheld, backend
                 FROM audit_runs ORDER BY run_id DESC LIMIT ?1",
            )
            .map_err(sqlite_err_owned())?;
        let rows = stmt
            .query_map([limit as i64], map_row)
            .map_err(sqlite_err_owned())?;
        let mut records = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_err_owned())?;
        for record in &mut records {
            // Pre-Phase-11 rows carry NULL backend; both backends display
            // "python".
            record.backend = Some(record.backend.take().unwrap_or_else(|| "python".to_string()));
        }
        Ok(records)
    }

    /// All batch summaries, newest first.
    pub fn list_batches(&self) -> Result<Vec<BatchRecord>, HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let mut stmt = conn
            .prepare(
                "SELECT batch_id, mode, status, attempts, elapsed_ms,
                        worker_count, started_at, target_count
                 FROM audit_batches ORDER BY started_at DESC",
            )
            .map_err(sqlite_err_owned())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BatchRecord {
                    batch_id: row.get(0)?,
                    mode: row.get(1)?,
                    status: row.get(2)?,
                    attempts: row.get(3)?,
                    elapsed_ms: row.get(4)?,
                    worker_count: row.get(5)?,
                    started_at: row.get(6)?,
                    target_count: row.get(7)?,
                })
            })
            .map_err(sqlite_err_owned())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_err_owned())
    }

    /// Delete all runs and batches; returns the combined rowcount.
    pub fn clear_runs(&self) -> Result<u64, HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let runs = conn
            .execute("DELETE FROM audit_runs", [])
            .map_err(sqlite_err_owned())?;
        let batches = conn
            .execute("DELETE FROM audit_batches", [])
            .map_err(sqlite_err_owned())?;
        Ok((runs + batches) as u64)
    }

    /// Read one `history_meta` value.
    pub fn meta_get(&self, key: &str) -> Result<Option<String>, HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        let mut stmt = conn
            .prepare("SELECT value FROM history_meta WHERE key = ?1")
            .map_err(sqlite_err_owned())?;
        let mut rows = stmt.query([key]).map_err(sqlite_err_owned())?;
        match rows.next().map_err(sqlite_err_owned())? {
            Some(row) => Ok(Some(row.get(0).map_err(sqlite_err_owned())?)),
            None => Ok(None),
        }
    }

    /// Write one `history_meta` value.
    pub fn meta_set(&self, key: &str, value: &str) -> Result<(), HistoryError> {
        let conn = self.conn.lock().expect("history lock");
        conn.execute(
            "INSERT INTO history_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )
        .map_err(sqlite_err_owned())?;
        Ok(())
    }

    /// CSV export with the pinned column order; run rows leave
    /// `target_count` empty, batch rows leave run-only columns empty.
    pub fn export_csv(&self) -> Result<String, HistoryError> {
        let runs = self.list_runs(usize::MAX)?;
        let batches = self.list_batches()?;
        let mut out = String::new();
        out.push_str(&EXPORT_COLUMNS.join(","));
        out.push_str("\r\n");
        for run in &runs {
            let row = [
                Some(run.run_id.to_string()),
                run.started_at.clone(),
                run.completed_at.clone(),
                Some(run.target_hash.clone()),
                Some(run.algorithm.clone()),
                Some(run.mode.clone()),
                Some(run.status.clone()),
                Some(run.attempts.to_string()),
                Some(run.elapsed_ms.to_string()),
                Some(run.worker_count.to_string()),
                run.matched_plaintext.clone(),
                run.salt.clone(),
                run.batch_id.clone(),
                // Python's DictWriter stringifies bools as True/False.
                Some(if run.plaintext_withheld { "True" } else { "False" }.to_string()),
                run.backend.clone().or_else(|| Some("python".to_string())),
                None,
            ];
            out.push_str(&csv_row(&row));
            out.push_str("\r\n");
        }
        for batch in &batches {
            let row: [Option<String>; 16] = [
                None,
                None,
                None,
                None,
                None,
                Some(batch.mode.clone()),
                Some(batch.status.clone()),
                Some(batch.attempts.to_string()),
                Some(batch.elapsed_ms.to_string()),
                Some(batch.worker_count.to_string()),
                None,
                None,
                Some(batch.batch_id.clone()),
                None,
                None,
                Some(batch.target_count.to_string()),
            ];
            out.push_str(&csv_row(&row));
            out.push_str("\r\n");
        }
        Ok(out)
    }

    /// JSON export: `{"runs": [...], "batches": [...]}` (indent 2).
    pub fn export_json(&self) -> Result<String, HistoryError> {
        let runs = self.list_runs(usize::MAX)?;
        let batches = self.list_batches()?;
        let payload = serde_json::json!({ "runs": runs, "batches": batches });
        let mut body = serde_json::to_string_pretty(&payload)
            .map_err(|e| HistoryError(format!("Cannot serialize export: {e}")))?;
        body.push('\n'); // Python json.dump leaves a trailing newline.
        Ok(body)
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        run_id: row.get(0)?,
        started_at: row.get(1)?,
        completed_at: row.get(2)?,
        target_hash: row.get(3)?,
        algorithm: row.get(4)?,
        mode: row.get(5)?,
        status: row.get(6)?,
        attempts: row.get(7)?,
        elapsed_ms: row.get(8)?,
        worker_count: row.get(9)?,
        matched_plaintext: row.get(10)?,
        salt: row.get(11)?,
        batch_id: row.get(12)?,
        plaintext_withheld: row.get::<_, Option<i64>>(13)?.unwrap_or(0) != 0,
        backend: row.get(14)?,
    })
}

fn apply_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    let mut existing: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("PRAGMA table_info(audit_runs)")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            existing.push(name);
        }
    }
    for (col, ty) in MIGRATION_COLUMNS {
        if !existing.iter().any(|name| name == col) {
            let sql = format!("ALTER TABLE audit_runs ADD COLUMN {col} {ty}");
            conn.execute_batch(&sql)?;
        }
    }
    Ok(())
}

fn migrate_legacy_dir(db_path: &Path) {
    // Only the default path participates in the legacy migration.
    if db_path != default_db_path() {
        return;
    }
    let legacy = dirs_home().join(".password_audit");
    let current = default_data_dir();
    if legacy.exists() && !current.exists() {
        let _ = std::fs::rename(&legacy, &current);
    }
}

fn expand_home(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        return dirs_home().join(rest);
    }
    path.to_path_buf()
}

fn sqlite_err(db_path: &Path) -> impl Fn(rusqlite::Error) -> HistoryError + '_ {
    let path = db_path.display().to_string();
    move |e| HistoryError(format!("Cannot open local history database at {path}: {e}"))
}

fn sqlite_err_owned() -> impl Fn(rusqlite::Error) -> HistoryError {
    |e| HistoryError(e.to_string())
}

/// RFC 4180 CSV field quoting (Python csv module's minimal quoting).
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r')
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(fields: &[Option<String>; 16]) -> String {
    fields
        .iter()
        .map(|field| csv_field(field.as_deref().unwrap_or("")))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        (dir, store)
    }

    fn sample_run(plaintext: Option<&str>) -> NewRun {
        NewRun {
            target_hash: "8743b52063cd84097a65d1633f5c74f5".into(),
            algorithm: "md5".into(),
            mode: "dictionary".into(),
            status: "match".into(),
            attempts: 12,
            elapsed_ms: 345,
            worker_count: 4,
            matched_plaintext: plaintext.map(String::from),
            plaintext_withheld: plaintext.is_none(),
            backend: Some("rust".into()),
            ..Default::default()
        }
    }

    #[test]
    fn record_and_list_roundtrip() {
        let (_dir, store) = open_temp();
        let id = store.record_run(&sample_run(Some("hashcat"))).unwrap();
        let records = store.list_runs(100).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].run_id, id);
        assert_eq!(records[0].matched_plaintext.as_deref(), Some("hashcat"));
        assert_eq!(records[0].backend.as_deref(), Some("rust"));
        assert!(!records[0].plaintext_withheld);
        let started = records[0].started_at.as_deref().expect("started_at");
        assert!(started.ends_with('Z'), "{started}");
        assert_eq!(started.len(), 24); // YYYY-MM-DDTHH:MM:SS.mmmZ
    }

    #[test]
    fn withheld_plaintext_is_flag_not_sentinel() {
        let (_dir, store) = open_temp();
        store.record_run(&sample_run(None)).unwrap();
        let records = store.list_runs(100).unwrap();
        assert!(records[0].matched_plaintext.is_none());
        assert!(records[0].plaintext_withheld);
    }

    #[test]
    fn list_runs_is_newest_first_with_limit() {
        let (_dir, store) = open_temp();
        for n in 0..5 {
            let mut run = sample_run(Some("x"));
            run.target_hash = format!("{n:032x}");
            store.record_run(&run).unwrap();
        }
        let records = store.list_runs(3).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records[0].run_id > records[2].run_id);
    }

    #[test]
    fn backend_migration_is_additive() {
        // A pre-Phase-11 database (no backend column) is migrated on open.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_runs (
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
                matched_plaintext TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_runs (started_at, target_hash, algorithm, mode,
             status, attempts, elapsed_ms, worker_count)
             VALUES ('2026-01-01T00:00:00.000Z','h','md5','dictionary','match',1,1,1)",
            [],
        )
        .unwrap();
        drop(conn);
        let store = Store::open(&path).unwrap();
        let records = store.list_runs(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].backend.as_deref(), Some("python")); // pre-Phase-11 row
        assert_eq!(records[0].salt, None);
        assert_eq!(records[0].plaintext_withheld, false);
    }

    #[test]
    fn meta_roundtrip() {
        let (_dir, store) = open_temp();
        assert_eq!(store.meta_get("enc_salt").unwrap(), None);
        store.meta_set("enc_salt", "aabb").unwrap();
        store.meta_set("enc_salt", "ccdd").unwrap();
        assert_eq!(store.meta_get("enc_salt").unwrap().as_deref(), Some("ccdd"));
    }

    #[test]
    fn clear_returns_combined_rowcount() {
        let (_dir, store) = open_temp();
        store.record_run(&sample_run(Some("x"))).unwrap();
        store.record_batch(&NewBatch {
            batch_id: "abcd1234".into(),
            mode: "dictionary".into(),
            status: "match".into(),
            attempts: 5,
            elapsed_ms: 10,
            worker_count: 2,
            started_at: None,
            target_count: 3,
        })
        .unwrap();
        assert_eq!(store.clear_runs().unwrap(), 2);
        assert!(store.list_runs(10).unwrap().is_empty());
        assert!(store.list_batches().unwrap().is_empty());
    }

    #[test]
    fn csv_export_has_pinned_column_order() {
        let (_dir, store) = open_temp();
        store.record_run(&sample_run(Some("secret"))).unwrap();
        store.record_batch(&NewBatch {
            batch_id: "abcd1234".into(),
            mode: "dictionary".into(),
            status: "match".into(),
            attempts: 5,
            elapsed_ms: 10,
            worker_count: 2,
            started_at: None,
            target_count: 3,
        })
        .unwrap();
        let csv = store.export_csv().unwrap();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "run_id,started_at,completed_at,target_hash,algorithm,mode,status,attempts,elapsed_ms,worker_count,matched_plaintext,salt,batch_id,plaintext_withheld,backend,target_count"
        );
        let run_line = lines.next().unwrap();
        assert!(run_line.contains("secret"));
        assert!(run_line.ends_with(",rust,")); // backend then empty target_count
        let batch_line = lines.next().unwrap();
        // Batch rows: run-only columns empty through `algorithm`, then mode.
        assert!(batch_line.starts_with(",,,,,dictionary,"), "{batch_line}");
        assert!(batch_line.contains("abcd1234"));
    }

    #[test]
    fn csv_quoting_matches_rfc4180() {
        let (_dir, store) = open_temp();
        let mut run = sample_run(Some("has,comma"));
        run.status = "match".into();
        store.record_run(&run).unwrap();
        let csv = store.export_csv().unwrap();
        assert!(csv.contains("\"has,comma\""));
    }

    #[test]
    fn json_export_shape() {
        let (_dir, store) = open_temp();
        store.record_run(&sample_run(Some("secret"))).unwrap();
        let json = store.export_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["runs"].as_array().unwrap().len() == 1);
        assert_eq!(value["runs"][0]["backend"], "rust");
        assert_eq!(value["runs"][0]["plaintext_withheld"], false);
        assert!(value["batches"].as_array().unwrap().is_empty());
    }
}
