//! `hashcrack-rs history` and `export` — parity with the Python CLI.

use std::io::Write;
use std::path::{Path, PathBuf};

use hc_history::encryption::ENCRYPT_PREFIX;
use hc_history::{AuditRecord, Store};

use crate::cmd_audit::{EXIT_INVALID, EXIT_OK, EXIT_STORAGE};

pub struct HistoryRequest {
    pub limit: usize,
    pub passphrase: Option<String>,
    pub unlock: bool,
    pub database: PathBuf,
}

pub struct ExportRequest {
    pub path: PathBuf,
    pub format: String,
    pub database: PathBuf,
}

/// Passphrase chain for unlocking: `--passphrase` → env → prompt (no confirm).
pub fn resolve_unlock_passphrase(flag: Option<&str>) -> Option<String> {
    resolve_passphrase_source(flag, false)
}

/// Passphrase chain for setting encryption on audit: prompts with confirmation.
pub fn resolve_new_passphrase(flag: Option<&str>) -> Option<String> {
    resolve_passphrase_source(flag, true)
}

fn resolve_passphrase_source(flag: Option<&str>, confirm: bool) -> Option<String> {
    if let Some(value) = flag {
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    if let Ok(value) = std::env::var("PASSWORD_AUDIT_PASSPHRASE") {
        if !value.is_empty() {
            return Some(value);
        }
    }
    let value = prompt("History encryption passphrase: ");
    if confirm {
        let confirm_value = prompt("Confirm passphrase: ");
        if value.is_empty() || value != confirm_value {
            return None;
        }
    }
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// No-echo prompt (getpass equivalent).
fn prompt(message: &str) -> String {
    print!("{message}");
    let _ = std::io::stdout().flush();
    rpassword::read_password().unwrap_or_default()
}

pub fn run_history(request: HistoryRequest) -> i32 {
    let mut plaintext_key: Option<[u8; 32]> = None;
    if request.unlock {
        let passphrase = match resolve_unlock_passphrase(request.passphrase.as_deref()) {
            Some(value) => value,
            None => {
                eprintln!("No passphrase provided; the history stays as it is.");
                return EXIT_INVALID;
            }
        };
        let store = match Store::open(&request.database) {
            Ok(store) => store,
            Err(err) => {
                eprintln!("Unlock failed: {err}");
                return EXIT_STORAGE;
            }
        };
        match hc_history::init(&store, &passphrase) {
            Ok(key) => plaintext_key = Some(key),
            Err(err) => {
                eprintln!("Unlock failed: {err}");
                return EXIT_STORAGE;
            }
        }
    }

    let store = match Store::open(&request.database) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("History storage failed: {err}");
            return EXIT_STORAGE;
        }
    };
    let records = match store.list_runs(request.limit) {
        Ok(records) => records,
        Err(err) => {
            eprintln!("History storage failed: {err}");
            return EXIT_STORAGE;
        }
    };
    if records.is_empty() {
        println!("No local audit records yet. Run an audit to create history.");
        return EXIT_OK;
    }
    println!(
        "Local audit history ({} record{}):",
        records.len(),
        if records.len() == 1 { "" } else { "s" }
    );
    println!(
        "{:>4}  {:<23}  {:<18}  {:<6}  {:<11}  {:>10}  {:>9}  W  Hash / plaintext",
        "ID", "Started (UTC)", "Status", "Alg", "Mode", "Attempts", "Elapsed"
    );
    for record in &records {
        println!("{}", format_record(record, plaintext_key.as_ref()));
    }
    println!(
        "\nSuccessful matches store the recovered plaintext/hash pair locally;\ntreat this database as sensitive credential data."
    );
    EXIT_OK
}

/// `_format_record` parity: `#id  started  status  alg  mode  attempts  elapsed  W  hash...`
fn format_record(record: &AuditRecord, plaintext_key: Option<&[u8; 32]>) -> String {
    let plaintext = display_plaintext(record.matched_plaintext.as_deref(), plaintext_key);
    format!(
        "#{id}  {started}  {status:<18}  {alg:<6}  {mode:<11}  {attempts:>10}  {elapsed:>8}ms  {workers}w  {hash}...  plaintext={plaintext}",
        id = record.run_id,
        started = record.started_at.as_deref().unwrap_or(""),
        status = record.status,
        alg = record.algorithm,
        mode = record.mode,
        attempts = crate::output::commas(record.attempts.max(0) as u64),
        elapsed = crate::output::commas(record.elapsed_ms.max(0) as u64),
        workers = record.worker_count,
        hash = &record.target_hash[..record.target_hash.len().min(16)],
        plaintext = plaintext,
    )
}

fn display_plaintext(value: Option<&str>, plaintext_key: Option<&[u8; 32]>) -> String {
    match value {
        None => "-".to_string(),
        Some(value) if value.starts_with(ENCRYPT_PREFIX) => match plaintext_key {
            None => "<encrypted>".to_string(),
            Some(key) => match hc_history::decrypt_stored(key, value) {
                Some(Ok(plain)) => plain,
                _ => "<decryption failed>".to_string(),
            },
        },
        Some(value) => value.to_string(),
    }
}

pub fn run_export(request: ExportRequest) -> i32 {
    let store = match Store::open(&request.database) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("Report export failed: {err}");
            return EXIT_STORAGE;
        }
    };
    let expanded = expand_home(&request.path);
    let contents = match request.format.as_str() {
        "json" => store.export_json(),
        _ => store.export_csv(),
    };
    let contents = match contents {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Report export failed: {err}");
            return EXIT_STORAGE;
        }
    };
    if std::fs::write(&expanded, contents).is_err() {
        eprintln!(
            "Report export failed: Cannot write to {}.",
            expanded.display()
        );
        return EXIT_STORAGE;
    }
    println!("Exported local audit history to {}", expanded.display());
    println!("The report contains sensitive plaintext/hash pairs for successful matches.");
    EXIT_OK
}

fn expand_home(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        return home.join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_line_shape() {
        let record = AuditRecord {
            run_id: 7,
            started_at: Some("2026-11-18T12:34:56.789Z".to_string()),
            completed_at: None,
            target_hash: "8743b52063cd84097a65d1633f5c74f5".to_string(),
            algorithm: "md5".to_string(),
            mode: "dictionary".to_string(),
            status: "match".to_string(),
            attempts: 3,
            elapsed_ms: 456,
            worker_count: 4,
            matched_plaintext: Some("hashcat".to_string()),
            salt: None,
            batch_id: None,
            plaintext_withheld: false,
            backend: Some("rust".to_string()),
        };
        let line = format_record(&record, None);
        assert!(line.starts_with("#7  2026-11-18T12:34:56.789Z  match"), "{line}");
        assert!(line.contains("md5     dictionary"));
        assert!(line.contains("8743b52063cd8409..."));
        assert!(line.ends_with("plaintext=hashcat"));
    }

    #[test]
    fn encrypted_display_placeholders() {
        assert_eq!(display_plaintext(Some("plain"), None), "plain");
        assert_eq!(display_plaintext(None, None), "-");
        assert_eq!(display_plaintext(Some("enc1:xyz"), None), "<encrypted>");
    }
}
