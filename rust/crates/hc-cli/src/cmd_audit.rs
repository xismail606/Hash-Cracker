//! `hashcrack-rs audit` — the parity twin of the Python CLI's audit command.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use hc_core::bruteforce::{
    self, format_commas, BruteforceSource, HARD_MAX_BUDGET,
};
use hc_core::candidates::{self, DictionarySource, HashlistTarget};
use hc_core::engine::{
    self, CandidateStream, Control, HashlistOptions, HashlistResult, RunResult,
    STATUS_BUDGET_EXHAUSTED, STATUS_CANCELLED, STATUS_INTERRUPTED, STATUS_MATCH, STATUS_NO_MATCH,
};
use hc_core::identify::{select_algorithm, HashInputError};
use hc_core::rules::{resolve_rules_preset, RuleError, RuleExpander};
use hc_history::{NewBatch, NewRun, Store};

use crate::output::ProgressRenderer;

pub const EXIT_OK: i32 = 0;
pub const EXIT_INVALID: i32 = 1;
pub const EXIT_CANCELLED: i32 = 2;
pub const EXIT_STORAGE: i32 = 3;

pub const RETENTION_WARNING: &str = "SENSITIVE-DATA WARNING: if this audit finds a match, the recovered\nplaintext and its target hash will be saved to the local SQLite audit\nhistory on this machine. Nothing is sent over the network, but anyone\nwith access to this computer can read the stored plaintext.\n";

/// clap enum for `--mode` (invalid values exit 2, mirroring argparse).
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Mode {
    Dictionary,
    #[value(name = "brute-force")]
    BruteForce,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Dictionary => "dictionary",
            Mode::BruteForce => "brute-force",
        }
    }
}

/// Errors that map to `EXIT_INVALID` with a printed message.
struct AuditError(String);

pub struct AuditRequest {
    pub hash: Option<String>,
    pub hashlist: Option<PathBuf>,
    pub rules: String,
    pub algorithm: Option<String>,
    pub mode: Mode,
    pub wordlist: Option<PathBuf>,
    pub salt: Option<String>,
    pub charset: Option<String>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub max_candidates: u64,
    pub workers: usize,
    pub no_store_plaintext: bool,
    pub yes: bool,
    pub encrypt: bool,
    pub passphrase: Option<String>,
    pub database: PathBuf,
}

/// Candidate stream combinator: dictionary batches, optionally rule-expanded.
enum Source {
    Dictionary(DictionarySource),
    BruteForce(BruteforceSource),
    Rules(Box<RuleExpander>, Box<Source>),
}

impl CandidateStream for Source {
    fn next_batch(&mut self, max: usize) -> Option<Vec<String>> {
        match self {
            Source::Dictionary(inner) => inner.next_batch(max),
            Source::BruteForce(inner) => inner.next_batch(max),
            Source::Rules(expander, inner) => {
                let batch = inner.next_batch(max)?;
                expander.expand_batch(&batch)
            }
        }
    }
}

pub fn run(request: AuditRequest) -> i32 {
    match run_inner(request) {
        Ok(code) => code,
        Err(AuditError(message)) => {
            eprintln!("{message}");
            EXIT_INVALID
        }
    }
}

fn run_inner(request: AuditRequest) -> Result<i32, AuditError> {
    // 1. Target selection: exactly one of a positional hash or --hashlist.
    if request.hashlist.is_some() && request.hash.is_some() {
        return Err(AuditError("Provide either HASH or --hashlist PATH, not both.".into()));
    }
    if request.hashlist.is_none() && request.hash.is_none() {
        return Err(AuditError("Provide HASH or --hashlist PATH.".into()));
    }

    // 2. Rules preset (dictionary only).
    let variants_for = if request.rules != "none" {
        if request.mode != Mode::Dictionary {
            return Err(AuditError("--rules applies to dictionary mode only.".into()));
        }
        match resolve_rules_preset(&request.rules) {
            Ok(resolved) => resolved,
            Err(RuleError(message)) => {
                return Err(AuditError(format!("Invalid audit options: {message}")))
            }
        }
    } else {
        None
    };

    // 3. Target validation / hashlist parsing.
    let targets: Option<Vec<HashlistTarget>> = match &request.hashlist {
        Some(path) => {
            let content = read_hashlist_file(path).map_err(AuditError)?;
            match candidates::parse_hashlist(&content) {
                Ok(targets) => Some(targets),
                Err(err) => return Err(AuditError(format!("Invalid hashlist: {err}"))),
            }
        }
        None => None,
    };
    if request.hashlist.is_some() {
        if request.salt.is_some() {
            return Err(AuditError(
                "--salt is not supported with hashlists (no per-target salt).".into(),
            ));
        }
        if request.algorithm.is_some() {
            return Err(AuditError(
                "--algorithm is ignored with --hashlist; each line carries its own algorithm."
                    .into(),
            ));
        }
    }

    let mut target_hash: Option<String> = None;
    let mut algorithm: Option<&'static str> = None;
    let mut salt: Option<String> = None;
    if targets.is_none() {
        let hash = request.hash.clone().expect("checked above");
        match select_algorithm(&hash, request.algorithm.as_deref()) {
            Ok((assessment, chosen)) => {
                target_hash = Some(assessment.normalized);
                algorithm = Some(
                    hc_core::formats::format_by_name(&chosen)
                        .expect("validated algorithm")
                        .name,
                );
            }
            Err(HashInputError(message)) => {
                return Err(AuditError(format!("Invalid hash input: {message}")))
            }
        }
        let format = hc_core::formats::format_by_name(algorithm.unwrap()).unwrap();
        if format.is_salted() {
            match &request.salt {
                Some(value) => salt = Some(value.clone()),
                None => {
                    return Err(AuditError(format!(
                        "Salted format {} requires --salt VALUE (the known salt stored alongside the hash).",
                        algorithm.unwrap()
                    )))
                }
            }
        } else if request.salt.is_some() {
            return Err(AuditError(format!(
                "Algorithm {} does not take a salt; remove --salt.",
                algorithm.unwrap()
            )));
        }
    }

    // 4. Workers.
    let workers = request.workers;
    if !(engine::MIN_WORKERS..=engine::MAX_WORKERS).contains(&workers) {
        return Err(AuditError(format!(
            "Invalid audit options: Worker count must be between {} and {} (got {workers}).",
            engine::MIN_WORKERS,
            engine::MAX_WORKERS
        )));
    }

    // 5. Mode setup: sources, budget, total space.
    let budget: Option<u64>;
    let total_space: Option<u128>;
    let mut source: Source;
    let mut alphabet: Option<String> = None;
    match request.mode {
        Mode::Dictionary => {
            let wordlist = request.wordlist.clone().unwrap_or_default();
            if !wordlist.is_file() {
                return Err(AuditError(format!(
                    "Invalid wordlist: {} is not a readable local file.",
                    wordlist.display()
                )));
            }
            let dict = DictionarySource::open(&wordlist)
                .map_err(|e| AuditError(format!("Invalid wordlist: {e}")))?;
            if variants_for.is_some() {
                budget = Some(request.max_candidates);
                total_space = None;
                source = Source::Rules(
                    Box::new(RuleExpander::new(variants_for, request.max_candidates)),
                    Box::new(Source::Dictionary(dict)),
                );
            } else {
                budget = None;
                total_space = DictionarySource::count_lines(&wordlist).map(|n| n as u128);
                source = Source::Dictionary(dict);
            }
        }
        Mode::BruteForce => {
            let spec = request.charset.clone().unwrap_or_default();
            let resolved = bruteforce::resolve_charset(&spec).map_err(|e| {
                AuditError(format!("Invalid audit options: {e}"))
            })?;
            let min_length = request.min_length.unwrap_or(0);
            let max_length = request.max_length.unwrap_or(0);
            let (resolved_alphabet, space) = bruteforce::validate_bruteforce_options(
                min_length,
                max_length,
                request.max_candidates,
                Some(resolved),
            )
            .map_err(|e| AuditError(format!("Invalid audit options: {e}")))?;
            alphabet = Some(resolved_alphabet);
            total_space = Some(space);
            budget = Some(request.max_candidates);
            source = Source::BruteForce(BruteforceSource::new(
                alphabet.clone().unwrap(),
                min_length,
                max_length,
            ));
        }
    }

    // 6. Withholding / encryption exclusivity.
    let withhold = request.no_store_plaintext;
    if withhold && request.encrypt {
        return Err(AuditError(
            "--encrypt and --no-store-plaintext are mutually exclusive.".into(),
        ));
    }

    // 7. Retention acknowledgement.
    if !confirm_retention(request.yes) {
        return Err(AuditError(
            "The audit was not started because the retention warning was not acknowledged.".into(),
        ));
    }

    // 8. Header.
    println!("Mode      : {}", request.mode.label());
    if let Some(targets) = &targets {
        println!("Hashlist  : {} targets", targets.len());
        println!("Workers   : {workers}");
    } else {
        println!("Algorithm : {}", algorithm.unwrap().to_uppercase());
        println!("Workers   : {workers}");
    }
    if request.mode == Mode::BruteForce {
        let alphabet = alphabet.as_ref().unwrap();
        let sorted: String = {
            let mut chars: Vec<char> = alphabet.chars().collect();
            chars.sort_unstable();
            chars.into_iter().collect()
        };
        println!(
            "Charset   : {} ({} characters)",
            crate::output::py_repr(&sorted),
            alphabet.chars().count()
        );
        println!(
            "Lengths   : {}..{}",
            request.min_length.unwrap_or(0),
            request.max_length.unwrap_or(0)
        );
        println!(
            "Budget    : {} candidates (hard max {})",
            format_commas(request.max_candidates),
            format_commas(HARD_MAX_BUDGET)
        );
    }
    if variants_for.is_some() {
        println!("Rules     : {}", request.rules);
    }
    println!("Starting audit; press Ctrl+C to interrupt...");

    // 9. Run the engine with throttled progress.
    let control = Control::new();
    install_interrupt_handler(&control);
    let progress_limit = total_space.map(|space| space.min(budget.unwrap_or(u64::MAX) as u128));
    let renderer = std::sync::Mutex::new(ProgressRenderer::new(progress_limit));
    let progress = |attempts: u64, elapsed_ms: i64, fraction: Option<f64>| {
        if let Ok(mut renderer) = renderer.lock() {
            renderer.render(attempts, elapsed_ms, fraction);
        }
    };
    let started_at = hc_history::utc_now();
    let result: EngineOutcome = match &targets {
        Some(targets) => EngineOutcome::Hashlist(engine::run_hashlist_audit(
            HashlistOptions {
                workers,
                budget,
                total_space,
                resume: None,
            },
            targets,
            &mut source,
            &control,
            Some(&progress),
        )),
        None => EngineOutcome::Single(engine::run_audit(
            engine::AuditOptions {
                format: hc_core::formats::format_by_name(algorithm.unwrap()).unwrap(),
                target: target_hash.as_deref().unwrap(),
                salt: salt.as_deref(),
                workers,
                budget,
                total_space,
                resume: None,
            },
            &mut source,
            &control,
            Some(&progress),
        )),
    };
    renderer.lock().unwrap().finish();

    // 10. Result output (section parity with the Python CLI).
    match &result {
        EngineOutcome::Single(result) => {
            println!(
                "Status    : {}",
                status_label(result.status)
            );
            println!("Attempts  : {}", crate::output::commas(result.attempts));
            println!(
                "Elapsed   : {:.2}s",
                result.elapsed_ms as f64 / 1000.0
            );
            println!("Workers   : {workers}");
            if result.status == STATUS_MATCH {
                println!(
                    "Plaintext : {}",
                    result.matched_plaintext.as_deref().unwrap_or("")
                );
                println!("Hash      : {}", target_hash.as_deref().unwrap_or(""));
                if !withhold {
                    println!(
                        "The recovered plaintext/hash pair above was saved to local SQLite\nhistory as sensitive audit data."
                    );
                }
            }
        }
        EngineOutcome::Hashlist(result) => {
            println!(
                "Status    : {}",
                status_label(result.status)
            );
            println!("Attempts  : {}", crate::output::commas(result.attempts));
            println!(
                "Elapsed   : {:.2}s",
                result.elapsed_ms as f64 / 1000.0
            );
            println!("Workers   : {workers}");
            let matched_count = result
                .targets
                .iter()
                .filter(|t| t.status == STATUS_MATCH)
                .count();
            println!("Targets   : {matched_count}/{} matched", result.targets.len());
            for t in &result.targets {
                let mark = if t.status == STATUS_MATCH { "MATCH   " } else { "no match" };
                let plaintext = t.matched_plaintext.as_deref().unwrap_or("-");
                println!(
                    "  [{mark}] {:<16} {}...  plaintext={plaintext}",
                    t.algorithm,
                    &t.hash[..t.hash.len().min(20)]
                );
            }
        }
    }

    // 11. Persist.
    let store = match Store::open(&request.database) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("History storage failed: {e}");
            eprintln!(
                "The audit finished but the result could not be recorded in local history."
            );
            return Ok(EXIT_STORAGE);
        }
    };

    // Encryption-at-rest init (CLI-only path; the dashboard withholds instead).
    let mut plaintext_key: Option<[u8; 32]> = None;
    if request.encrypt {
        let passphrase = match crate::cmd_history::resolve_new_passphrase(request.passphrase.as_deref()) {
            Some(value) => value,
            None => {
                eprintln!(
                    "Passphrases do not match or are empty; the audit result was not saved."
                );
                return Ok(EXIT_INVALID);
            }
        };
        match hc_history::init(&store, &passphrase) {
            Ok(key) => plaintext_key = Some(key),
            Err(e) => {
                eprintln!("History encryption failed: {e}");
                return Ok(EXIT_STORAGE);
            }
        }
    }

    // Encrypt matched plaintext before storage when --encrypt is set.
    let encrypt_value = |value: &Option<String>, key: &Option<[u8; 32]>| -> Option<String> {
        match (value, key) {
            (Some(plain), Some(key)) => hc_history::encrypt_stored(key, plain).ok(),
            (other, _) => other.clone(),
        }
    };
    
    match (&result, &targets) {
        (EngineOutcome::Hashlist(result), Some(_targets)) => {
            let id = uuid_v4_hex();
            let batch = NewBatch {
                batch_id: id.clone(),
                mode: request.mode.label().to_string(),
                status: result.status.to_string(),
                attempts: result.attempts as i64,
                elapsed_ms: result.elapsed_ms,
                worker_count: workers as i64,
                started_at: Some(started_at.clone()),
                target_count: result.targets.len() as i64,
            };
            if let Err(e) = store.record_batch(&batch) {
                return Ok(history_fail(e));
            }
            for t in &result.targets {
                let run = NewRun {
                    target_hash: t.hash.clone(),
                    algorithm: t.algorithm.to_string(),
                    mode: request.mode.label().to_string(),
                    status: t.status.to_string(),
                    attempts: t.match_at_attempt.unwrap_or(result.attempts) as i64,
                    elapsed_ms: result.elapsed_ms,
                    worker_count: workers as i64,
                    matched_plaintext: if withhold {
                        None
                    } else {
                        encrypt_value(&t.matched_plaintext, &plaintext_key)
                    },
                    started_at: Some(started_at.clone()),
                    completed_at: None,
                    salt: None,
                    batch_id: Some(id.clone()),
                    plaintext_withheld: withhold,
                    backend: Some("rust".to_string()),
                };
                if let Err(e) = store.record_run(&run) {
                    return Ok(history_fail(e));
                }
            }
            println!(
                "Batch     : {} ({} target records)",
                &id[..8],
                result.targets.len()
            );
            Some(id)
        }
        (EngineOutcome::Single(result), None) => {
            let run = NewRun {
                target_hash: target_hash.clone().unwrap_or_default(),
                algorithm: algorithm.unwrap_or_default().to_string(),
                mode: request.mode.label().to_string(),
                status: result.status.to_string(),
                attempts: result.attempts as i64,
                elapsed_ms: result.elapsed_ms,
                worker_count: workers as i64,
                matched_plaintext: if withhold || result.status != STATUS_MATCH {
                    None
                } else {
                    encrypt_value(&result.matched_plaintext, &plaintext_key)
                },
                started_at: Some(started_at.clone()),
                completed_at: None,
                salt,
                batch_id: None,
                plaintext_withheld: withhold,
                backend: Some("rust".to_string()),
            };
            if let Err(e) = store.record_run(&run) {
                return Ok(history_fail(e));
            }
            None
        }
        _ => unreachable!("outcome/target pairing"),
    };

    if withhold && matches!(&result, EngineOutcome::Single(r) if r.status == STATUS_MATCH) {
        println!(
            "Plaintext withheld from local history (--no-store-plaintext);\nthe match above is displayed for this session only."
        );
    }

    // 12. Exit code by status.
    let status = match &result {
        EngineOutcome::Single(r) => r.status,
        EngineOutcome::Hashlist(r) => r.status,
    };
    Ok(match status {
        STATUS_MATCH | STATUS_NO_MATCH | STATUS_BUDGET_EXHAUSTED => EXIT_OK,
        STATUS_CANCELLED | STATUS_INTERRUPTED => EXIT_CANCELLED,
        _ => EXIT_INVALID,
    })
}

fn history_fail(e: hc_history::HistoryError) -> i32 {
    eprintln!("History storage failed: {e}");
    eprintln!("The audit finished but the result could not be recorded in local history.");
    EXIT_STORAGE
}

enum EngineOutcome {
    Single(RunResult),
    Hashlist(HashlistResult),
}

fn status_label(status: &str) -> String {
    match status {
        STATUS_MATCH => "MATCH".to_string(),
        STATUS_NO_MATCH => "NO MATCH".to_string(),
        STATUS_BUDGET_EXHAUSTED => "BUDGET EXHAUSTED".to_string(),
        STATUS_CANCELLED => "CANCELLED".to_string(),
        STATUS_INTERRUPTED => "INTERRUPTED".to_string(),
        "storage_error" => "STORAGE ERROR".to_string(),
        other => other.to_string(),
    }
}

fn read_hashlist_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("Invalid hashlist: Cannot read the hashlist file: {e}"))
}

/// Print the sensitive-data warning and require explicit acknowledgement.
fn confirm_retention(assumed_yes: bool) -> bool {
    // print(RETENTION_WARNING) in Python adds a trailing blank line.
    println!("{RETENTION_WARNING}");
    let _ = std::io::stdout().flush();
    if assumed_yes {
        println!("Acknowledged automatically via --yes.");
        return true;
    }
    print!("Acknowledge local plaintext/hash retention to continue? [yes/no]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    match std::io::stdin().read_line(&mut answer) {
        Ok(0) | Err(_) => {
            eprintln!("\nNo acknowledgement received; the audit was not started.");
            return false;
        }
        Ok(_) => {}
    }
    let trimmed = answer.trim().to_lowercase();
    trimmed == "y" || trimmed == "yes"
}

fn install_interrupt_handler(control: &Arc<Control>) {
    let control = Arc::clone(control);
    let _ = ctrlc::set_handler(move || {
        control.interrupted.store(true, Ordering::SeqCst);
    });
}

fn uuid_v4_hex() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
