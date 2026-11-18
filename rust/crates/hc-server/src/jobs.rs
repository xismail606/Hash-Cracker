//! Dashboard job lifecycle: single-slot audit submission, polling,
//! pause/resume/cancel, the paused-jobs sidecar, and restart recovery.
//! Semantics mirror `src/hash_cracker/web.py` (see contracts/api.md).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use hc_core::bruteforce::BruteforceSource;
use hc_core::candidates::{self, DictionarySource, HashlistTarget};
use hc_core::engine::{
    self, CandidateStream, Control, HashlistOptions, ResumeState, STATUS_MATCH, STATUS_PAUSED,
};
use hc_core::formats;
use hc_core::identify::select_algorithm;
use hc_core::rules::{resolve_rules_preset, RuleExpander};
use hc_history::{NewBatch, NewRun, Store};

use crate::app::{csrf_check, request_host, SharedState};

const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;
const STATE_VALIDATING: &str = "validating";
const STATE_RUNNING: &str = "running";
const STATE_PAUSED: &str = "paused";
const PAUSED_JOB_RETENTION_DAYS: u64 = 7;

/// Parameterization needed to rebuild the candidate source on resume.
#[derive(Debug, Clone)]
pub enum RunParams {
    Dictionary {
        wordlist: PathBuf,
        wordlist_size: u64,
        rules_name: String,
    },
    BruteForce {
        charset: String,
        min_length: u64,
        max_length: u64,
    },
}

/// One dashboard audit job.
pub struct Job {
    pub id: String,
    pub state: Mutex<String>,
    pub mode: &'static str,
    pub algorithm: Option<&'static str>,
    pub target_hash: Option<String>,
    pub salt: Option<String>,
    pub workers: usize,
    pub budget: Option<u64>,
    pub total_space: Option<u128>,
    pub attempts: AtomicU64,
    pub elapsed_ms: AtomicI64,
    pub result: Mutex<Option<serde_json::Value>>,
    pub error: Mutex<Option<String>>,
    pub control: Arc<Control>,
    /// Parameterization for resume; updated when uploads move into the
    /// paused dir (jobs are shared across threads via Arc).
    pub params: Mutex<RunParams>,
    pub targets: Option<Vec<HashlistTarget>>,
    pub plaintext_withheld: bool,
    pub started_at: String,
    /// Uploaded files (moved into the paused dir on pause; deleted on terminal).
    pub wordlist_path: Mutex<Option<PathBuf>>,
    pub hashlist_path: Mutex<Option<PathBuf>>,
    /// Resume state produced by a pause (consumed by resume).
    pub resume: Mutex<Option<ResumeState>>,
    pub thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Job {
    fn is_active(state: &str) -> bool {
        state == STATE_VALIDATING || state == STATE_RUNNING
    }
}

/// The one-job-at-a-time registry plus paused-job storage location.
pub struct JobRegistry {
    pub slot: Mutex<Option<Arc<Job>>>,
    pub db_path: PathBuf,
    pub paused_dir: PathBuf,
}

impl JobRegistry {
    pub fn new(db_path: PathBuf) -> Self {
        let paused_dir = db_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("paused_jobs");
        Self {
            slot: Mutex::new(None),
            db_path,
            paused_dir,
        }
    }
}

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

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// `POST /api/audits` — multipart submission (CSRF required).
pub async fn submit_audit(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    let host = request_host(&headers);
    let _ = host;

    // Collect all fields first; validation follows the pinned order.
    let mut form: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut wordlist_bytes: Option<Vec<u8>> = None;
    let mut hashlist_text: Option<String> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "wordlist" => {
                let data = match field.bytes().await {
                    Ok(bytes) => bytes.to_vec(),
                    Err(_) => {
                        return bad_request("The wordlist upload could not be read.");
                    }
                };
                if data.len() as u64 > MAX_UPLOAD_BYTES {
                    return too_large();
                }
                wordlist_bytes = Some(data);
            }
            "hashlist" => match field.text().await {
                Ok(text) => hashlist_text = Some(text),
                Err(_) => {
                    return bad_request("Invalid hashlist: the upload could not be read.");
                }
            },
            _ => {
                if let Ok(value) = field.text().await {
                    form.insert(name, value);
                }
            }
        }
    }

    // 1. Retention acknowledgement.
    if form.get("acknowledge_retention").map(String::as_str) != Some("true") {
        return bad_request(
            "You must acknowledge the local plaintext/hash retention warning before starting an audit.",
        );
    }
    // 2. Mode.
    let mode = match form.get("mode").map(String::as_str) {
        Some("dictionary") => "dictionary",
        Some("brute-force") => "brute-force",
        _ => {
            return bad_request("Mode must be 'dictionary' or 'brute-force'.");
        }
    };
    // 3. Algorithm (required iff no hashlist).
    let mut algorithm: Option<&'static str> = if hashlist_text.is_none() {
        let requested = form.get("algorithm").map(String::as_str).unwrap_or("");
        match formats::format_by_name(requested) {
            Some(format) => Some(format.name),
            None => {
                return bad_request(&format!(
                    "Unsupported algorithm '{requested}'. Supported: {}.",
                    formats::ALGORITHM_NAMES.join(", ")
                ));
            }
        }
    } else {
        None
    };
    // 4. Hash (validated against the chosen algorithm).
    let mut target_hash: Option<String> = None;
    if hashlist_text.is_none() {
        let hash_value = form.get("hash").map(String::as_str).unwrap_or("");
        match select_algorithm(hash_value, algorithm) {
            Ok((assessment, chosen)) => {
                target_hash = Some(assessment.normalized);
                algorithm = Some(
                    formats::format_by_name(&chosen)
                        .expect("validated algorithm")
                        .name,
                );
            }
            Err(err) => return bad_request(&err.0),
        }
    }
    // 5. Salt.
    let salt = if hashlist_text.is_some() {
        if form.contains_key("salt") {
            return bad_request("--salt is not supported with hashlists (no per-target salt).");
        }
        None
    } else {
        let format = formats::format_by_name(algorithm.unwrap()).unwrap();
        if format.is_salted() {
            match form.get("salt").map(String::as_str) {
                Some(value) if !value.is_empty() => Some(value.to_string()),
                _ => {
                    return bad_request(&format!(
                        "Salted format {} requires a salt value.",
                        algorithm.unwrap()
                    ));
                }
            }
        } else {
            if form.contains_key("salt") {
                return bad_request(&format!(
                    "Algorithm {} does not take a salt.",
                    algorithm.unwrap()
                ));
            }
            None
        }
    };
    // 6. Workers.
    let workers = match form.get("workers") {
        None => 4usize,
        Some(raw) => match raw.trim().parse::<usize>() {
            Ok(count) => count,
            Err(_) => return bad_request("Worker count must be an integer."),
        },
    };
    if !(engine::MIN_WORKERS..=engine::MAX_WORKERS).contains(&workers) {
        return bad_request("Worker count must be between 1 and 8.");
    }
    // 7. Rules.
    let rules_name = form.get("rules").map(String::as_str).unwrap_or("none");
    let variants_for = if rules_name != "none" {
        if mode != "dictionary" {
            return bad_request("Rules apply to dictionary mode only.");
        }
        match resolve_rules_preset(rules_name) {
            Ok(resolved) => resolved,
            Err(err) => return bad_request(&err.0),
        }
    } else {
        None
    };
    // 8. Plaintext withholding.
    let plaintext_withheld = form.get("store_plaintext").map(String::as_str) == Some("false");
    // 9. Candidate budget.
    let mut budget: Option<u64> = None;
    if mode == "dictionary" && variants_for.is_some() {
        match form
            .get("max_candidates")
            .map(String::as_str)
            .unwrap_or("")
            .trim()
            .parse::<u64>()
        {
            Ok(value) => budget = Some(value.clamp(1, hc_core::bruteforce::HARD_MAX_BUDGET)),
            Err(_) => return bad_request("The candidate budget must be an integer."),
        }
    }
    // 10. Brute-force settings.
    let mut charset: Option<String> = None;
    let mut min_length = 0u64;
    let mut max_length = 0u64;
    let mut total_space: Option<u128> = None;
    if mode == "brute-force" {
        let spec = form.get("charset").map(String::as_str).unwrap_or("");
        let parsed_min = form
            .get("min_length")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let parsed_max = form
            .get("max_length")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let parsed_budget = form
            .get("max_candidates")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let outcome = (|| {
            let resolved = hc_core::bruteforce::resolve_charset(spec).ok()?;
            let min = parsed_min?;
            let max = parsed_max?;
            let cap = parsed_budget?;
            let (alphabet, space) =
                hc_core::bruteforce::validate_bruteforce_options(min, max, cap, Some(resolved))
                    .ok()?;
            Some((alphabet, space, min, max, cap))
        })();
        match outcome {
            Some((alphabet, space, min, max, cap)) => {
                charset = Some(alphabet);
                total_space = Some(space);
                min_length = min;
                max_length = max;
                budget = Some(cap);
            }
            None => {
                return bad_request(
                    "Invalid brute-force settings: charset, length range, and a candidate budget up to 10,000,000 are required.",
                );
            }
        }
    }
    // 11. Wordlist file (dictionary mode).
    if mode == "dictionary" && wordlist_bytes.is_none() {
        return bad_request("Dictionary mode requires a wordlist upload.");
    }
    // 12. Hashlist parsing.
    let targets: Option<Vec<HashlistTarget>> = match &hashlist_text {
        Some(text) => match candidates::parse_hashlist(text) {
            Ok(targets) => Some(targets),
            Err(err) => return bad_request(&format!("Invalid hashlist: {err}")),
        },
        None => None,
    };

    // Single-slot reservation.
    let job_id = uuid::Uuid::new_v4().simple().to_string();
    let temp_dir = tempfile::tempdir().expect("temp staging dir");
    let wordlist_path: Option<PathBuf> = match wordlist_bytes {
        Some(bytes) => {
            let path = temp_dir.path().join(format!("{job_id}-wordlist.txt"));
            if std::fs::write(&path, &bytes).is_err() {
                return bad_request("The wordlist upload could not be stored temporarily.");
            }
            Some(path)
        }
        None => None,
    };
    let wordlist_size = wordlist_path
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.len());
    let hashlist_path: Option<PathBuf> = match hashlist_text {
        Some(text) => {
            let path = temp_dir.path().join(format!("{job_id}-hashlist.txt"));
            if std::fs::write(&path, &text).is_err() {
                return bad_request("Invalid hashlist: the upload could not be stored temporarily.");
            }
            Some(path)
        }
        None => None,
    };

    let params = match mode {
        "dictionary" => RunParams::Dictionary {
            wordlist: wordlist_path.clone().expect("dictionary needs wordlist"),
            wordlist_size: wordlist_size.unwrap_or(0),
            rules_name: rules_name.to_string(),
        },
        _ => RunParams::BruteForce {
            charset: charset.expect("brute force has charset"),
            min_length,
            max_length,
        },
    };

    let job = Arc::new(Job {
        id: job_id,
        state: Mutex::new(STATE_VALIDATING.to_string()),
        mode,
        algorithm,
        target_hash,
        salt,
        workers,
        budget,
        total_space,
        attempts: AtomicU64::new(0),
        elapsed_ms: AtomicI64::new(0),
        result: Mutex::new(None),
        error: Mutex::new(None),
        control: Control::new(),
        params: Mutex::new(params),
        targets,
        plaintext_withheld,
        started_at: hc_history::utc_now(),
        wordlist_path: Mutex::new(wordlist_path),
        hashlist_path: Mutex::new(hashlist_path),
        resume: Mutex::new(None),
        thread: Mutex::new(None),
    });

    // A restored paused job in the slot is silently abandoned.
    {
        let mut slot = state.jobs.slot.lock().expect("job slot");
        if let Some(existing) = slot.as_ref() {
            let existing_state = existing.state.lock().expect("job state").clone();
            if Job::is_active(&existing_state) {
                return conflict();
            }
        }
        abandon_restored(&state, &mut slot);
        *slot = Some(Arc::clone(&job));
    }

    // Spawn the runner thread (the engine is sync).
    let runner_job = Arc::clone(&job);
    let db_path = state.jobs.db_path.clone();
    let paused_dir = state.jobs.paused_dir.clone();
    let handle = std::thread::spawn(move || {
        execute_job(runner_job, db_path, paused_dir, Some(temp_dir));
    });
    *job.thread.lock().expect("thread slot") = Some(handle);

    (
        StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({ "job_id": job.id, "state": STATE_VALIDATING })),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

fn too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(serde_json::json!({
            "error": "The wordlist upload exceeds the 256 MiB limit."
        })),
    )
        .into_response()
}

fn conflict() -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": "Another dashboard audit is already running. Cancel it or wait for it to finish."
        })),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": "Unknown job ID." })),
    )
        .into_response()
}

/// `GET /api/audits/<job_id>` — polling payload.
pub async fn poll_audit(
    State(state): State<SharedState>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    let job = {
        let slot = state.jobs.slot.lock().expect("job slot");
        match slot.as_ref().filter(|job| job.id == job_id) {
            Some(job) => Arc::clone(job),
            None => return not_found(),
        }
    };
    let state_str = job.state.lock().expect("job state").clone();
    let mut payload = serde_json::json!({
        "job_id": job.id,
        "state": state_str,
        "mode": job.mode,
        "algorithm": job.algorithm,
        "workers": job.workers,
        "attempts": job.attempts.load(Ordering::SeqCst),
        "elapsed_ms": job.elapsed_ms.load(Ordering::SeqCst),
        "budget": job.budget,
    });
    if let Some(result) = job.result.lock().expect("job result").clone() {
        payload["result"] = result;
    }
    if let Some(error) = job.error.lock().expect("job error").clone() {
        payload["error"] = serde_json::Value::String(error);
    }
    axum::Json(payload).into_response()
}

/// `POST /api/audits/<job_id>/pause`.
pub async fn pause_audit(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    let job = {
        let slot = state.jobs.slot.lock().expect("job slot");
        match slot.as_ref().filter(|job| job.id == job_id) {
            Some(job) => Arc::clone(job),
            None => return not_found(),
        }
    };
    let state_str = job.state.lock().expect("job state").clone();
    if state_str != STATE_RUNNING {
        return bad_request("Only a running job can be paused.");
    }
    job.control.paused.store(true, Ordering::SeqCst);
    (
        StatusCode::ACCEPTED,
        axum::Json(serde_json::json!({
            "job_id": job.id,
            "state": STATE_RUNNING,
            "pausing": true
        })),
    )
        .into_response()
}

/// `POST /api/audits/<job_id>/resume`.
pub async fn resume_audit(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    let job = {
        let slot = state.jobs.slot.lock().expect("job slot");
        match slot.as_ref().filter(|job| job.id == job_id) {
            Some(job) => Arc::clone(job),
            None => return not_found(),
        }
    };
    let state_str = job.state.lock().expect("job state").clone();
    if state_str != STATE_PAUSED {
        return bad_request("Only a paused job can be resumed.");
    }
    // Validate the stored params against the current filesystem.
    if let Err(message) = validate_resume_params(&job.params.lock().expect("job params")) {
        return bad_request(&message);
    }
    // Delete the sidecar record; uploads stay in the paused dir until a
    // terminal outcome deletes them.
    let sidecar = state.jobs.paused_dir.join(format!("{}.json", job.id));
    let _ = std::fs::remove_file(&sidecar);

    job.control.paused.store(false, Ordering::SeqCst);
    *job.state.lock().expect("job state") = STATE_RUNNING.to_string();

    let runner_job = Arc::clone(&job);
    let db_path = state.jobs.db_path.clone();
    let paused_dir = state.jobs.paused_dir.clone();
    let handle = std::thread::spawn(move || {
        execute_job(runner_job, db_path, paused_dir, None);
    });
    *job.thread.lock().expect("thread slot") = Some(handle);

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "job_id": job.id,
            "state": STATE_RUNNING,
            "resumed": true
        })),
    )
        .into_response()
}

/// `POST /api/audits/<job_id>/cancel`.
pub async fn cancel_audit(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    if let Some(response) = csrf_check(&headers, &request_host(&headers)) {
        return response;
    }
    let job = {
        let slot = state.jobs.slot.lock().expect("job slot");
        match slot.as_ref().filter(|job| job.id == job_id) {
            Some(job) => Arc::clone(job),
            None => return not_found(),
        }
    };
    let has_thread = job.thread.lock().expect("thread slot").is_some();
    let state_str = job.state.lock().expect("job state").clone();
    if Job::is_active(&state_str) && has_thread {
        job.control.cancelled.store(true, Ordering::SeqCst);
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "job_id": job.id,
                "state": state_str,
                "cancelling": true
            })),
        )
            .into_response();
    }
    // Threadless (paused or restored) job: finalize synchronously.
    finalize_cancelled_paused(&state, &job);
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "job_id": job.id, "state": "cancelled" })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn validate_resume_params(params: &RunParams) -> Result<(), String> {
    match params {
        RunParams::Dictionary {
            wordlist,
            wordlist_size,
            ..
        } => {
            if !wordlist.is_file() {
                return Err("The uploaded wordlist is gone; re-start the audit.".to_string());
            }
            let current = std::fs::metadata(wordlist)
                .map(|meta| meta.len())
                .unwrap_or(*wordlist_size);
            if current != *wordlist_size {
                return Err("The wordlist changed since the pause; resume is refused.".to_string());
            }
            Ok(())
        }
        RunParams::BruteForce {
            charset,
            min_length,
            max_length,
        } => {
            if charset.is_empty()
                || hc_core::bruteforce::resolve_charset(charset).is_err()
                || *min_length < 1
                || *max_length < *min_length
            {
                return Err("Stored brute-force params are invalid.".to_string());
            }
            Ok(())
        }
    }
}

/// Build the candidate source for a job (with optional resume skip).
fn build_source(job: &Job) -> Result<(Source, Option<u128>), String> {
    let params = job.params.lock().expect("job params").clone();
    match &params {
        RunParams::Dictionary {
            wordlist,
            rules_name,
            ..
        } => {
            let dict = DictionarySource::open(wordlist).map_err(|e| e.0)?;
            let mut total_space = DictionarySource::count_lines(wordlist).map(|n| n as u128);
            let mut source = Source::Dictionary(dict);
            if rules_name != "none" {
                let variants_for = resolve_rules_preset(rules_name).map_err(|e| e.0)?;
                let budget = job.budget.ok_or_else(|| {
                    "Stored rule-expansion budget is invalid.".to_string()
                })?;
                if budget < 1 {
                    return Err("Stored rule-expansion budget is invalid.".to_string());
                }
                total_space = None;
                source = Source::Rules(
                    Box::new(RuleExpander::new(variants_for, budget)),
                    Box::new(source),
                );
            }
            Ok((source, total_space))
        }
        RunParams::BruteForce {
            charset,
            min_length,
            max_length,
        } => {
            let (alphabet, space) = hc_core::bruteforce::validate_bruteforce_options(
                *min_length,
                *max_length,
                job.budget.unwrap_or(1),
                Some(charset.clone()),
            )
            .map_err(|_| "Stored brute-force params are invalid.".to_string())?;
            Ok((
                Source::BruteForce(BruteforceSource::new(alphabet, *min_length, *max_length)),
                Some(space),
            ))
        }
    }
}

/// Execute (or continue) a job in a background thread; persists the outcome.
fn execute_job(
    job: Arc<Job>,
    db_path: PathBuf,
    paused_dir: PathBuf,
    _temp_dir: Option<tempfile::TempDir>,
) {
    *job.state.lock().expect("job state") = STATE_RUNNING.to_string();

    let (mut source, _source_total_space) = match build_source(&job) {
        Ok(outcome) => outcome,
        Err(message) => {
            *job.error.lock().expect("job error") = Some(message);
            *job.result.lock().expect("job result") = Some(serde_json::json!({
                "status": "interrupted",
                "attempts": job.attempts.load(Ordering::SeqCst),
                "elapsed_ms": job.elapsed_ms.load(Ordering::SeqCst),
            }));
            *job.state.lock().expect("job state") = "interrupted".to_string();
            return;
        }
    };
    let attempts_ref = &job.attempts;
    let elapsed_ref = &job.elapsed_ms;
    let progress = |attempts: u64, elapsed_ms: i64, _fraction: Option<f64>| {
        attempts_ref.store(attempts, Ordering::SeqCst);
        elapsed_ref.store(elapsed_ms, Ordering::SeqCst);
    };

    let resume_state = job.resume.lock().expect("job resume").clone();
    let control = Arc::clone(&job.control);

    let outcome = if let Some(targets) = &job.targets {
        let result = engine::run_hashlist_audit(
            HashlistOptions {
                workers: job.workers,
                budget: job.budget,
                total_space: job.total_space,
                resume: resume_state,
            },
            targets,
            &mut source,
            &control,
            Some(&progress),
        );
        EngineOutcome::Hashlist(result)
    } else {
        let format = formats::format_by_name(job.algorithm.expect("single target algorithm"))
            .expect("registry algorithm");
        let result = engine::run_audit(
            engine::AuditOptions {
                format,
                target: job.target_hash.as_deref().expect("target hash"),
                salt: job.salt.as_deref(),
                workers: job.workers,
                budget: job.budget,
                total_space: job.total_space,
                resume: resume_state,
            },
            &mut source,
            &control,
            Some(&progress),
        );
        EngineOutcome::Single(result)
    };

    match outcome {
        EngineOutcome::Single(result) => {
            if result.status == STATUS_PAUSED {
                if let Some(resume) = result.resume {
                    persist_paused(&job, paused_dir, &resume);
                    *job.resume.lock().expect("job resume") = Some(resume);
                    *job.state.lock().expect("job state") = STATE_PAUSED.to_string();
                    // Drop the runner thread handle: the job is threadless now.
                    *job.thread.lock().expect("thread slot") = None;
                    return;
                }
            }
            finalize_terminal_single(&job, db_path, result);
        }
        EngineOutcome::Hashlist(result) => {
            if result.status == STATUS_PAUSED {
                if let Some(resume) = result.resume {
                    persist_paused(&job, paused_dir, &resume);
                    *job.resume.lock().expect("job resume") = Some(resume);
                    *job.state.lock().expect("job state") = STATE_PAUSED.to_string();
                    *job.thread.lock().expect("thread slot") = None;
                    return;
                }
            }
            finalize_terminal_hashlist(&job, db_path, result);
        }
    }
}

enum EngineOutcome {
    Single(engine::RunResult),
    Hashlist(engine::HashlistResult),
}

/// Move uploads into the paused dir and write the sidecar record.
fn persist_paused(job: &Arc<Job>, paused_dir: PathBuf, resume: &ResumeState) {
    let _ = std::fs::create_dir_all(&paused_dir);
    let moved_wordlist = job
        .wordlist_path
        .lock()
        .expect("wordlist path")
        .as_ref()
        .and_then(|path| {
            let target = paused_dir.join(path.file_name()?);
            std::fs::rename(path, &target).ok()?;
            Some(target)
        });
    let moved_hashlist = job
        .hashlist_path
        .lock()
        .expect("hashlist path")
        .as_ref()
        .and_then(|path| {
            let target = paused_dir.join(path.file_name()?);
            std::fs::rename(path, &target).ok()?;
            Some(target)
        });
    // Keep the job pointing at the moved files so resume/terminal cleanup
    // finds them.
    if let Some(path) = &moved_wordlist {
        *job.wordlist_path.lock().expect("wordlist path") = Some(path.clone());
        if let RunParams::Dictionary { wordlist, .. } =
            &mut *job.params.lock().expect("job params")
        {
            *wordlist = path.clone();
        }
    }
    if let Some(path) = &moved_hashlist {
        *job.hashlist_path.lock().expect("hashlist path") = Some(path.clone());
    }
    let run_params = match &*job.params.lock().expect("job params") {
        RunParams::Dictionary {
            wordlist,
            wordlist_size,
            rules_name,
        } => serde_json::json!({
            "wordlist": wordlist.display().to_string(),
            "wordlist_size": wordlist_size,
            "rules_name": rules_name,
        }),
        RunParams::BruteForce {
            charset,
            min_length,
            max_length,
        } => serde_json::json!({
            "charset": charset,
            "min_length": min_length,
            "max_length": max_length,
        }),
    };
    let targets_json = job.targets.as_ref().map(|targets| {
        serde_json::Value::Array(
            targets
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id, "algorithm": t.algorithm,
                        "hash": t.hash, "line": t.line,
                    })
                })
                .collect(),
        )
    });
    let record = serde_json::json!({
        "job_id": job.id,
        "target_hash": job.target_hash,
        "algorithm": job.algorithm,
        "mode": job.mode,
        "workers": job.workers,
        "budget": job.budget,
        "salt": job.salt,
        "run_params": run_params,
        "resume_state": {
            "attempts_base": resume.attempts_base,
            "skip_source": resume.skip_source,
            "matched_plaintext": resume.matched_plaintext,
            "matched_attempt": resume.matched_attempt,
        },
        "targets": targets_json,
        "plaintext_withheld": job.plaintext_withheld,
        "started_at": job.started_at,
        "attempts": job.attempts.load(Ordering::SeqCst),
        "elapsed_ms": job.elapsed_ms.load(Ordering::SeqCst),
        "temp_path": moved_wordlist.as_ref().map(|p| p.display().to_string()),
        "temp_hashlist": moved_hashlist.as_ref().map(|p| p.display().to_string()),
    });
    let _ = std::fs::write(
        paused_dir.join(format!("{}.json", job.id)),
        serde_json::to_string(&record).unwrap_or_default(),
    );
}

fn finalize_terminal_single(job: &Arc<Job>, db_path: PathBuf, result: engine::RunResult) {
    job.attempts.store(result.attempts, Ordering::SeqCst);
    job.elapsed_ms.store(result.elapsed_ms, Ordering::SeqCst);
    let store = Store::open(&db_path).ok();
    let mut persist_error = false;
    if let Some(store) = &store {
        let run = NewRun {
            target_hash: job.target_hash.clone().unwrap_or_default(),
            algorithm: job.algorithm.unwrap_or_default().to_string(),
            mode: job.mode.to_string(),
            status: result.status.to_string(),
            attempts: result.attempts as i64,
            elapsed_ms: result.elapsed_ms,
            worker_count: job.workers as i64,
            matched_plaintext: if job.plaintext_withheld || result.status != STATUS_MATCH {
                None
            } else {
                result.matched_plaintext.clone()
            },
            started_at: Some(job.started_at.clone()),
            completed_at: None,
            salt: job.salt.clone(),
            batch_id: None,
            plaintext_withheld: job.plaintext_withheld,
            backend: Some("rust".to_string()),
        };
        if store.record_run(&run).is_err() {
            persist_error = true;
        }
    } else {
        persist_error = true;
    }
    let result_value = serde_json::json!({
        "status": result.status,
        "attempts": result.attempts,
        "elapsed_ms": result.elapsed_ms,
        "workers": job.workers,
        "matched_plaintext": if job.plaintext_withheld || result.status != STATUS_MATCH {
            serde_json::Value::Null
        } else {
            result.matched_plaintext.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null)
        },
        "target_hash": job.target_hash,
        "plaintext_withheld": job.plaintext_withheld,
    });
    *job.result.lock().expect("job result") = Some(result_value);
    if persist_error {
        if result.status == STATUS_MATCH {
            *job.error.lock().expect("job error") = Some(
                "A match was found but it could not be recorded in local history (storage error); nothing is displayed.".to_string(),
            );
            *job.state.lock().expect("job state") = "storage_error".to_string();
        } else {
            *job.error.lock().expect("job error") = Some(
                "The run finished but could not be recorded in local history.".to_string(),
            );
            *job.state.lock().expect("job state") = result.status.to_string();
        }
    } else {
        *job.error.lock().expect("job error") = None;
        *job.state.lock().expect("job state") = result.status.to_string();
    }
    *job.thread.lock().expect("thread slot") = None;
    // Terminal: delete the temp uploads.
    let wordlist = job.wordlist_path.lock().expect("wordlist path").take();
    let hashlist = job.hashlist_path.lock().expect("hashlist path").take();
    if let Some(path) = wordlist {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = hashlist {
        let _ = std::fs::remove_file(path);
    }
}

fn finalize_terminal_hashlist(job: &Arc<Job>, db_path: PathBuf, result: engine::HashlistResult) {
    job.attempts.store(result.attempts, Ordering::SeqCst);
    job.elapsed_ms.store(result.elapsed_ms, Ordering::SeqCst);
    let store = Store::open(&db_path).ok();
    let mut persist_error = false;
    let mut batch_id: Option<String> = None;
    if let Some(store) = &store {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let batch = NewBatch {
            batch_id: id.clone(),
            mode: job.mode.to_string(),
            status: result.status.to_string(),
            attempts: result.attempts as i64,
            elapsed_ms: result.elapsed_ms,
            worker_count: job.workers as i64,
            started_at: Some(job.started_at.clone()),
            target_count: result.targets.len() as i64,
        };
        if store.record_batch(&batch).is_err() {
            persist_error = true;
        } else {
            batch_id = Some(id.clone());
        }
        for t in &result.targets {
            let run = NewRun {
                target_hash: t.hash.clone(),
                algorithm: t.algorithm.to_string(),
                mode: job.mode.to_string(),
                status: t.status.to_string(),
                attempts: t.match_at_attempt.unwrap_or(result.attempts) as i64,
                elapsed_ms: result.elapsed_ms,
                worker_count: job.workers as i64,
                matched_plaintext: if job.plaintext_withheld {
                    None
                } else {
                    t.matched_plaintext.clone()
                },
                started_at: Some(job.started_at.clone()),
                completed_at: None,
                salt: None,
                batch_id: Some(id.clone()),
                plaintext_withheld: job.plaintext_withheld,
                backend: Some("rust".to_string()),
            };
            if store.record_run(&run).is_err() {
                persist_error = true;
            }
        }
    } else {
        persist_error = true;
    }
    let targets_json: Vec<serde_json::Value> = result
        .targets
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "algorithm": t.algorithm,
                "hash": t.hash,
                "status": t.status,
                "matched_plaintext": t.matched_plaintext,
                "match_at_attempt": t.match_at_attempt,
                "plaintext_withheld": job.plaintext_withheld,
            })
        })
        .collect();
    let mut result_value = serde_json::json!({
        "status": result.status,
        "attempts": result.attempts,
        "elapsed_ms": result.elapsed_ms,
        "workers": job.workers,
        "matched_plaintext": serde_json::Value::Null,
        "target_hash": serde_json::Value::Null,
        "targets": targets_json,
        "plaintext_withheld": job.plaintext_withheld,
    });
    if let Some(id) = &batch_id {
        result_value["batch_id"] = serde_json::Value::String(id[..8].to_string());
    }
    *job.result.lock().expect("job result") = Some(result_value);
    if persist_error {
        *job.error.lock().expect("job error") = Some(
            "The hashlist run finished but could not be recorded in local history.".to_string(),
        );
    } else {
        *job.error.lock().expect("job error") = None;
    }
    *job.state.lock().expect("job state") = result.status.to_string();
    *job.thread.lock().expect("thread slot") = None;
    let wordlist = job.wordlist_path.lock().expect("wordlist path").take();
    let hashlist = job.hashlist_path.lock().expect("hashlist path").take();
    if let Some(path) = wordlist {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = hashlist {
        let _ = std::fs::remove_file(path);
    }
}

/// Cancel a threadless (paused/restored) job: finalise as cancelled, delete
/// the sidecar and uploads.
fn finalize_cancelled_paused(state: &SharedState, job: &Arc<Job>) {
    let attempts = job.attempts.load(Ordering::SeqCst);
    let elapsed_ms = job.elapsed_ms.load(Ordering::SeqCst);
    *job.result.lock().expect("job result") = Some(serde_json::json!({
        "status": "cancelled",
        "attempts": attempts,
        "elapsed_ms": elapsed_ms,
    }));
    *job.error.lock().expect("job error") = None;
    *job.state.lock().expect("job state") = "cancelled".to_string();
    let sidecar = state.jobs.paused_dir.join(format!("{}.json", job.id));
    let _ = std::fs::remove_file(&sidecar);
    let wordlist = job.wordlist_path.lock().expect("wordlist path").take();
    let hashlist = job.hashlist_path.lock().expect("hashlist path").take();
    if let Some(path) = wordlist {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = hashlist {
        let _ = std::fs::remove_file(path);
    }
    *job.thread.lock().expect("thread slot") = None;
}

/// Drop a restored paused job from the slot without recording anything.
fn abandon_restored(state: &SharedState, slot: &mut Option<Arc<Job>>) {
    if let Some(job) = slot.take() {
        let state_str = job.state.lock().expect("job state").clone();
        if state_str == STATE_PAUSED {
            let sidecar = state.jobs.paused_dir.join(format!("{}.json", job.id));
            let _ = std::fs::remove_file(&sidecar);
            // Uploads are deleted together with the abandoned record.
            let wordlist = job.wordlist_path.lock().expect("wordlist path").take();
            let hashlist = job.hashlist_path.lock().expect("hashlist path").take();
            if let Some(path) = wordlist {
                let _ = std::fs::remove_file(path);
            }
            if let Some(path) = hashlist {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Startup recovery: restore the newest paused-job record; delete records
/// older than the retention window (keeping the newest).
pub fn restore_paused_jobs(state: &SharedState) {
    let _ = std::fs::create_dir_all(&state.jobs.paused_dir);
    let mut records: Vec<(PathBuf, serde_json::Value)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.jobs.paused_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        records.push((path, value));
                    }
                }
            }
        }
    }
    // Newest first by started_at.
    records.sort_by(|a, b| {
        let key = |item: &serde_json::Value| {
            item.get("started_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        key(&b.1).cmp(&key(&a.1))
    });
    let now = time::OffsetDateTime::now_utc();
    for (index, (path, record)) in records.iter().enumerate() {
        let started_at = record
            .get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let stale = parse_started_at(started_at)
            .map(|parsed| {
                (now - parsed).whole_days() > PAUSED_JOB_RETENTION_DAYS as i64
            })
            .unwrap_or(false);
        if index > 0 && stale {
            let _ = std::fs::remove_file(path);
            for key in ["temp_path", "temp_hashlist"] {
                if let Some(artifact) = record.get(key).and_then(|v| v.as_str()) {
                    let _ = std::fs::remove_file(artifact);
                }
            }
        }
    }
    if let Some((_path, record)) = records.first() {
        if let Some(job) = restore_job_from_record(record) {
            *state.jobs.slot.lock().expect("job slot") = Some(Arc::new(job));
        }
    }
}

fn parse_started_at(value: &str) -> Option<time::OffsetDateTime> {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time::OffsetDateTime::parse(value, &format).ok()
}

fn restore_job_from_record(record: &serde_json::Value) -> Option<Job> {
    let job_id = record.get("job_id")?.as_str()?.to_string();
    let mode = match record.get("mode")?.as_str()? {
        "dictionary" => "dictionary",
        "brute-force" => "brute-force",
        _ => return None,
    };
    let params = match mode {
        "dictionary" => {
            let run_params = record.get("run_params")?;
            RunParams::Dictionary {
                wordlist: PathBuf::from(run_params.get("wordlist")?.as_str()?),
                wordlist_size: run_params.get("wordlist_size")?.as_u64()?,
                rules_name: run_params
                    .get("rules_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none")
                    .to_string(),
            }
        }
        _ => {
            let run_params = record.get("run_params")?;
            RunParams::BruteForce {
                charset: run_params.get("charset")?.as_str()?.to_string(),
                min_length: run_params.get("min_length")?.as_u64()?,
                max_length: run_params.get("max_length")?.as_u64()?,
            }
        }
    };
    let resume = {
        let state = record.get("resume_state")?;
        ResumeState {
            attempts_base: state.get("attempts_base")?.as_u64()?,
            skip_source: state.get("skip_source")?.as_u64()?,
            matched_plaintext: state
                .get("matched_plaintext")
                .and_then(|v| v.as_array())
                .map(|pairs| {
                    pairs
                        .iter()
                        .filter_map(|pair| {
                            let id = pair.get(0)?.as_u64()? as usize;
                            let text = pair.get(1)?.as_str()?.to_string();
                            Some((id, text))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            matched_attempt: state
                .get("matched_attempt")
                .and_then(|v| v.as_array())
                .map(|pairs| {
                    pairs
                        .iter()
                        .filter_map(|pair| {
                            let id = pair.get(0)?.as_u64()? as usize;
                            let attempt = pair.get(1)?.as_u64()?;
                            Some((id, attempt))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    };
    let algorithm = record
        .get("algorithm")
        .and_then(|v| v.as_str())
        .and_then(formats::format_by_name)
        .map(|f| f.name);
    Some(Job {
        id: job_id,
        state: Mutex::new(STATE_PAUSED.to_string()),
        mode,
        algorithm,
        target_hash: record
            .get("target_hash")
            .and_then(|v| v.as_str())
            .map(String::from),
        salt: record.get("salt").and_then(|v| v.as_str()).map(String::from),
        workers: record.get("workers").and_then(|v| v.as_u64()).unwrap_or(4) as usize,
        budget: record.get("budget").and_then(|v| v.as_u64()),
        total_space: None,
        attempts: AtomicU64::new(record.get("attempts").and_then(|v| v.as_u64()).unwrap_or(0)),
        elapsed_ms: AtomicI64::new(
            record
                .get("elapsed_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
        ),
        result: Mutex::new(None),
        error: Mutex::new(None),
        control: Control::new(),
        params: Mutex::new(params),
        targets: None, // restored hashlists resume from the sidecar's run_params
        plaintext_withheld: record
            .get("plaintext_withheld")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        started_at: record
            .get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        wordlist_path: Mutex::new(
            record
                .get("temp_path")
                .and_then(|v| v.as_str())
                .map(PathBuf::from),
        ),
        hashlist_path: Mutex::new(
            record
                .get("temp_hashlist")
                .and_then(|v| v.as_str())
                .map(PathBuf::from),
        ),
        resume: Mutex::new(Some(resume)),
        thread: Mutex::new(None),
    })
}
