//! Audit engine: bounded worker threads, candidate-level attempt accounting,
//! budget/pause/cancel semantics, single-target and hashlist loops, and
//! resume offsets — mirroring `src/hash_cracker/engine.py`.
//!
//! Accounting contract (pinned by specs/003-rust-backend/contracts/api.md):
//! - `attempts` counts individual candidates.
//! - Per completed batch: `attempts = max(attempts, offset + batch_size)`.
//! - On a match (single target): `attempts = offset + match_index + 1`
//!   exactly (the match freezes accounting; later batches are not counted).
//! - Hashlist all-matched: `attempts = max(matched_attempt.values())`.
//! - `budget_exhausted` only when the run stopped at the budget with space
//!   remaining (`budget_is_limit`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crossbeam_channel::RecvTimeoutError;
use std::time::{Duration, Instant};

use crate::candidates::DEFAULT_BATCH_SIZE;
use crate::formats::Format;
use crate::hashing;

// Status strings (contract-pinned; identical to the Python backend).
pub const STATUS_MATCH: &str = "match";
pub const STATUS_NO_MATCH: &str = "no_match";
pub const STATUS_CANCELLED: &str = "cancelled";
pub const STATUS_BUDGET_EXHAUSTED: &str = "budget_exhausted";
pub const STATUS_PAUSED: &str = "paused";
pub const STATUS_INTERRUPTED: &str = "interrupted";
pub const STATUS_INVALID_INPUT: &str = "invalid_input";
pub const STATUS_STORAGE_ERROR: &str = "storage_error";

/// Default candidate budget (pinned).
pub const DEFAULT_BUDGET: u64 = 1_000_000;

/// A per-candidate hasher returning raw digest bytes.
pub type CandidateHasher = Box<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

pub const MIN_WORKERS: usize = 1;
pub const MAX_WORKERS: usize = 8;
pub const DEFAULT_WORKERS: usize = 4;
const OUTSTANDING_FACTOR: usize = 2;

/// Cooperative stop flags shared with the caller (pause/cancel/interrupt).
#[derive(Default)]
pub struct Control {
    pub cancelled: AtomicBool,
    pub paused: AtomicBool,
    pub interrupted: AtomicBool,
}

impl Control {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn any_stop(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
            || self.paused.load(Ordering::SeqCst)
            || self.interrupted.load(Ordering::SeqCst)
    }

    fn stop_status(&self) -> &'static str {
        if self.interrupted.load(Ordering::SeqCst) {
            STATUS_INTERRUPTED
        } else if self.cancelled.load(Ordering::SeqCst) {
            STATUS_CANCELLED
        } else {
            STATUS_PAUSED
        }
    }
}

/// Resume offset state produced on pause (consumed by the next run segment).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResumeState {
    /// Candidates already examined (attempt count at pause).
    pub attempts_base: u64,
    /// Candidates already pulled from the source (skipped on resume).
    pub skip_source: u64,
    /// Hashlist only: target id -> matched plaintext (ids sorted).
    pub matched_plaintext: Vec<(usize, String)>,
    /// Hashlist only: target id -> attempt number of the match (ids sorted,
    /// same id order as `matched_plaintext`).
    pub matched_attempt: Vec<(usize, u64)>,
}

/// Terminal result of one engine run segment.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub status: &'static str,
    pub attempts: u64,
    pub elapsed_ms: i64,
    pub matched_plaintext: Option<String>,
    /// Present only when the run ended paused.
    pub resume: Option<ResumeState>,
}

/// Per-target result inside a hashlist run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetResult {
    pub id: usize,
    pub algorithm: &'static str,
    pub hash: String,
    /// `match` | `no_match` | `paused`.
    pub status: &'static str,
    pub matched_plaintext: Option<String>,
    pub match_at_attempt: Option<u64>,
}

pub struct HashlistResult {
    pub status: &'static str,
    pub attempts: u64,
    pub elapsed_ms: i64,
    pub targets: Vec<TargetResult>,
    pub resume: Option<ResumeState>,
}

/// Progress hook: `(attempts, elapsed_ms, fraction)` — fraction is `None`
/// when the total space is unknown. The caller throttles rendering.
pub type ProgressFn<'a> = &'a (dyn Fn(u64, i64, Option<f64>) + Send + Sync);

/// A batch-producing candidate stream (dictionary, brute force, or
/// rule-expanded). The engine skips `resume.skip_source` candidates first.
pub trait CandidateStream {
    fn next_batch(&mut self, max: usize) -> Option<Vec<String>>;
}

/// Options for a single-target audit.
pub struct AuditOptions<'a> {
    pub format: &'static Format,
    /// Normalized target: lowercase hex digest, or the full adaptive string.
    pub target: &'a str,
    pub salt: Option<&'a str>,
    pub workers: usize,
    pub budget: Option<u64>,
    pub total_space: Option<u128>,
    pub resume: Option<ResumeState>,
}

/// Options for a hashlist audit.
pub struct HashlistOptions {
    pub workers: usize,
    pub budget: Option<u64>,
    pub total_space: Option<u128>,
    pub resume: Option<ResumeState>,
}

enum Outcome {
    Single {
        offset: u64,
        hit: Option<(usize, String)>,
    },
    Hashlist {
        offset: u64,
        hits: Vec<(usize, usize, String)>, // (batch idx, target id, candidate)
    },
}

enum TargetCtx {
    Fast {
        expected: Vec<u8>,
        compare_len: usize,
        hasher: CandidateHasher,
    },
    Adaptive {
        format_name: &'static str,
        stored: String,
    },
}

impl TargetCtx {
    fn build(format: &'static Format, target: &str, salt: Option<&str>) -> Option<Self> {
        if format.is_adaptive() {
            return Some(TargetCtx::Adaptive {
                format_name: format.name,
                stored: target.to_string(),
            });
        }
        // 16-hex LM targets compare the first DES half only (hashcat mode
        // 3000 semantics).
        let compare_len = if format.name == "lm" && target.len() == 16 {
            8
        } else {
            target.len() / 2
        };
        let expected = hex_decode(target);
        if expected.is_empty() {
            return None;
        }
        let hasher: CandidateHasher = match format.name {
            "ntlm" => Box::new(|c: &str| hex_decode(&hashing::ntlm_hex(c))),
            "lm" => Box::new(|c: &str| hashing::lm_raw(c).to_vec()),
            _ if format.is_salted() => {
                let base = format.base?;
                let salt_first = format.salt_first?;
                let salt = salt.map(String::from);
                Box::new(move |c: &str| {
                    let data = salted_data(c, salt.as_deref(), salt_first);
                    hex_decode(&hashing::hex_digest(base, &data).unwrap_or_default())
                })
            }
            _ => {
                let name = format.name;
                Box::new(move |c: &str| {
                    hex_decode(&hashing::hex_digest(name, c.as_bytes()).unwrap_or_default())
                })
            }
        };
        Some(TargetCtx::Fast {
            expected,
            compare_len,
            hasher,
        })
    }
}

fn salted_data(pass: &str, salt: Option<&str>, salt_first: bool) -> Vec<u8> {
    let salt = salt.unwrap_or("");
    let mut data = if salt_first {
        salt.as_bytes().to_vec()
    } else {
        pass.as_bytes().to_vec()
    };
    let tail = if salt_first {
        pass.as_bytes()
    } else {
        salt.as_bytes()
    };
    data.extend_from_slice(tail);
    data
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_default()
}

/// Skip the first `skip_source` candidates from a freshly-opened stream
/// (resume semantics: read-and-discard).
fn skip_candidates(stream: &mut dyn CandidateStream, mut remaining: u64) {
    while remaining > 0 {
        let Some(batch) = stream.next_batch(DEFAULT_BATCH_SIZE) else {
            return;
        };
        if (batch.len() as u64) <= remaining {
            remaining -= batch.len() as u64;
        } else {
            return; // tail beyond the skip window
        }
    }
}

fn max_outstanding(workers: usize) -> usize {
    (workers * OUTSTANDING_FACTOR).max(4)
}

/// Single-target audit over the given candidate stream.
pub fn run_audit(
    options: AuditOptions<'_>,
    stream: &mut dyn CandidateStream,
    control: &Arc<Control>,
    progress: Option<ProgressFn<'_>>,
) -> RunResult {
    let started = Instant::now();
    let workers = options.workers.clamp(MIN_WORKERS, MAX_WORKERS);
    let resume = options.resume.clone().unwrap_or_default();
    let budget_is_limit = options
        .budget
        .is_some_and(|b| options.total_space.is_none_or(|space| space > b as u128));
    // Python computes the remaining budget once (budget - attempts_base) and
    // truncates submissions against `submitted`, not re-computed attempts.
    let budget_remaining = options.budget.map(|b| b.saturating_sub(resume.attempts_base));

    let ctx = match TargetCtx::build(options.format, options.target, options.salt) {
        Some(ctx) => Arc::new(ctx),
        None => {
            return RunResult {
                status: STATUS_INVALID_INPUT,
                attempts: 0,
                elapsed_ms: 0,
                matched_plaintext: None,
                resume: None,
            };
        }
    };

    skip_candidates(stream, resume.skip_source);

    let (task_tx, task_rx) = crossbeam_channel::bounded::<(u64, Vec<String>)>(16);
    let (result_tx, result_rx) = crossbeam_channel::unbounded::<Outcome>();
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let task_rx = task_rx.clone();
        let result_tx = result_tx.clone();
        let ctx = Arc::clone(&ctx);
        handles.push(std::thread::spawn(move || {
            while let Ok((offset, batch)) = task_rx.recv() {
                let mut hit = None;
                for (idx, candidate) in batch.iter().enumerate() {
                    if matches_candidate(&ctx, candidate) {
                        hit = Some((idx, candidate.clone()));
                        break;
                    }
                }
                if result_tx.send(Outcome::Single { offset, hit }).is_err() {
                    break;
                }
            }
        }));
    }
    drop(task_rx);
    drop(result_tx);

    let mut submitted: u64 = 0; // post-skip submissions this segment
    let mut consumed = resume.skip_source;
    let mut attempts = resume.attempts_base;
    let mut in_flight: Vec<(u64, u64)> = Vec::new(); // (offset, size)
    let mut source_done = false;
    let mut stopped = false;
    let mut budget_hit = false;
    let mut match_hit: Option<(u64, usize, String)> = None; // (offset, idx, candidate)
    let mut poll_ms = 10u64;

    loop {
        // Stop checks: pause/cancel/interrupt, or a match already found.
        if !stopped && (control.any_stop() || match_hit.is_some()) {
            stopped = true;
        }
        // Budget check precedes pulling the next batch (Python parity).
        if !stopped
            && !budget_hit
            && budget_remaining.is_some_and(|cap| submitted >= cap)
        {
            budget_hit = true;
        }

        // Submit while capacity, source, and budget allow.
        while !stopped
            && !source_done
            && in_flight.len() < max_outstanding(workers)
            && budget_remaining.is_none_or(|cap| submitted < cap)
        {
            match stream.next_batch(DEFAULT_BATCH_SIZE) {
                None => {
                    source_done = true;
                }
                Some(mut batch) => {
                    if let Some(cap) = budget_remaining {
                        batch.truncate((cap - submitted) as usize);
                    }
                    if batch.is_empty() {
                        source_done = true;
                        break;
                    }
                    let offset = consumed;
                    let size = batch.len() as u64;
                    consumed += size;
                    submitted += size;
                    if task_tx.send((offset, batch)).is_err() {
                        source_done = true;
                        break;
                    }
                    in_flight.push((offset, size));
                }
            }
        }

        if in_flight.is_empty() {
            break;
        }

        // Await results with an adaptive poll so stop flags stay responsive.
        let timeout = if stopped || source_done {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(poll_ms)
        };
        match result_rx.recv_timeout(timeout) {
            Ok(Outcome::Single { offset, hit }) => {
                poll_ms = 10;
                if let Some(pos) = in_flight.iter().position(|(o, _)| *o == offset) {
                    let size = in_flight.remove(pos).1;
                    if match_hit.is_none() {
                        attempts = attempts.max(offset + size);
                    }
                }
                if let Some((idx, candidate)) = hit {
                    if match_hit.is_none() {
                        match_hit = Some((offset, idx, candidate));
                    }
                }
                if let (Some(progress), false) = (progress, match_hit.is_some()) {
                    let fraction = options
                        .total_space
                        .map(|space| (attempts as f64 / space as f64).min(1.0));
                    progress(attempts, started.elapsed().as_millis() as i64, fraction);
                }
            }
            Ok(Outcome::Hashlist { .. }) => {
                // The single-target loop never receives hashlist outcomes.
            }
            Err(RecvTimeoutError::Timeout) => {
                poll_ms = (poll_ms * 2).min(250);
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    drop(task_tx);
    for handle in handles {
        let _ = handle.join();
    }

    let elapsed_ms = started.elapsed().as_millis() as i64;
    let (status, matched_plaintext, resume_out) = if let Some((offset, idx, candidate)) = match_hit
    {
        // A match freezes accounting at the matched candidate's position.
        attempts = offset + idx as u64 + 1;
        (
            STATUS_MATCH,
            Some(candidate),
            None,
        )
    } else if stopped {
        (
            control.stop_status(),
            None,
            Some(ResumeState {
                attempts_base: attempts,
                skip_source: consumed,
                ..Default::default()
            }),
        )
    } else if budget_is_limit && budget_hit {
        (STATUS_BUDGET_EXHAUSTED, None, None)
    } else {
        (STATUS_NO_MATCH, None, None)
    };

    RunResult {
        status,
        attempts,
        elapsed_ms,
        matched_plaintext,
        resume: resume_out,
    }
}

fn matches_candidate(ctx: &TargetCtx, candidate: &str) -> bool {
    match ctx {
        TargetCtx::Fast {
            expected,
            compare_len,
            hasher,
        } => {
            let digest = hasher(candidate);
            digest.len() >= *compare_len && digest[..*compare_len] == expected[..*compare_len]
        }
        TargetCtx::Adaptive {
            format_name,
            stored,
        } => crate::adaptive::verify_adaptive(format_name, candidate, stored),
    }
}

/// Hashlist audit: one shared candidate stream against many targets.
pub fn run_hashlist_audit(
    options: HashlistOptions,
    targets: &[crate::candidates::HashlistTarget],
    stream: &mut dyn CandidateStream,
    control: &Arc<Control>,
    progress: Option<ProgressFn<'_>>,
) -> HashlistResult {
    let started = Instant::now();
    let workers = options.workers.clamp(MIN_WORKERS, MAX_WORKERS);
    let resume = options.resume.unwrap_or_default();
    let budget_is_limit = options
        .budget
        .is_some_and(|b| options.total_space.is_none_or(|space| space > b as u128));
    // Python computes the remaining budget once (budget - attempts_base) and
    // truncates submissions against `submitted`, not re-computed attempts.
    let budget_remaining = options.budget.map(|b| b.saturating_sub(resume.attempts_base));

    // Per-algorithm digest maps; 16-hex LM targets compare the first DES half.
    let mut digest_maps: HashMap<&'static str, HashMap<String, Vec<usize>>> = HashMap::new();
    let mut lm_16_targets: Vec<(usize, [u8; 8])> = Vec::new();
    for target in targets {
        if resume.matched_attempt.iter().any(|(id, _)| id == &target.id) {
            continue; // matched in a prior segment
        }
        if target.algorithm == "lm" && target.hash.len() == 16 {
            if let Ok(first_half) = decode_8_bytes(&target.hash) {
                lm_16_targets.push((target.id, first_half));
            }
            continue;
        }
        digest_maps
            .entry(target.algorithm)
            .or_default()
            .entry(target.hash.clone())
            .or_default()
            .push(target.id);
    }
    let ctx = Arc::new(HashlistCtx {
        digest_maps,
        lm_16_targets,
    });

    skip_candidates(stream, resume.skip_source);

    let (task_tx, task_rx) = crossbeam_channel::bounded::<(u64, Vec<String>)>(16);
    let (result_tx, result_rx) = crossbeam_channel::unbounded::<Outcome>();
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let task_rx = task_rx.clone();
        let result_tx = result_tx.clone();
        let ctx = Arc::clone(&ctx);
        handles.push(std::thread::spawn(move || {
            while let Ok((offset, batch)) = task_rx.recv() {
                let mut hits = Vec::new();
                for (idx, candidate) in batch.iter().enumerate() {
                    for target_id in ctx.match_candidate(candidate) {
                        hits.push((idx, target_id, candidate.clone()));
                    }
                }
                if result_tx.send(Outcome::Hashlist { offset, hits }).is_err() {
                    break;
                }
            }
        }));
    }
    drop(task_rx);
    drop(result_tx);

    // Resumed matches (id-paired plaintext/attempt maps).
    let mut matched: HashMap<usize, (String, u64)> = HashMap::new();
    for (id, plaintext) in &resume.matched_plaintext {
        matched.insert(*id, (plaintext.clone(), 0));
    }
    for (id, attempt) in &resume.matched_attempt {
        matched.entry(*id).and_modify(|(_, a)| *a = *attempt);
    }

    let mut submitted: u64 = 0;
    let mut consumed = resume.skip_source;
    let mut attempts = resume.attempts_base;
    let mut in_flight: Vec<(u64, u64)> = Vec::new();
    let mut source_done = false;
    let mut stopped = false;
    let mut budget_hit = false;
    let mut poll_ms = 10u64;

    loop {
        if !stopped && control.any_stop() {
            stopped = true;
        }
        if matched.len() >= targets.len() {
            break; // every target matched
        }
        // Budget check precedes pulling the next batch (Python parity).
        if !stopped
            && !budget_hit
            && budget_remaining.is_some_and(|cap| submitted >= cap)
        {
            budget_hit = true;
        }

        while !stopped
            && !source_done
            && in_flight.len() < max_outstanding(workers)
            && budget_remaining.is_none_or(|cap| submitted < cap)
        {
            match stream.next_batch(DEFAULT_BATCH_SIZE) {
                None => {
                    source_done = true;
                }
                Some(mut batch) => {
                    if let Some(cap) = budget_remaining {
                        batch.truncate((cap - submitted) as usize);
                    }
                    if batch.is_empty() {
                        source_done = true;
                        break;
                    }
                    let offset = consumed;
                    let size = batch.len() as u64;
                    consumed += size;
                    submitted += size;
                    if task_tx.send((offset, batch)).is_err() {
                        source_done = true;
                        break;
                    }
                    in_flight.push((offset, size));
                }
            }
        }

        if in_flight.is_empty() {
            break;
        }

        let timeout = if stopped || source_done {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(poll_ms)
        };
        match result_rx.recv_timeout(timeout) {
            Ok(Outcome::Single { .. }) => {
                // The hashlist loop never receives single-target outcomes.
            }
            Ok(Outcome::Hashlist { offset, hits }) => {
                poll_ms = 10;
                if let Some(pos) = in_flight.iter().position(|(o, _)| *o == offset) {
                    let size = in_flight.remove(pos).1;
                    attempts = attempts.max(offset + size);
                }
                for (idx, target_id, candidate) in hits {
                    matched
                        .entry(target_id)
                        .or_insert((candidate, offset + idx as u64 + 1));
                }
                if let Some(progress) = progress {
                    let fraction = options
                        .total_space
                        .map(|space| (attempts as f64 / space as f64).min(1.0));
                    progress(attempts, started.elapsed().as_millis() as i64, fraction);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                poll_ms = (poll_ms * 2).min(250);
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    drop(task_tx);
    for handle in handles {
        let _ = handle.join();
    }

    let elapsed_ms = started.elapsed().as_millis() as i64;
    let all_matched = matched.len() >= targets.len();
    let status = if all_matched {
        STATUS_MATCH
    } else if stopped {
        control.stop_status()
    } else if budget_is_limit && budget_hit {
        STATUS_BUDGET_EXHAUSTED
    } else {
        STATUS_NO_MATCH
    };

    if all_matched {
        attempts = matched.values().map(|(_, a)| *a).max().unwrap_or(attempts);
    }

    let mut out_targets = Vec::with_capacity(targets.len());
    for target in targets {
        let entry = matched.get(&target.id);
        let target_status = if entry.is_some() {
            STATUS_MATCH
        } else if status == STATUS_PAUSED {
            STATUS_PAUSED
        } else {
            STATUS_NO_MATCH
        };
        out_targets.push(TargetResult {
            id: target.id,
            algorithm: target.algorithm,
            hash: target.hash.clone(),
            status: target_status,
            matched_plaintext: entry.map(|(p, _)| p.clone()),
            match_at_attempt: entry.map(|(_, a)| *a),
        });
    }

    let resume_out = if !all_matched && stopped {
        // Emit id-sorted paired maps so plaintexts and attempts stay aligned.
        let mut ids: Vec<usize> = matched.keys().copied().collect();
        ids.sort_unstable();
        Some(ResumeState {
            attempts_base: attempts,
            skip_source: consumed,
            matched_plaintext: ids
                .iter()
                .map(|id| (*id, matched[id].0.clone()))
                .collect(),
            matched_attempt: ids.iter().map(|id| (*id, matched[id].1)).collect(),
        })
    } else {
        None
    };

    HashlistResult {
        status,
        attempts,
        elapsed_ms,
        targets: out_targets,
        resume: resume_out,
    }
}

struct HashlistCtx {
    digest_maps: HashMap<&'static str, HashMap<String, Vec<usize>>>,
    lm_16_targets: Vec<(usize, [u8; 8])>,
}

impl HashlistCtx {
    fn match_candidate(&self, candidate: &str) -> Vec<usize> {
        let mut hits = Vec::new();
        let mut lm_digest: Option<String> = None;
        for (algorithm, map) in &self.digest_maps {
            let digest_hex = if *algorithm == "ntlm" {
                hashing::ntlm_hex(candidate)
            } else if *algorithm == "lm" {
                let digest = hashing::lm_hex(candidate);
                lm_digest = Some(digest.clone());
                digest
            } else if let Some(digest) = hashing::hex_digest(algorithm, candidate.as_bytes()) {
                digest
            } else {
                continue;
            };
            if let Some(ids) = map.get(&digest_hex) {
                hits.extend_from_slice(ids);
            }
        }
        // 16-hex LM targets compare the first DES half of the full digest.
        if !self.lm_16_targets.is_empty() {
            let digest_hex = lm_digest.get_or_insert_with(|| hashing::lm_hex(candidate));
            if digest_hex.len() == 32 {
                if let Ok(first) = decode_8_bytes(&digest_hex[..16]) {
                    for (id, expected) in &self.lm_16_targets {
                        if *expected == first && !hits.contains(id) {
                            hits.push(*id);
                        }
                    }
                }
            }
        }
        hits
    }
}

fn decode_8_bytes(hex16: &str) -> Result<[u8; 8], ()> {
    let bytes = hex::decode(hex16).map_err(|_| ())?;
    if bytes.len() != 8 {
        return Err(());
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidates::HashlistTarget;
    use crate::formats::format_by_name;
    use std::sync::Mutex;

    struct VecSource {
        batches: Vec<Vec<String>>,
        index: usize,
    }

    impl VecSource {
        fn flat(words: &[&str]) -> Self {
            Self {
                batches: vec![words.iter().map(|w| w.to_string()).collect()],
                index: 0,
            }
        }
    }

    impl CandidateStream for VecSource {
        fn next_batch(&mut self, max: usize) -> Option<Vec<String>> {
            if self.index >= self.batches.len() {
                return None;
            }
            let mut batch = self.batches[self.index].clone();
            batch.truncate(max);
            self.index += 1;
            Some(batch)
        }
    }

    /// Fixed-size chunk source to exercise multi-batch paths.
    struct ChunkSource {
        words: Vec<String>,
        chunk: usize,
        index: usize,
    }

    impl CandidateStream for ChunkSource {
        fn next_batch(&mut self, max: usize) -> Option<Vec<String>> {
            if self.index >= self.words.len() {
                return None;
            }
            let end = (self.index + max.min(self.chunk)).min(self.words.len());
            let batch = self.words[self.index..end].to_vec();
            self.index = end;
            Some(batch)
        }
    }

    fn md5(word: &str) -> String {
        hashing::hex_digest("md5", word.as_bytes()).unwrap()
    }

    #[test]
    fn match_attempt_math_is_candidate_level() {
        let words = ["alpha", "beta", "hashcat", "delta"];
        let mut stream = VecSource::flat(&words);
        let control = Control::new();
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("hashcat"),
                salt: None,
                workers: 2,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.attempts, 3); // offset 0 + idx 2 + 1
        assert_eq!(result.matched_plaintext.as_deref(), Some("hashcat"));
    }

    #[test]
    fn match_across_batches_stops_accounting() {
        // Match in batch 1; later batches must not inflate attempts.
        let words: Vec<String> = (0..30)
            .map(|i| if i == 12 { "hashcat".to_string() } else { format!("w{i:02}") })
            .collect();
        let mut stream = ChunkSource {
            words,
            chunk: 5,
            index: 0,
        };
        let control = Control::new();
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("hashcat"),
                salt: None,
                workers: 3,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.attempts, 13); // idx 12 within the stream
    }

    #[test]
    fn budget_truncation_ends_budget_exhausted() {
        let words: Vec<String> = (0..10).map(|i| format!("word{i}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 3,
            index: 0,
        };
        let control = Control::new();
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("not-present"),
                salt: None,
                workers: 2,
                budget: Some(4),
                total_space: Some(10),
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_BUDGET_EXHAUSTED);
        assert_eq!(result.attempts, 4);
    }

    #[test]
    fn full_space_coverage_ends_no_match() {
        // Space (4 words) <= budget: full coverage → no_match, not budget_exhausted.
        let words: Vec<String> = (0..4).map(|i| format!("w{i}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 2,
            index: 0,
        };
        let control = Control::new();
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("nope"),
                salt: None,
                workers: 1,
                budget: Some(10),
                total_space: Some(4),
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_NO_MATCH);
        assert_eq!(result.attempts, 4);
    }

    #[test]
    fn pause_before_submit_yields_empty_offset() {
        let words: Vec<String> = (0..100).map(|i| format!("w{i:03}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 5,
            index: 0,
        };
        let control = Control::new();
        control.paused.store(true, Ordering::SeqCst);
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("nope"),
                salt: None,
                workers: 2,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_PAUSED);
        let resume = result.resume.expect("paused runs carry resume state");
        assert_eq!(resume.skip_source, 0);
        assert_eq!(resume.attempts_base, 0);
    }

    #[test]
    fn pause_midrun_drains_and_counts() {
        let words: Vec<String> = (0..200).map(|i| format!("w{i:03}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 10,
            index: 0,
        };
        let control = Control::new();
        let format = format_by_name("md5").unwrap();
        let stopper_control = Arc::clone(&control);
        let once = Mutex::new(false);
        let progress = move |_attempts: u64, _elapsed: i64, _fraction: Option<f64>| {
            let mut flag = once.lock().unwrap();
            if !*flag {
                *flag = true;
                stopper_control.paused.store(true, Ordering::SeqCst);
            }
        };
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("nope"),
                salt: None,
                workers: 2,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            Some(&progress),
        );
        assert_eq!(result.status, STATUS_PAUSED);
        let resume = result.resume.unwrap();
        assert!(resume.skip_source > 0, "drained candidates recorded");
        assert_eq!(resume.skip_source, resume.attempts_base);
        assert_eq!(resume.skip_source, result.attempts);
    }

    #[test]
    fn resume_continues_from_offset() {
        let words: Vec<String> = (0..100).map(|i| format!("w{i:03}")).collect();
        let target_word = "w090";
        let format = format_by_name("md5").unwrap();

        // Segment 1: paused before any submission (resume state all zeros —
        // a caller-driven pause). Segment 2 starts from a synthetic offset of
        // 20 candidates.
        let control = Control::new();
        let mut stream2 = ChunkSource {
            words,
            chunk: 10,
            index: 0,
        };
        let segment2 = run_audit(
            AuditOptions {
                format,
                target: &md5(target_word),
                salt: None,
                workers: 2,
                budget: None,
                total_space: None,
                resume: Some(ResumeState {
                    attempts_base: 20,
                    skip_source: 20,
                    ..Default::default()
                }),
            },
            &mut stream2,
            &control,
            None,
        );
        assert_eq!(segment2.status, STATUS_MATCH);
        assert_eq!(segment2.matched_plaintext.as_deref(), Some(target_word));
        // Global position of w090 is 90 (0-based) → attempt 91, matching
        // Python's offset = attempts_base + submitted accounting.
        assert_eq!(segment2.attempts, 91);
    }

    #[test]
    fn cancel_wins_over_pause() {
        let words: Vec<String> = (0..50).map(|i| format!("w{i}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 5,
            index: 0,
        };
        let control = Control::new();
        control.cancelled.store(true, Ordering::SeqCst);
        control.paused.store(true, Ordering::SeqCst);
        let format = format_by_name("md5").unwrap();
        let result = run_audit(
            AuditOptions {
                format,
                target: &md5("nope"),
                salt: None,
                workers: 1,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_CANCELLED);
    }

    #[test]
    fn hashlist_matches_mixed_algorithms() {
        let targets = vec![
            HashlistTarget {
                id: 0,
                algorithm: "md5",
                hash: md5("hashcat"),
                line: 1,
            },
            HashlistTarget {
                id: 1,
                algorithm: "sha1",
                hash: hashing::hex_digest("sha1", b"dragon").unwrap(),
                line: 2,
            },
        ];
        let words = ["nope1", "hashcat", "dragon", "nope2"];
        let mut stream = ChunkSource {
            words: words.iter().map(|w| w.to_string()).collect(),
            chunk: 2,
            index: 0,
        };
        let control = Control::new();
        let result = run_hashlist_audit(
            HashlistOptions {
                workers: 2,
                budget: None,
                total_space: None,
                resume: None,
            },
            &targets,
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert!(result.targets.iter().all(|t| t.status == STATUS_MATCH));
        let md5_target = &result.targets[0];
        assert_eq!(md5_target.matched_plaintext.as_deref(), Some("hashcat"));
        assert_eq!(md5_target.match_at_attempt, Some(2));
        // attempts = max over matched attempts (dragon = attempt 3).
        assert_eq!(result.attempts, 3);
    }

    #[test]
    fn hashlist_lm_16_hex_prefix_match() {
        let targets = vec![HashlistTarget {
            id: 0,
            algorithm: "lm",
            hash: "299bd128c1101fd6".to_string(), // first half of lm("hashcat")
            line: 1,
        }];
        let words = ["a", "b", "hashcat"];
        let mut stream = ChunkSource {
            words: words.iter().map(|w| w.to_string()).collect(),
            chunk: 3,
            index: 0,
        };
        let control = Control::new();
        let result = run_hashlist_audit(
            HashlistOptions {
                workers: 1,
                budget: None,
                total_space: None,
                resume: None,
            },
            &targets,
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.targets[0].matched_plaintext.as_deref(), Some("hashcat"));
    }

    #[test]
    fn hashlist_pause_carries_matched_maps() {
        let targets = vec![
            HashlistTarget {
                id: 0,
                algorithm: "md5",
                hash: md5("hashcat"),
                line: 1,
            },
            HashlistTarget {
                id: 1,
                algorithm: "sha1",
                hash: hashing::hex_digest("sha1", b"dragon").unwrap(),
                line: 2,
            },
        ];
        let words: Vec<String> = (0..40)
            .map(|i| if i == 2 { "hashcat".to_string() } else { format!("w{i:02}") })
            .collect();
        let mut stream = ChunkSource {
            words,
            chunk: 2,
            index: 0,
        };
        let control = Control::new();
        let stopper = Arc::clone(&control);
        let once = Mutex::new(false);
        let progress = move |_a: u64, _e: i64, _f: Option<f64>| {
            let mut flag = once.lock().unwrap();
            if !*flag {
                *flag = true;
                stopper.paused.store(true, Ordering::SeqCst);
            }
        };
        let result = run_hashlist_audit(
            HashlistOptions {
                workers: 1,
                budget: None,
                total_space: None,
                resume: None,
            },
            &targets,
            &mut stream,
            &control,
            Some(&progress),
        );
        assert_eq!(result.status, STATUS_PAUSED);
        let resume = result.resume.expect("paused hashlist carries resume state");
        // Matched maps are id-paired and sorted.
        assert_eq!(
            resume
                .matched_plaintext
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            resume
                .matched_attempt
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        );
        // Unmatched targets are marked paused.
        assert!(result.targets.iter().any(|t| t.status == STATUS_PAUSED));
        // At least one target matched before the pause (hashcat at idx 2).
        assert!(resume.matched_plaintext.iter().any(|(_, p)| p == "hashcat"));
    }

    #[test]
    fn hashlist_resume_skips_matched_targets() {
        let targets = vec![
            HashlistTarget {
                id: 0,
                algorithm: "md5",
                hash: md5("hashcat"),
                line: 1,
            },
            HashlistTarget {
                id: 1,
                algorithm: "sha1",
                hash: hashing::hex_digest("sha1", b"w10").unwrap(),
                line: 2,
            },
        ];
        let words: Vec<String> = (0..20).map(|i| format!("w{i:02}")).collect();
        let mut stream = ChunkSource {
            words,
            chunk: 10,
            index: 0,
        };
        let control = Control::new();
        let result = run_hashlist_audit(
            HashlistOptions {
                workers: 1,
                budget: None,
                total_space: None,
                resume: Some(ResumeState {
                    attempts_base: 0,
                    skip_source: 0,
                    matched_plaintext: vec![(0, "hashcat".to_string())],
                    matched_attempt: vec![(0, 3)],
                }),
            },
            &targets,
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.attempts, 11); // max(matched_attempt) = w10 at idx 10
        assert_eq!(result.targets[0].matched_plaintext.as_deref(), Some("hashcat"));
        assert_eq!(result.targets[0].match_at_attempt, Some(3));
    }

    #[test]
    fn adaptive_verify_finds_bcrypt_candidate() {
        let stored = bcrypt::hash("hashcat", 4).unwrap();
        let format = format_by_name("bcrypt").unwrap();
        let words = ["a", "b", "hashcat"];
        let mut stream = ChunkSource {
            words: words.iter().map(|w| w.to_string()).collect(),
            chunk: 3,
            index: 0,
        };
        let control = Control::new();
        let result = run_audit(
            AuditOptions {
                format,
                target: &stored,
                salt: None,
                workers: 2,
                budget: Some(10_000),
                total_space: Some(3),
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.matched_plaintext.as_deref(), Some("hashcat"));
        assert_eq!(result.attempts, 3);
    }

    #[test]
    fn salted_target_matches_in_engine() {
        // md5($salt.$pass) with salt "salt": md5("salthashcat").
        let format = format_by_name("md5_salt_pass").unwrap();
        let expected = hashing::hex_digest("md5", b"salthashcat").unwrap();
        let words = ["a", "hashcat"];
        let mut stream = ChunkSource {
            words: words.iter().map(|w| w.to_string()).collect(),
            chunk: 2,
            index: 0,
        };
        let control = Control::new();
        let result = run_audit(
            AuditOptions {
                format,
                target: &expected,
                salt: Some("salt"),
                workers: 1,
                budget: None,
                total_space: None,
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, STATUS_MATCH);
        assert_eq!(result.matched_plaintext.as_deref(), Some("hashcat"));
        assert_eq!(result.attempts, 2);
    }
}
