//! Per-algorithm throughput benchmarking, mirroring `src/hash_cracker/benchmark.py`:
//! hash a growing-suffix sample inside a wall-clock slice; informational only.

use std::time::{Duration, Instant};

use crate::formats::{self, Kind};
use crate::hashing;

/// Default benchmark sample (pinned).
pub const BENCHMARK_SAMPLE: &str = "benchmark-sample-candidate-0001";

/// One algorithm's measurement.
#[derive(Debug, Clone)]
pub struct Measurement {
    pub algorithm: String,
    pub hashes_per_second: f64,
    pub elapsed_ms: i64,
    pub hashed: u64,
}

/// Measure one algorithm for `seconds` of wall clock.
pub fn measure_algorithm(algorithm: &str, seconds: f64) -> Option<Measurement> {
    let format = formats::format_by_name(algorithm)?;
    if format.is_adaptive() {
        // Adaptive verify is far too slow for a 2 s slice at default cost;
        // the Python backend reports it as unavailable without the extras.
        return None;
    }
    let salt = format.is_salted().then_some("benchmark-salt");
    let slice = Duration::try_from_secs_f64(seconds).unwrap_or(Duration::from_secs(2));
    let start = Instant::now();
    let mut hashed: u64 = 0;
    let mut sample = String::from(BENCHMARK_SAMPLE);
    loop {
        // Deterministic growing suffix: f"{sample}-{hashed}".
        sample.truncate(BENCHMARK_SAMPLE.len());
        sample.push('-');
        sample.push_str(&hashed.to_string());
        match format.kind {
            Kind::Fast if format.name == "ntlm" => {
                let _ = hashing::ntlm_hex(&sample);
            }
            Kind::Fast if format.name == "lm" => {
                let _ = hashing::lm_hex(&sample);
            }
            Kind::Fast => {
                let _ = hashing::hex_digest(format.name, sample.as_bytes());
            }
            Kind::Salted => {
                let mut data = sample.as_bytes().to_vec();
                if format.salt_first.unwrap_or(false) {
                    data.splice(0..0, salt.unwrap_or_default().as_bytes().to_vec());
                } else {
                    data.extend_from_slice(salt.unwrap_or_default().as_bytes());
                }
                let _ = hashing::hex_digest(format.base.unwrap_or(""), &data);
            }
            Kind::Adaptive => unreachable!("filtered above"),
        }
        hashed += 1;
        if hashed.is_multiple_of(1024) && start.elapsed() >= slice {
            break;
        }
        if hashed == u64::MAX {
            break;
        }
    }
    let elapsed = start.elapsed();
    Some(Measurement {
        algorithm: algorithm.to_string(),
        hashes_per_second: hashed as f64 / elapsed.as_secs_f64(),
        elapsed_ms: elapsed.as_millis() as i64,
        hashed,
    })
}

/// Measure every algorithm in registry order (skipping adaptive).
pub fn measure_all(seconds: f64) -> Vec<Measurement> {
    formats::ALGORITHM_NAMES
        .iter()
        .filter_map(|name| measure_algorithm(name, seconds))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_shape_is_stable() {
        let m = measure_algorithm("md5", 0.05).expect("md5 measures");
        assert_eq!(m.algorithm, "md5");
        assert!(m.hashes_per_second > 0.0);
        assert!(m.hashed > 0);
        assert!(m.elapsed_ms >= 0);
    }

    #[test]
    fn salted_formats_measure_with_salt() {
        let m = measure_algorithm("md5_pass_salt", 0.05).expect("salted measures");
        assert_eq!(m.algorithm, "md5_pass_salt");
        assert!(m.hashed > 0);
    }

    #[test]
    fn adaptive_formats_report_unavailable() {
        assert!(measure_algorithm("bcrypt", 0.05).is_none());
        assert!(measure_algorithm("phpass", 0.05).is_none());
    }

    #[test]
    fn unknown_format_is_none() {
        assert!(measure_algorithm("nope", 0.05).is_none());
    }

    #[test]
    fn measure_all_skips_adaptive() {
        let all = measure_all(0.01);
        assert!(!all.is_empty());
        assert!(all.iter().all(|m| m.algorithm != "bcrypt"));
        // Registry order preserved.
        let names: Vec<_> = all.iter().map(|m| m.algorithm.as_str()).collect();
        let expected: Vec<_> = formats::ALGORITHM_NAMES
            .iter()
            .filter(|n| formats::format_by_name(n).map(|f| !f.is_adaptive()).unwrap_or(false))
            .copied()
            .collect();
        assert_eq!(names, expected);
    }
}
