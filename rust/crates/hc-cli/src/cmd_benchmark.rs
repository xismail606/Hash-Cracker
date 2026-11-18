//! `hashcrack-rs benchmark` — per-algorithm throughput, output parity with
//! the Python CLI.

use hc_core::benchmark::{measure_algorithm, Measurement};
use hc_core::formats::{self, ALGORITHM_NAMES};

use crate::cmd_audit::{EXIT_INVALID, EXIT_OK};
use crate::output::commas;

pub struct BenchmarkRequest {
    pub seconds: f64,
    pub algorithms: Option<String>,
}

pub fn run(request: BenchmarkRequest) -> i32 {
    let names: Vec<String> = match &request.algorithms {
        Some(spec) => spec
            .split(',')
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty())
            .collect(),
        None => default_benchmark_names(),
    };
    let invalid: Vec<&String> = names
        .iter()
        .filter(|n| !ALGORITHM_NAMES.contains(&n.as_str()))
        .collect();
    if !invalid.is_empty() {
        eprintln!(
            "Unknown algorithms: {}. Supported: {}.",
            invalid
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            ALGORITHM_NAMES.join(", ")
        );
        return EXIT_INVALID;
    }

    println!(
        "Benchmarking {} algorithms, {:.1}s each (in-process, CPU-bound):",
        names.len(),
        request.seconds
    );
    let mut results: Vec<Measurement> = Vec::new();
    for name in &names {
        print!("  {name:<16} ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        match measure_algorithm(name, request.seconds) {
            None => {
                // Adaptive formats are reported unavailable, like the Python
                // backend without its optional extras.
                println!("unavailable (adaptive verify is not benchmarked)");
            }
            Some(r) => {
                let rate = commas(r.hashes_per_second as u64);
                println!(
                    "{rate:>14} candidates/s  ({} hashed in {}ms)",
                    commas(r.hashed),
                    r.elapsed_ms
                );
                results.push(r);
            }
        }
    }
    if let Some(best) = results
        .iter()
        .max_by(|a, b| a.hashes_per_second.total_cmp(&b.hashes_per_second))
    {
        println!(
            "\nFastest: {} at {:.0} candidates/s. Use this to pick a realistic brute-force budget on this machine.",
            best.algorithm,
            best.hashes_per_second
        );
    }
    EXIT_OK
}

/// Default benchmark list: all non-salted formats (adaptive entries report
/// "unavailable" at measure time, mirroring the Python default).
fn default_benchmark_names() -> Vec<String> {
    ALGORITHM_NAMES
        .iter()
        .filter(|n| {
            formats::format_by_name(n)
                .map(|f| !f.is_salted())
                .unwrap_or(false)
        })
        .map(|n| n.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names_are_unsalted_in_order() {
        let names = default_benchmark_names();
        assert!(names.contains(&"md5".to_string()));
        // Adaptive formats stay in the default list (reported unavailable).
        assert!(names.contains(&"bcrypt".to_string()));
        // Salted formats are excluded.
        assert!(!names.iter().any(|n| n == "md5_pass_salt"));
        assert_eq!(names[0], "md5");
    }
}
