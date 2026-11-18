//! Shared output helpers for the `hashcrack-rs` CLI (parity with the
//! Python CLI's formatting helpers).

/// `f"{n:,}"` comma grouping (single implementation, shared with hc-core).
pub fn commas(n: u64) -> String {
    hc_core::bruteforce::format_commas(n)
}

/// Right-aligned comma-grouped number: `{n:>12,}`.
pub fn attempts_field(attempts: u64) -> String {
    let grouped = commas(attempts);
    format!("{grouped:>12}")
}

/// Python `repr()` of a simple string (used for the charset header).
/// Single quotes unless the value contains one.
pub fn py_repr(value: &str) -> String {
    if value.contains('\'') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        format!("'{value}'")
    }
}

/// Fixed-width seconds display: `{secs:6.1f}`.
pub fn elapsed_field(elapsed_ms: i64) -> String {
    let secs = elapsed_ms as f64 / 1000.0;
    format!("{secs:>6.1}")
}

/// Progress line body: `\r  Attempts: {...}{percent}  Elapsed: {...}s`.
pub fn progress_line(attempts: u64, elapsed_ms: i64, fraction: Option<f64>) -> String {
    let percent = match fraction {
        Some(f) => format!(" {:>5.1}%", f * 100.0),
        None => String::new(),
    };
    format!(
        "\r  Attempts: {}{}  Elapsed: {}s",
        attempts_field(attempts),
        percent,
        elapsed_field(elapsed_ms)
    )
}

/// Throttled progress state (0.25 s, rate + ETA), mirroring the Python CLI.
pub struct ProgressRenderer {
    last_print: std::time::Instant,
    sample_time: std::time::Instant,
    sample_attempts: u64,
    progress_limit: Option<u128>,
}

impl ProgressRenderer {
    pub fn new(progress_limit: Option<u128>) -> Self {
        let now = std::time::Instant::now();
        Self {
            last_print: now,
            sample_time: now,
            sample_attempts: 0,
            progress_limit,
        }
    }

    /// Render one progress callback (callers call it for every engine update;
    /// the renderer throttles itself).
    pub fn render(&mut self, attempts: u64, elapsed_ms: i64, fraction: Option<f64>) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_print).as_secs_f64() < 0.25 {
            return;
        }
        let dt = now
            .duration_since(self.sample_time)
            .as_secs_f64()
            .max(f64::EPSILON);
        let rate = if attempts > self.sample_attempts {
            (attempts - self.sample_attempts) as f64 / dt
        } else {
            0.0
        };
        let progress_fraction = match self.progress_limit {
            Some(limit) if limit > 0 => Some((attempts as f64 / limit as f64).min(1.0)),
            _ => fraction,
        };
        eprint!("{}", progress_line(attempts, elapsed_ms, progress_fraction));
        use std::io::Write;
        let _ = std::io::stderr().flush();
        if let Some(limit) = self.progress_limit {
            if (attempts as u128) < limit && rate > 0.0 {
                let remaining = (limit as f64 - attempts as f64) / rate;
                eprint!("\r  ETA ~{remaining:.0}s ({:.0} candidates/s)   ", rate);
                let _ = std::io::stderr().flush();
            }
        }
        self.sample_time = now;
        self.sample_attempts = attempts;
        self.last_print = now;
    }

    /// Clear the progress line.
    pub fn finish(&self) {
        eprint!("\r{}", " ".repeat(70));
        eprint!("\r");
        use std::io::Write;
        let _ = std::io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commas_groups_thousands() {
        assert_eq!(commas(1_000_000), "1,000,000");
        assert_eq!(commas(999), "999");
    }

    #[test]
    fn attempts_field_pads_to_12() {
        assert_eq!(attempts_field(12), "          12");
        assert_eq!(attempts_field(1_000_000), "   1,000,000");
    }

    #[test]
    fn py_repr_quotes() {
        assert_eq!(py_repr("abc"), "'abc'");
        assert_eq!(py_repr("a'c"), "\"a'c\"");
    }

    #[test]
    fn progress_line_shape() {
        let line = progress_line(1234, 6789, Some(0.5));
        assert!(line.starts_with("\r  Attempts: "));
        assert!(line.contains(" 50.0%"));
        assert!(line.contains("Elapsed: "));
        assert!(line.ends_with('s'));
    }
}
