//! Brute-force mode: charset presets, alphabet resolution, validation,
//! deterministic candidate generation — mirroring `src/hash_cracker/bruteforce.py`.

use crate::identify::HashInputError;

/// Hard candidate budget cap (pinned).
pub const HARD_MAX_BUDGET: u64 = 10_000_000;

/// Charset preset alphabets (`symbols` = Python's `string.punctuation`).
pub const CHARSET_PRESETS: &[(&str, &str)] = &[
    ("lower", "abcdefghijklmnopqrstuvwxyz"),
    ("upper", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("digits", "0123456789"),
    ("symbols", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
];

/// Preset labels for interface selects.
pub const CHARSET_PRESET_LABELS: &[(&str, &str)] = &[
    ("lower", "lowercase a-z"),
    ("upper", "uppercase A-Z"),
    ("digits", "digits 0-9"),
    ("symbols", "symbols"),
];

/// Resolve a charset specification (preset names and/or literal characters,
/// comma-separated) into a deduplicated alphabet. Comma cannot be a literal.
pub fn resolve_charset(spec: &str) -> Result<String, HashInputError> {
    if spec.trim().is_empty() {
        return Err(HashInputError(
            "Brute-force mode requires a non-empty character set \
             (preset names lower, upper, digits, symbols, or literal characters)."
                .to_string(),
        ));
    }
    let mut alphabet = String::new();
    for part in spec.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        match CHARSET_PRESETS.iter().find(|(name, _)| *name == token) {
            Some((_, preset)) => alphabet.push_str(preset),
            None => alphabet.push_str(token),
        }
    }
    let mut seen = Vec::new();
    for ch in alphabet.chars() {
        if !seen.contains(&ch) {
            seen.push(ch);
        }
    }
    let resolved: String = seen.into_iter().collect();
    if resolved.is_empty() {
        return Err(HashInputError(
            "The selected character set resolved to an empty alphabet. \
             Use preset names (lower, upper, digits, symbols) or literal characters."
                .to_string(),
        ));
    }
    Ok(resolved)
}

/// Validate length range and budget; return `(alphabet, total_space)`.
/// `total_space` saturates (Python's unbounded ints only ever exceed u128
/// far beyond the 10,000,000 budget, where the comparison outcome is identical).
pub fn validate_bruteforce_options(
    min_length: u64,
    max_length: u64,
    budget: u64,
    alphabet: Option<String>,
) -> Result<(String, u128), HashInputError> {
    if min_length < 1 {
        return Err(HashInputError(
            "Minimum candidate length must be at least 1.".to_string(),
        ));
    }
    if max_length < min_length {
        return Err(HashInputError(format!(
            "Maximum length ({max_length}) must be greater than or equal to \
             the minimum length ({min_length})."
        )));
    }
    if budget < 1 {
        return Err(HashInputError(
            "The candidate budget must be at least 1.".to_string(),
        ));
    }
    if budget > HARD_MAX_BUDGET {
        return Err(HashInputError(format!(
            "The candidate budget {} exceeds the hard maximum of {} candidates per run.",
            format_commas(budget),
            format_commas(HARD_MAX_BUDGET)
        )));
    }
    let alphabet = alphabet.ok_or_else(|| {
        HashInputError("Brute-force mode requires a resolved alphabet.".to_string())
    })?;
    let base = alphabet.chars().count() as u128;
    let mut total_space: u128 = 0;
    for length in min_length..=max_length {
        total_space = total_space.saturating_add(base.saturating_pow(length.min(127) as u32));
    }
    Ok((alphabet, total_space))
}

/// `1_000_000`-style comma grouping (Python's `f"{n:,}"`).
pub fn format_commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = s.len() % 3;
    if first > 0 {
        out.push_str(&s[..first]);
        if s.len() > first {
            out.push(',');
        }
    }
    for (i, ch) in s[first..].chars().enumerate() {
        out.push(ch);
        if (i + 1) % 3 == 0 && i + 1 != s.len() - first {
            out.push(',');
        }
    }
    out
}

/// Deterministic brute-force enumeration: per length in increasing order,
/// lexicographic within a length (itertools.product order).
pub struct BruteforceSource {
    alphabet: Vec<char>,
    lengths: std::ops::RangeInclusive<u64>,
    current_length: Option<u64>,
    odometer: Vec<usize>,
    done: bool,
}

impl BruteforceSource {
    pub fn new(alphabet: String, min_length: u64, max_length: u64) -> Self {
        Self {
            alphabet: alphabet.chars().collect(),
            lengths: min_length..=max_length,
            current_length: None,
            odometer: Vec::new(),
            done: false,
        }
    }

    fn start_length(&mut self, length: u64) {
        self.current_length = Some(length);
        self.odometer = vec![0; length as usize];
    }

    /// Advance the odometer; `false` when the current length is exhausted.
    fn advance(&mut self) -> bool {
        let base = self.alphabet.len();
        for pos in (0..self.odometer.len()).rev() {
            self.odometer[pos] += 1;
            if self.odometer[pos] < base {
                return true;
            }
            self.odometer[pos] = 0;
        }
        false
    }

    fn render(&self) -> String {
        self.odometer
            .iter()
            .map(|&idx| self.alphabet[idx])
            .collect()
    }

    /// Next batch of candidates; `None` when the space is exhausted.
    pub fn next_batch(&mut self, batch_size: usize) -> Option<Vec<String>> {
        if self.done {
            return None;
        }
        let mut batch = Vec::with_capacity(batch_size);
        while batch.len() < batch_size {
            if self.current_length.is_none() {
                match self.lengths.next() {
                    Some(length) => self.start_length(length),
                    None => {
                        self.done = true;
                        break;
                    }
                }
                if self.odometer.is_empty() {
                    // min_length could be 0 only via misvalidation; emit "" once.
                    batch.push(String::new());
                    self.current_length = None;
                    continue;
                }
            }
            batch.push(self.render());
            if !self.advance() {
                self.current_length = None;
            }
        }
        if batch.is_empty() && self.done {
            None
        } else {
            Some(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_match_python() {
        assert_eq!(CHARSET_PRESETS.iter().find(|(n, _)| *n == "lower").unwrap().1.len(), 26);
        assert_eq!(CHARSET_PRESETS.iter().find(|(n, _)| *n == "symbols").unwrap().1, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
    }

    #[test]
    fn resolve_charset_mixes_presets_and_literals() {
        let resolved = resolve_charset("lower,digits").unwrap();
        assert_eq!(resolved, "abcdefghijklmnopqrstuvwxyz0123456789");
        let resolved = resolve_charset("abc123,abc").unwrap();
        assert_eq!(resolved, "abc123");
        assert!(resolve_charset("").is_err());
        assert!(resolve_charset("  ").is_err());
    }

    #[test]
    fn validation_messages() {
        let err = validate_bruteforce_options(0, 4, 100, Some("ab".into())).unwrap_err();
        assert_eq!(err.0, "Minimum candidate length must be at least 1.");
        let err = validate_bruteforce_options(4, 2, 100, Some("ab".into())).unwrap_err();
        assert_eq!(
            err.0,
            "Maximum length (2) must be greater than or equal to the minimum length (4)."
        );
        let err = validate_bruteforce_options(1, 2, 0, Some("ab".into())).unwrap_err();
        assert_eq!(err.0, "The candidate budget must be at least 1.");
        let err =
            validate_bruteforce_options(1, 2, HARD_MAX_BUDGET + 1, Some("ab".into())).unwrap_err();
        assert_eq!(
            err.0,
            "The candidate budget 10,000,001 exceeds the hard maximum of 10,000,000 candidates per run."
        );
    }

    #[test]
    fn total_space_sums_all_lengths() {
        let (_, space) = validate_bruteforce_options(1, 3, 100, Some("ab".into())).unwrap();
        assert_eq!(space, 2 + 4 + 8);
    }

    #[test]
    fn enumeration_is_length_ordered_and_lexicographic() {
        let mut src = BruteforceSource::new("ba".to_string(), 1, 2);
        let mut all = Vec::new();
        while let Some(batch) = src.next_batch(3) {
            all.extend(batch);
        }
        assert_eq!(
            all,
            vec!["b", "a", "bb", "ba", "ab", "aa"]
        );
    }

    #[test]
    fn format_commas_groups_thousands() {
        assert_eq!(format_commas(1_000_000), "1,000,000");
        assert_eq!(format_commas(999), "999");
        assert_eq!(format_commas(10_000_001), "10,000,001");
    }
}
