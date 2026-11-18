//! Candidate sources: dictionary streaming and hashlist parsing, mirroring
//! `src/hash_cracker/candidates.py`.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Default candidates per batch (pinned to the Python engine).
pub const DEFAULT_BATCH_SIZE: usize = 8192;

/// Maximum wordlist upload size accepted by the dashboard (256 MiB).
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// One hashlist target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashlistTarget {
    pub id: usize,
    pub algorithm: &'static str,
    pub hash: String,
    pub line: usize,
}

/// Errors from candidate sources (messages are part of the API contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateError(pub String);

impl std::fmt::Display for CandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CandidateError {}

/// Stream dictionary candidates in batches. Encoding matches Python:
/// UTF-8 with replacement, only `\r\n`/`\n` stripped, blank lines preserved
/// as empty-string candidates, duplicates kept in file order.
pub struct DictionarySource {
    reader: BufReader<File>,
    batch_size: usize,
    buffer: Vec<String>,
    done: bool,
}

impl DictionarySource {
    pub fn open(path: &Path) -> Result<Self, CandidateError> {
        let file = File::open(path).map_err(|e| {
            CandidateError(format!("Cannot open wordlist {}: {e}", path.display()))
        })?;
        Ok(Self {
            reader: BufReader::new(file),
            batch_size: DEFAULT_BATCH_SIZE,
            buffer: Vec::with_capacity(DEFAULT_BATCH_SIZE),
            done: false,
        })
    }

    /// Total line count (best effort; `None` on I/O error), matching
    /// `count_dictionary_lines`: `\n` bytes counted in 1 MiB chunks.
    pub fn count_lines(path: &Path) -> Option<u64> {
        let mut file = File::open(path).ok()?;
        let mut count = 0u64;
        let mut chunk = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            count += chunk[..read].iter().filter(|&&b| b == b'\n').count() as u64;
        }
        Some(count)
    }

    /// Next batch of candidates; `None` when the source is exhausted.
    pub fn read_batch(&mut self) -> Option<Vec<String>> {
        if self.done {
            return None;
        }
        self.buffer.clear();
        let mut line = String::new();
        while self.buffer.len() < self.batch_size {
            line.clear();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    self.done = true;
                    break;
                }
                Ok(_) => {
                    // Only \r\n/\n are stripped (no trim()).
                    let line = line.strip_suffix('\n').unwrap_or(&line);
                    let line = line.strip_suffix('\r').unwrap_or(line);
                    self.buffer.push(line.to_string());
                }
                Err(_) => {
                    // Hard I/O errors end the stream with whatever was read.
                    self.done = true;
                    return Some(std::mem::take(&mut self.buffer));
                }
            }
        }
        if self.buffer.is_empty() && self.done {
            None
        } else {
            Some(std::mem::take(&mut self.buffer))
        }
    }

}

impl crate::engine::CandidateStream for DictionarySource {
    fn next_batch(&mut self, _max: usize) -> Option<Vec<String>> {
        self.read_batch()
    }
}

/// Parse a hashlist file: one target per line, optional `algorithm:hash`
/// prefix, `#` comments and blank lines skipped. Salted and adaptive
/// algorithms are rejected per line; every error carries the line number.
/// Message strings mirror `src/hash_cracker/candidates.py` exactly.
pub fn parse_hashlist(content: &str) -> Result<Vec<HashlistTarget>, CandidateError> {
    let mut targets = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (target_algorithm, normalized) = match line.split_once(':') {
            Some((prefix, value)) => {
                let alg = prefix.trim().to_lowercase();
                let format = crate::formats::format_by_name(&alg).ok_or_else(|| {
                    CandidateError(format!(
                        "Hashlist line {lineno}: unknown algorithm '{alg}'."
                    ))
                })?;
                if format.is_salted() || format.is_adaptive() {
                    return Err(CandidateError(format!(
                        "Hashlist line {lineno}: format {alg} is not supported in hashlists."
                    )));
                }
                crate::identify::select_algorithm(value.trim(), Some(&alg))
                    .map(|(assessment, algorithm)| (algorithm, assessment.normalized))
                    .map_err(|e| CandidateError(format!("Hashlist line {lineno}: {e}")))?
            }
            None => crate::identify::select_algorithm(line, None)
                .map(|(assessment, algorithm)| (algorithm, assessment.normalized))
                .map_err(|e| CandidateError(format!("Hashlist line {lineno}: {e}")))?,
        };
        let static_name = crate::formats::format_by_name(&target_algorithm)
            .unwrap_or_else(|| {
                panic!("algorithm '{target_algorithm}' validated but missing from registry")
            })
            .name;
        targets.push(HashlistTarget {
            id: targets.len(),
            algorithm: static_name,
            hash: normalized,
            line: lineno,
        });
    }
    if targets.is_empty() {
        return Err(CandidateError(
            "The hashlist file contains no targets.".to_string(),
        ));
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_wordlist(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{content}").unwrap();
        f
    }

    #[test]
    fn dictionary_preserves_blank_lines_and_duplicates() {
        let f = temp_wordlist("hashcat\n\nmonkey\nhashcat\ntrailing");
        let mut src = DictionarySource::open(f.path()).unwrap();
        let mut all = Vec::new();
        while let Some(batch) = src.read_batch() {
            all.extend(batch);
        }
        assert_eq!(all, vec!["hashcat", "", "monkey", "hashcat", "trailing"]);
    }

    #[test]
    fn dictionary_only_strips_newlines() {
        let f = temp_wordlist("  spaced  \r\n\t tabbed\t\n");
        let mut src = DictionarySource::open(f.path()).unwrap();
        let mut all = Vec::new();
        while let Some(batch) = src.read_batch() {
            all.extend(batch);
        }
        assert_eq!(all, vec!["  spaced  ", "\t tabbed\t"]);
    }

    #[test]
    fn count_lines_matches_newline_bytes() {
        let f = temp_wordlist("a\nb\nc\n");
        assert_eq!(DictionarySource::count_lines(f.path()), Some(3));
    }

    #[test]
    fn hashlist_parses_prefixes_and_skips_comments() {
        let content = "# comment\n\n\
                       e52cac67419a9a22\n\
                       md5:900150983cd24fb0d6963f7d28e17f72\n\
                       ntlm:b4b9b02e6f09a9bd760f388b67351e2b\n";
        let targets = parse_hashlist(content).unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].id, 0);
        // Bare 16-hex resolves unambiguously to lm.
        assert_eq!(targets[0].algorithm, "lm");
        assert_eq!(targets[1].algorithm, "md5");
        assert_eq!(targets[2].algorithm, "ntlm");
        assert_eq!(targets[0].line, 3);
        assert_eq!(targets[1].line, 4);
        assert_eq!(targets[2].line, 5);
    }

    #[test]
    fn hashlist_rejects_bare_ambiguous_shapes() {
        // 32-hex is always ambiguous (md5/ntlm/md4/lm); 40-hex (sha1/ripemd160).
        for shape in ["8743b52063cd84097a65d1633f5c74f5", "a9993e364706816aba3e25717850c26c9cd0d89d"] {
            let err = parse_hashlist(&format!("{shape}\n")).unwrap_err();
            assert!(
                err.0.contains("matches more than one supported format"),
                "{err}"
            );
            assert!(err.0.contains("Hashlist line 1:"), "{err}");
        }
    }

    #[test]
    fn hashlist_rejects_salted_and_adaptive_prefixes() {
        let err = parse_hashlist("md5_pass_salt:8743b52063cd84097a65d1633f5c74f5\n").unwrap_err();
        assert_eq!(
            err.0,
            "Hashlist line 1: format md5_pass_salt is not supported in hashlists."
        );
        let err = parse_hashlist("bcrypt:$2b$12$abc\n").unwrap_err();
        assert_eq!(
            err.0,
            "Hashlist line 1: format bcrypt is not supported in hashlists."
        );
    }

    #[test]
    fn hashlist_rejects_unknown_algorithm_and_empty_file() {
        let err = parse_hashlist("nope:8743\n").unwrap_err();
        assert_eq!(err.0, "Hashlist line 1: unknown algorithm 'nope'.");
        let err = parse_hashlist("# only comments\n\n").unwrap_err();
        assert_eq!(err.0, "The hashlist file contains no targets.");
    }
}
