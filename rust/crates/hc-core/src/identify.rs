//! Hash shape assessment and explicit algorithm selection, mirroring
//! `src/hash_cracker/algorithms.py` (`assess_hash` / `select_algorithm`),
//! including the exact error message strings the API and CLI surface.

use crate::formats::{self, Format};

/// Error mirroring Python's `HashInputError` (message is part of the contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashInputError(pub String);

impl std::fmt::Display for HashInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of inspecting a submitted hash's structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashAssessment {
    pub submitted: String,
    pub normalized: String,
    pub compatible_algorithms: Vec<&'static str>,
    pub ambiguous: bool,
}

/// Trim outer whitespace and lowercase, rejecting empty or non-hex values.
fn normalize_hash(value: &str) -> Result<String, HashInputError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HashInputError(
            "The hash value is empty. Provide a hexadecimal digest such as \
             a 32-character (MD5/NTLM/MD4/LM) or 64-character (SHA-256) value."
                .to_string(),
        ));
    }
    let mut invalid: Vec<char> = trimmed
        .chars()
        .filter(|ch| !ch.is_ascii_hexdigit())
        .collect();
    if !invalid.is_empty() {
        invalid.sort();
        invalid.dedup();
        let shown: Vec<String> = invalid.iter().take(8).map(|ch| py_repr_char(*ch)).collect();
        return Err(HashInputError(format!(
            "The hash value contains characters that are not hexadecimal ({}). \
             Supported formats use 0-9 and a-f only.",
            shown.join(", ")
        )));
    }
    Ok(trimmed.to_lowercase())
}

/// `assess_hash`: adaptive prefixes first, then strict hex + length groups.
pub fn assess_hash(value: &str) -> Result<HashAssessment, HashInputError> {
    let trimmed_probe = value.trim();
    if let Some(format) = formats::adaptive_by_prefix(trimmed_probe) {
        return Ok(HashAssessment {
            submitted: value.to_string(),
            normalized: trimmed_probe.to_string(),
            compatible_algorithms: vec![format.name],
            ambiguous: false,
        });
    }
    let normalized = normalize_hash(value)?;
    let length = normalized.chars().count();
    let candidates: Vec<&'static str> = match formats::ambiguity_for_length(length) {
        Some(group) => group.to_vec(),
        None => {
            let expected = formats::ALGORITHMS_BY_LENGTH
                .iter()
                .map(|(l, _)| l.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(HashInputError(format!(
                "Unsupported hash shape: {length} hexadecimal characters. \
                 Supported formats are {expected} characters long \
                 (LM: 16 or 32, MD5/NTLM/MD4: 32, SHA-1: 40, SHA-224: 56, \
                 SHA-256: 64, SHA-384: 96, SHA-512: 128)."
            )));
        }
    };
    Ok(HashAssessment {
        submitted: value.to_string(),
        normalized,
        ambiguous: candidates.len() > 1,
        compatible_algorithms: candidates,
    })
}

/// `select_algorithm`: validate a submitted hash against an explicit choice
/// (or pick the unambiguous format). Returns the assessment and the resolved
/// algorithm name.
pub fn select_algorithm(
    value: &str,
    algorithm: Option<&str>,
) -> Result<(HashAssessment, String), HashInputError> {
    let assessment = assess_hash(value)?;
    let algorithm = match algorithm {
        None => {
            if assessment.ambiguous {
                let list = assessment.compatible_algorithms.join(", ");
                let names = assessment.compatible_algorithms.join(" or ");
                return Err(HashInputError(format!(
                    "This hash shape matches more than one supported format \
                     ({list}). Select an algorithm explicitly (--algorithm {names}) \
                     before auditing."
                )));
            }
            assessment.compatible_algorithms[0].to_string()
        }
        Some(choice) => choice.trim().to_lowercase(),
    };
    let format: &Format = formats::format_by_name(&algorithm).ok_or_else(|| {
        let supported = formats::ALGORITHM_NAMES.join(", ");
        HashInputError(format!(
            "Unsupported algorithm '{}'. Supported formats: {supported}.",
            algorithm
        ))
    })?;
    if format.is_adaptive() {
        // The target is the full hash string; length checks do not apply.
        return Ok((assessment, algorithm));
    }
    if !format.lengths.contains(&assessment.normalized.len()) {
        let shown = format
            .lengths
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join(" or ");
        return Err(HashInputError(format!(
            "The hash does not match the {algorithm} format: expected {shown} \
             hexadecimal characters, got {}.",
            assessment.normalized.len()
        )));
    }
    if !assessment.compatible_algorithms.contains(&algorithm.as_str())
        && !format.is_salted()
    {
        let list = assessment.compatible_algorithms.join(", ");
        return Err(HashInputError(format!(
            "The hash shape is not compatible with {algorithm}. Compatible \
             formats for this shape: {list}."
        )));
    }
    Ok((assessment, algorithm))
}

/// Python `repr()` of a single character (message parity).
fn py_repr_char(ch: char) -> String {
    match ch {
        '\'' => "'\\''".to_string(),
        '\\' => "'\\\\'".to_string(),
        '\n' => "'\\n'".to_string(),
        '\r' => "'\\r'".to_string(),
        '\t' => "'\\t'".to_string(),
        c if (c as u32) < 0x20 || (c as u32) > 0x7e => format!("'\\x{:02x}'", c as u32),
        c => format!("'{c}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_32_hex() {
        let a = assess_hash("8743B52063CD84097A65D1633F5C74F5").unwrap();
        assert_eq!(
            a.compatible_algorithms,
            vec!["md5", "ntlm", "md4", "lm"]
        );
        assert!(a.ambiguous);
        assert_eq!(a.normalized, "8743b52063cd84097a65d1633f5c74f5");
    }

    #[test]
    fn lm_only_at_16_hex() {
        let a = assess_hash("299bd128c1101fd6").unwrap();
        assert_eq!(a.compatible_algorithms, vec!["lm"]);
        assert!(!a.ambiguous);
    }

    #[test]
    fn adaptive_prefixes_short_circuit() {
        for (probe, name) in [
            ("$2b$12$abcdefghijklmnopqrstuv", "bcrypt"),
            ("$6$rounds=500$salt$hash", "sha512crypt"),
            ("$P$SxAbCdEfGh1234567890", "phpass"),
        ] {
            let a = assess_hash(probe).unwrap();
            assert_eq!(a.compatible_algorithms, vec![name]);
            assert!(!a.ambiguous);
            // normalized keeps the trimmed original (not lowercased).
            assert_eq!(a.normalized, probe);
        }
    }

    #[test]
    fn non_hex_error_lists_offending_chars() {
        let err = assess_hash("deadbeef!!").unwrap_err();
        assert!(err.0.contains("'!'"), "{}", err.0);
        assert!(err.0.starts_with("The hash value contains characters"));
    }

    #[test]
    fn unsupported_shape_message() {
        let err = assess_hash("1234").unwrap_err();
        assert!(err.0.starts_with("Unsupported hash shape: 4 hexadecimal"));
        assert!(err.0.contains("16, 32, 40, 56, 64, 96, 128"));
    }

    #[test]
    fn ambiguous_requires_explicit_algorithm() {
        let err = select_algorithm("8743b52063cd84097a65d1633f5c74f5", None).unwrap_err();
        assert!(err.0.contains("matches more than one supported format"));
        assert!(err.0.contains("--algorithm md5 or ntlm or md4 or lm"));
    }

    #[test]
    fn shape_compatibility_is_enforced() {
        // SHA-1 value claimed as sha256.
        let err = select_algorithm("a9993e364706816aba3e25717850c26c9cd0d89d", Some("sha256"))
            .unwrap_err();
        assert!(err.0.starts_with("The hash does not match the sha256 format"), "{}", err.0);
    }

    #[test]
    fn salted_selection_bypasses_shape_compatibility() {
        let (a, alg) =
            select_algorithm("8743b52063cd84097a65d1633f5c74f5", Some("md5_pass_salt")).unwrap();
        assert_eq!(alg, "md5_pass_salt");
        assert_eq!(a.normalized.len(), 32);
    }

    #[test]
    fn unsupported_algorithm_message() {
        let err = select_algorithm("8743b52063cd84097a65d1633f5c74f5", Some("foo")).unwrap_err();
        assert!(err.0.starts_with("Unsupported algorithm 'foo'."), "{}", err.0);
    }

    #[test]
    fn lm_accepts_16_and_32() {
        select_algorithm("e52cac67419a9a22", Some("lm")).unwrap();
        select_algorithm("e52cac67419a9a224a3b108f3fa6cb6d", Some("lm")).unwrap();
    }
}
