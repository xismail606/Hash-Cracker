//! Format registry: the 23 supported hash formats with their identifiers,
//! labels, kinds, digest lengths, ambiguity groups, and salt/adaptive rules.
//!
//! This catalog is pinned byte-for-byte against the Python backend
//! (`src/hash_cracker/algorithms.py`) — see `contracts/api.md` §formats.

/// Kind of format as exposed by `/api/formats`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Fast,
    Salted,
    Adaptive,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Fast => "fast",
            Kind::Salted => "salted",
            Kind::Adaptive => "adaptive",
        }
    }
}

/// Static description of one supported format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    /// Bare hex-digest lengths used for shape identification (empty for adaptive).
    pub lengths: &'static [usize],
    /// For salted formats: the underlying fast hash name.
    pub base: Option<&'static str>,
    /// For salted formats: true when the digest is over `salt || pass`.
    pub salt_first: Option<bool>,
    /// For adaptive formats: the hash-string prefix that identifies them.
    pub adaptive_prefix: Option<&'static str>,
}

impl Format {
    pub fn is_salted(&self) -> bool {
        self.kind == Kind::Salted
    }
    pub fn is_adaptive(&self) -> bool {
        self.kind == Kind::Adaptive
    }
}

/// Registry order — identifiers used in code, CLI choices, API, hashlist prefixes.
pub const ALGORITHM_NAMES: &[&str] = &[
    "md5",
    "sha256",
    "ntlm",
    "sha1",
    "sha224",
    "sha384",
    "sha512",
    "md4",
    "lm",
    "md5_pass_salt",
    "md5_salt_pass",
    "sha1_pass_salt",
    "sha1_salt_pass",
    "sha256_pass_salt",
    "sha256_salt_pass",
    "sha512_pass_salt",
    "sha512_salt_pass",
    "sha512_224",
    "sha512_256",
    "ripemd160",
    "bcrypt",
    "sha512crypt",
    "phpass",
];

const fn fast(name: &'static str, label: &'static str, lengths: &'static [usize]) -> Format {
    Format {
        name,
        label,
        kind: Kind::Fast,
        lengths,
        base: None,
        salt_first: None,
        adaptive_prefix: None,
    }
}

const fn salted(
    name: &'static str,
    label: &'static str,
    base: &'static str,
    salt_first: bool,
    lengths: &'static [usize],
) -> Format {
    Format {
        name,
        label,
        kind: Kind::Salted,
        lengths,
        base: Some(base),
        salt_first: Some(salt_first),
        adaptive_prefix: None,
    }
}

const L32: &[usize] = &[32];
const L40: &[usize] = &[40];
const L64: &[usize] = &[64];
const L128: &[usize] = &[128];

const fn adaptive(
    name: &'static str,
    label: &'static str,
    prefix: &'static str,
) -> Format {
    Format {
        name,
        label,
        kind: Kind::Adaptive,
        lengths: &[],
        base: None,
        salt_first: None,
        adaptive_prefix: Some(prefix),
    }
}

/// Registry in the pinned order.
pub const FORMATS: &[Format] = &[
    fast("md5", "MD5", &[32]),
    fast("sha256", "SHA-256", &[64]),
    fast("ntlm", "NTLM", &[32]),
    fast("sha1", "SHA-1", &[40]),
    fast("sha224", "SHA-224", &[56]),
    fast("sha384", "SHA-384", &[96]),
    fast("sha512", "SHA-512", &[128]),
    fast("md4", "MD4", &[32]),
    fast("lm", "LM", &[16, 32]),
    salted("md5_pass_salt", "md5($pass.$salt)", "md5", false, L32),
    salted("md5_salt_pass", "md5($salt.$pass)", "md5", true, L32),
    salted("sha1_pass_salt", "sha1($pass.$salt)", "sha1", false, L40),
    salted("sha1_salt_pass", "sha1($salt.$pass)", "sha1", true, L40),
    salted("sha256_pass_salt", "sha256($pass.$salt)", "sha256", false, L64),
    salted("sha256_salt_pass", "sha256($salt.$pass)", "sha256", true, L64),
    salted("sha512_pass_salt", "sha512($pass.$salt)", "sha512", false, L128),
    salted("sha512_salt_pass", "sha512($salt.$pass)", "sha512", true, L128),
    fast("sha512_224", "SHA-512/224", &[56]),
    fast("sha512_256", "SHA-512/256", &[64]),
    fast("ripemd160", "RIPEMD-160", &[40]),
    adaptive("bcrypt", "bcrypt", "$2"),
    adaptive("sha512crypt", "sha512crypt", "$6$"),
    adaptive("phpass", "phpass", "$P$"),
];

/// Shape-identification ambiguity groups by hex length.
pub const ALGORITHMS_BY_LENGTH: &[(usize, &[&str])] = &[
    (16, &["lm"]),
    (32, &["md5", "ntlm", "md4", "lm"]),
    (40, &["sha1", "ripemd160"]),
    (56, &["sha224", "sha512_224"]),
    (64, &["sha256", "sha512_256"]),
    (96, &["sha384"]),
    (128, &["sha512"]),
];

/// Lookup a format by its registry identifier.
pub fn format_by_name(name: &str) -> Option<&'static Format> {
    FORMATS.iter().find(|f| f.name == name)
}

/// Compatible algorithms for a bare hex length, or `None` when unsupported.
pub fn ambiguity_for_length(len: usize) -> Option<&'static [&'static str]> {
    ALGORITHMS_BY_LENGTH
        .iter()
        .find(|(l, _)| *l == len)
        .map(|(_, group)| *group)
}

/// The adaptive format whose prefix matches `probe`, if any.
pub fn adaptive_by_prefix(probe: &str) -> Option<&'static Format> {
    FORMATS
        .iter()
        .find(|f| f.is_adaptive() && probe.starts_with(f.adaptive_prefix.unwrap()))
}

/// `salted_by_length` map content for `/api/formats`: salted format ids grouped
/// by their bare digest length.
pub fn salted_by_length() -> Vec<(usize, Vec<&'static str>)> {
    let mut out: Vec<(usize, Vec<&'static str>)> = Vec::new();
    for f in FORMATS {
        if f.is_salted() {
            let len = f.lengths[0];
            match out.iter_mut().find(|(l, _)| *l == len) {
                Some((_, ids)) => ids.push(f.name),
                None => out.push((len, vec![f.name])),
            }
        }
    }
    out
}

/// Registry order preserved: index of a format name, or `None`.
pub fn index_of(name: &str) -> Option<usize> {
    ALGORITHM_NAMES.iter().position(|n| *n == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_twenty_three_formats_in_pinned_order() {
        let expected = [
            "md5", "sha256", "ntlm", "sha1", "sha224", "sha384", "sha512", "md4", "lm",
            "md5_pass_salt", "md5_salt_pass", "sha1_pass_salt", "sha1_salt_pass",
            "sha256_pass_salt", "sha256_salt_pass", "sha512_pass_salt", "sha512_salt_pass",
            "sha512_224", "sha512_256", "ripemd160", "bcrypt", "sha512crypt", "phpass",
        ];
        assert_eq!(ALGORITHM_NAMES, expected);
        assert_eq!(FORMATS.len(), 23);
        for f in FORMATS {
            assert_eq!(f.name, ALGORITHM_NAMES[index_of(f.name).unwrap()]);
        }
    }

    #[test]
    fn ambiguity_groups_match_python() {
        assert_eq!(ambiguity_for_length(16), Some(&["lm"][..]));
        assert_eq!(ambiguity_for_length(32), Some(&["md5", "ntlm", "md4", "lm"][..]));
        assert_eq!(ambiguity_for_length(40), Some(&["sha1", "ripemd160"][..]));
        assert_eq!(ambiguity_for_length(56), Some(&["sha224", "sha512_224"][..]));
        assert_eq!(ambiguity_for_length(64), Some(&["sha256", "sha512_256"][..]));
        assert_eq!(ambiguity_for_length(96), Some(&["sha384"][..]));
        assert_eq!(ambiguity_for_length(128), Some(&["sha512"][..]));
        assert_eq!(ambiguity_for_length(12), None);
    }

    #[test]
    fn salted_map_groups_by_base_length() {
        let map = salted_by_length();
        assert_eq!(map.len(), 4);
        assert_eq!(map[0], (32, vec!["md5_pass_salt", "md5_salt_pass"]));
        assert_eq!(map[1], (40, vec!["sha1_pass_salt", "sha1_salt_pass"]));
        assert_eq!(map[2], (64, vec!["sha256_pass_salt", "sha256_salt_pass"]));
        assert_eq!(map[3], (128, vec!["sha512_pass_salt", "sha512_salt_pass"]));
    }

    #[test]
    fn adaptive_prefixes_are_pinned() {
        assert_eq!(adaptive_by_prefix("$2ab$").map(|f| f.name), Some("bcrypt"));
        assert_eq!(adaptive_by_prefix("$6$salt").map(|f| f.name), Some("sha512crypt"));
        assert_eq!(adaptive_by_prefix("$P$Sx").map(|f| f.name), Some("phpass"));
        assert_eq!(adaptive_by_prefix("$5$salt"), None);
        assert_eq!(adaptive_by_prefix("deadbeef"), None);
    }

    #[test]
    fn kinds_are_pinned() {
        assert_eq!(format_by_name("bcrypt").unwrap().kind, Kind::Adaptive);
        assert_eq!(format_by_name("md5_salt_pass").unwrap().kind, Kind::Salted);
        assert_eq!(format_by_name("ripemd160").unwrap().kind, Kind::Fast);
        assert!(format_by_name("lm").unwrap().lengths.contains(&16));
        assert!(format_by_name("lm").unwrap().lengths.contains(&32));
        assert!(format_by_name("bcrypt").unwrap().lengths.is_empty());
    }
}
