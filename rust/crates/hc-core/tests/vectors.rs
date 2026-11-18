//! Full-format vector sweep: every supported format verifies a Python-produced
//! example hash for the candidate `hashcat` (salt `salt` for salted formats).
//! Parity source: passlib + hashlib in this repository's venv.

use hc_core::candidates::HashlistTarget;
use hc_core::engine::{run_audit, run_hashlist_audit, AuditOptions, CandidateStream, Control, HashlistOptions};
use hc_core::formats::{format_by_name, Kind};
use hc_core::hashing;

const CANDIDATE: &str = "hashcat";
const SALT: &str = "salt";

/// (algorithm, expected digest or adaptive hash) — generated on this machine.
const VECTORS: &[(&str, &str)] = &[
    ("md5", "8743b52063cd84097a65d1633f5c74f5"),
    ("sha256", "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"),
    ("ntlm", "b4b9b02e6f09a9bd760f388b67351e2b"),
    ("sha1", "b89eaac7e61417341b710b727768294d0e6a277b"),
    ("sha224", "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198"),
    ("sha384", "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"),
    ("sha512", "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"),
    ("md4", "afe04867ec7a3845145579a95f72eca7"),
    ("lm", "299bd128c1101fd6aad3b435b51404ee"),
    ("md5_pass_salt", "cd75d65ba78809e8e942ac058bb61596"),
    ("md5_salt_pass", "d12052308c473c05d262dada6cf5b9ca"),
    ("sha1_pass_salt", "a688d439246f4745209b02de96c2c99e48092014"),
    ("sha1_salt_pass", "362e3ae280101a00109f4d57f5377f36b8b775d8"),
    ("sha256_pass_salt", "38800d934742c0a8d0937b447b7b6845993f6ed21cc0343cd8088485b674b66b"),
    ("sha256_salt_pass", "994db6263b7a2367a5be0402d8c16cf99348986e213c843e2cf1a7cd8a75a2c0"),
    ("sha512_pass_salt", "61847d429e0d8a757b87f6bb760df692aaf3c629e80b2cdffce76f73377b1b6c84a3bf2351de125026f1b14da542c99628ed77373dd62a8ab8d1af5fa3fc1107"),
    ("sha512_salt_pass", "69aef0813cdde1715232f0a898e020d1fb0b318a46a79c9c82179f5bea1d773bd0c37d9f81699fd257b13fa7f83d947df321d4d07a9f7ad3890323a29a266166"),
    ("sha512_224", "6e8f8ef6b20f7ad1a75f5bac75585b5a98b890013d317a9b45f477d1"),
    ("sha512_256", "7bf80da439438473433145774c02ca78960b4135d5d4eb52c656cda2cb45010f"),
    ("ripemd160", "012cb9b334ec1aeb71a9c8ce85586082467f7eb6"),
    ("bcrypt", "$2b$10$XLv5ooW9GUHtv6NOUZAg6.VVEOi9VzKDLnw1JqdCOyFSAU8E1xDf6"),
    ("sha512crypt", "$6$d0S69S3p3pH.QS3j$WHSOwCYUUEtminwSg8N.2SiUzHB4EBqFCq5Z1wc65syYi1a3MeZEJlF0BKg5GTq/qHLafLn.aEaetnvKzaosM/"),
    ("phpass", "$P$5WeP/9qWOc7uHJPMUhcuhM.8qGYpS61"),
];

/// Fixed batch stream over a small wordlist containing the target candidate.
struct WordSource {
    words: Vec<String>,
    index: usize,
}

impl WordSource {
    fn new() -> Self {
        Self {
            words: vec!["alpha".into(), "beta".into(), CANDIDATE.into(), "delta".into()],
            index: 0,
        }
    }
}

impl CandidateStream for WordSource {
    fn next_batch(&mut self, max: usize) -> Option<Vec<String>> {
        if self.index >= self.words.len() {
            return None;
        }
        let end = (self.index + max).min(self.words.len());
        let batch = self.words[self.index..end].to_vec();
        self.index = end;
        Some(batch)
    }
}

fn candidate_digest(algorithm: &str, candidate: &str, salt: Option<&str>) -> Option<String> {
    let format = format_by_name(algorithm)?;
    match format.kind {
        Kind::Adaptive => None,
        _ => hashing::candidate_digest(format, candidate, salt),
    }
}

#[test]
fn every_format_matches_python_vector() {
    for (algorithm, expected) in VECTORS {
        let format = format_by_name(algorithm).expect("registry algorithm");
        match format.kind {
            Kind::Adaptive => {
                assert!(
                    hc_core::adaptive::verify_adaptive(algorithm, CANDIDATE, expected),
                    "adaptive verify failed for {algorithm}"
                );
                assert!(
                    !hc_core::adaptive::verify_adaptive(algorithm, "monkey", expected),
                    "adaptive verify must reject wrong candidates ({algorithm})"
                );
            }
            _ => {
                let salt = format.is_salted().then_some(SALT);
                let digest =
                    candidate_digest(algorithm, CANDIDATE, salt).expect("fast/salted digest");
                assert_eq!(
                    digest, *expected,
                    "digest mismatch for {algorithm}"
                );
                // Digest-level direct comparison of the full target.
                let target = format_by_name(algorithm).unwrap();
                let _ = target;
            }
        }
    }
}

#[test]
fn engine_finds_every_format() {
    for (algorithm, expected) in VECTORS {
        let format = format_by_name(algorithm).expect("registry algorithm");
        let control = Control::new();
        let mut stream = WordSource::new();
        let result = run_audit(
            AuditOptions {
                format,
                target: expected,
                salt: format.is_salted().then_some(SALT),
                workers: 2,
                budget: Some(100_000),
                total_space: Some(4),
                resume: None,
            },
            &mut stream,
            &control,
            None,
        );
        assert_eq!(result.status, "match", "engine miss for {algorithm}");
        assert_eq!(result.matched_plaintext.as_deref(), Some(CANDIDATE));
        assert_eq!(result.attempts, 3);
    }
}

#[test]
fn hashlist_sweep_matches_every_fast_format() {
    // Salted formats carry no per-target salt in hashlists and adaptive
    // formats never join one — both are rejected at parse time (Python
    // parity). The sweep therefore covers the bare-digest formats only.
    let targets: Vec<HashlistTarget> = VECTORS
        .iter()
        .filter(|(algorithm, _)| {
            let format = format_by_name(algorithm).unwrap();
            format.kind == Kind::Fast
        })
        .enumerate()
        .map(|(id, (algorithm, hash))| HashlistTarget {
            id,
            algorithm: format_by_name(algorithm).unwrap().name,
            hash: hash.to_string(),
            line: id + 1,
        })
        .collect();
    assert_eq!(targets.len(), 12); // 23 - 8 salted - 3 adaptive
    let control = Control::new();
    let mut stream = WordSource::new();
    let result = run_hashlist_audit(
        HashlistOptions {
            workers: 2,
            budget: Some(1_000),
            total_space: Some(4),
            resume: None,
        },
        &targets,
        &mut stream,
        &control,
        None,
    );
    let unmatched: Vec<&str> = result
        .targets
        .iter()
        .filter(|t| t.status != "match")
        .map(|t| t.algorithm)
        .collect();
    assert!(
        unmatched.is_empty(),
        "hashlist miss for {unmatched:?} (status {})",
        result.status
    );
    assert_eq!(result.status, "match");
    for target in &result.targets {
        assert_eq!(target.matched_plaintext.as_deref(), Some(CANDIDATE));
    }
}
