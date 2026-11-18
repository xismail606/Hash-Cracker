//! Adaptive format verification: bcrypt, sha512crypt, and portable phpass.
//!
//! Adaptive formats are verify-only (no shape identification, no hashlist
//! participation), mirroring `src/hash_cracker/hashing.py`.

/// Verify a candidate against an adaptive-format stored hash.
///
/// `format_name` must be one of the adaptive registry names; unknown names
/// simply fail verification.
pub fn verify_adaptive(format_name: &str, candidate: &str, stored: &str) -> bool {
    match format_name {
        "bcrypt" => bcrypt::verify(candidate, stored).unwrap_or(false),
        "sha512crypt" => sha_crypt::sha512_check(candidate, stored).is_ok(),
        "phpass" => phpass_verify(candidate, stored),
        _ => false,
    }
}

/// Portable phpass (`$P$`), implemented in-crate: iterated MD5 over
/// `(salt || candidate)` with the `itoa64` alphabet `./0-9A-Za-z`.
/// Mirrors passlib's portable-phpass handler (used by WordPress/phpBB).
mod phpass_inner {
    use digest::Digest;
    use md5::Md5;

    pub const ITOA64: &[u8; 64] =
        b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    pub fn index64(ch: u8) -> Option<usize> {
        ITOA64.iter().position(|&c| c == ch)
    }

    /// Encode the low `count * 6` bits of `value` in the itoa64 alphabet.
    pub fn encode64(mut value: u128, count: usize) -> String {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(ITOA64[(value & 0x3f) as usize]);
            value >>= 6;
        }
        String::from_utf8(out).expect("itoa64 is ASCII")
    }

    /// Compute the 16-byte portable phpass digest for a candidate.
    /// `stored` is the full `$P$<cost><salt>` string.
    pub fn digest(candidate: &str, stored: &str) -> Option<[u8; 16]> {
        let bytes = stored.as_bytes();
        if bytes.len() < 12 || !bytes.starts_with(b"$P$") {
            return None;
        }
        let count_log2 = index64(bytes[3])?;
        if count_log2 > 30 {
            return None;
        }
        let rounds = 1u64 << count_log2;
        let salt = &bytes[4..12];

        let mut hash: Vec<u8> = {
            let mut h = Md5::new();
            h.update(salt);
            h.update(candidate.as_bytes());
            h.finalize().to_vec()
        };
        for _ in 0..rounds {
            let mut h = Md5::new();
            h.update(&hash);
            h.update(candidate.as_bytes());
            hash = h.finalize().to_vec();
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash);
        Some(out)
    }
}

fn phpass_verify(candidate: &str, stored: &str) -> bool {
    use phpass_inner::*;

    let Some(computed) = digest(candidate, stored) else {
        return false;
    };
    let body = &stored.as_bytes()[12..];
    if body.len() < 22 {
        return false;
    }
    // The digest (16 bytes) is packed little-endian and emitted as 22 chars.
    let value = u128::from_le_bytes(computed);
    encode64(value, 22) == String::from_utf8_lossy(&body[..22])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_verify_roundtrip() {
        let stored = bcrypt::hash("hashcat", 4).expect("hash");
        assert!(verify_adaptive("bcrypt", "hashcat", &stored));
        assert!(!verify_adaptive("bcrypt", "monkey", &stored));
    }

    #[test]
    fn sha512crypt_verify_roundtrip() {
        let stored = sha_crypt::sha512_simple(
            "hashcat",
            &sha_crypt::Sha512Params::new(1_000).expect("params"),
        )
        .expect("hash");
        assert!(verify_adaptive("sha512crypt", "hashcat", &stored));
        assert!(!verify_adaptive("sha512crypt", "monkey", &stored));
    }

    #[test]
    fn phpass_verify_known_passlib_vector() {
        // passlib.hash.phpass.using(rounds=7).hash("hashcat") — generated on this machine.
        let stored = PHPASS_VECTOR;
        assert!(phpass_verify("hashcat", stored), "vector: {stored}");
        assert!(!phpass_verify("monkey", stored));
    }

    #[test]
    fn phpass_rejects_malformed_stored() {
        assert!(!phpass_verify("hashcat", "garbage"));
        assert!(!phpass_verify("hashcat", "$P$"));
        assert!(!phpass_verify("hashcat", "$P$zzzzzzzzzzzzzzzzzzzzzzzzzz"));
        assert!(!verify_adaptive("unknown_format", "x", "y"));
    }

    /// Parity fixture: passlib.hash.phpass.using(rounds=7).hash("hashcat").
    const PHPASS_VECTOR: &str = "$P$52XytkJSIwsl3uIsdMw5HZd2kkTnLa0";
}
