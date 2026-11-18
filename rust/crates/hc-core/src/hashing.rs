//! Digest adapters for every fast/salted format, mirroring
//! `src/hash_cracker/hashing.py` semantics exactly.

use cipher::{Block, BlockCipherEncrypt, KeyInit};
use digest::Digest;
use des::Des;
use md4::Md4;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

use crate::formats::{self, Format};

/// Lowercase hex digest of `data` for a fast format identifier, or `None`
/// when the format is not a bare digest.
pub fn hex_digest(algorithm: &str, data: &[u8]) -> Option<String> {
    let digest: Vec<u8> = match algorithm {
        "md5" => Md5::digest(data).to_vec(),
        "sha1" => Sha1::digest(data).to_vec(),
        "sha224" => Sha224::digest(data).to_vec(),
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        "sha512_224" => Sha512_224::digest(data).to_vec(),
        "sha512_256" => Sha512_256::digest(data).to_vec(),
        "ripemd160" => Ripemd160::digest(data).to_vec(),
        "md4" => Md4::digest(data).to_vec(),
        _ => return None,
    };
    Some(hex::encode(digest))
}

/// NTLM: MD4 over the UTF-16LE encoding of the candidate.
pub fn ntlm_hex(candidate: &str) -> String {
    let utf16: Vec<u8> = candidate.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    hex::encode(Md4::digest(&utf16))
}

/// LM hash: uppercase candidate, truncated/padded to 14 bytes, split into two
/// 7-byte halves expanded to odd-parity DES keys, each ECB-encrypting `KGS!@#$%`.
///
/// The DES key schedule ignores parity bits, so the standard 7-bit expansion
/// (shifted left) is used without explicit parity adjustment.
pub fn lm_raw(candidate: &str) -> [u8; 16] {
    let upper: String = candidate.to_uppercase();
    let mut bytes: Vec<u8> = upper.as_bytes().to_vec();
    // Latin-1-style truncation to the 14 significant bytes (passlib treats
    // non-latin-1 candidates as an encoding error; the engine validates first).
    bytes.truncate(14);
    bytes.resize(14, 0);

    const MAGIC: [u8; 8] = *b"KGS!@#$%";
    let mut out = [0u8; 16];
    for (half, out_slice) in bytes.chunks(7).zip(out.chunks_mut(8)) {
        let key = expand_des_key(half);
        let mut block = Block::<Des>::default();
        block.copy_from_slice(&MAGIC);
        let cipher = Des::new_from_slice(&key).expect("DES key is always 8 bytes");
        cipher.encrypt_block(&mut block);
        out_slice.copy_from_slice(block.as_slice());
    }
    out
}

pub fn lm_hex(candidate: &str) -> String {
    hex::encode(lm_raw(candidate))
}

/// Expand 7 bytes into a DES key of 8 bytes (each holding 7 key bits, MSB
/// aligned, parity bit low — the bit DES discards).
fn expand_des_key(input: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = input[0] >> 1;
    key[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2);
    key[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3);
    key[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4);
    key[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5);
    key[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6);
    key[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7);
    key[7] = input[6] & 0x7f;
    for byte in &mut key {
        *byte <<= 1;
    }
    key
}

/// Digest for a salted format: `pass||salt` or `salt||pass`, both UTF-8.
pub fn salted_hex(format: &Format, pass: &str, salt: &str) -> Option<String> {
    let base = format.base?;
    let data: Vec<u8> = if format.salt_first? {
        let mut v = salt.as_bytes().to_vec();
        v.extend_from_slice(pass.as_bytes());
        v
    } else {
        let mut v = pass.as_bytes().to_vec();
        v.extend_from_slice(salt.as_bytes());
        v
    };
    hex_digest(base, &data)
}

/// Candidate encoding note: wordlist candidates are hashed as UTF-8, matching
/// the Python engine (`candidate.encode("utf-8")`).
pub fn candidate_digest(format: &Format, pass: &str, salt: Option<&str>) -> Option<String> {
    match format.kind {
        formats::Kind::Salted => salted_hex(format, pass, salt.expect("salted needs salt")),
        formats::Kind::Fast => match format.name {
            "ntlm" => Some(ntlm_hex(pass)),
            "lm" => Some(lm_hex(pass)),
            _ => hex_digest(format.name, pass.as_bytes()),
        },
        formats::Kind::Adaptive => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_1320_md4_vectors() {
        assert_eq!(
            hex_digest("md4", b"").unwrap(),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert_eq!(
            hex_digest("md4", b"abc").unwrap(),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
    }

    #[test]
    fn rfc_vectors_for_standard_digests() {
        assert_eq!(
            hex_digest("md5", b"abc").unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex_digest("sha1", b"abc").unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_digest("sha256", b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_digest("sha512", b"abc").unwrap(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex_digest("ripemd160", b"abc").unwrap(),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
        assert_eq!(hex_digest("ripemd160", b"").unwrap(), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        // sha512_224/sha512_256 values generated from Python hashlib (parity source).
        assert_eq!(
            hex_digest("sha512_224", b"abc").unwrap(),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
        assert_eq!(
            hex_digest("sha512_256", b"abc").unwrap(),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
        assert_eq!(hex_digest("sha224", b"abc").unwrap(), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        assert_eq!(
            hex_digest("sha384", b"abc").unwrap(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn ntlm_matches_md4_over_utf16le() {
        // Vectors generated from passlib nthash (parity source).
        assert_eq!(ntlm_hex(""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(ntlm_hex("abc"), "e0fba38268d0ec66ef1cb452d5885e53");
        assert_eq!(ntlm_hex("hashcat"), "b4b9b02e6f09a9bd760f388b67351e2b");
        let utf16: Vec<u8> = "abc".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(ntlm_hex("abc"), hex::encode(Md4::digest(&utf16)));
    }

    #[test]
    fn lm_known_vectors() {
        // Vectors generated from passlib lmhash (parity source).
        assert_eq!(lm_hex(""), "aad3b435b51404eeaad3b435b51404ee");
        assert_eq!(lm_hex("password"), "e52cac67419a9a224a3b108f3fa6cb6d");
        assert_eq!(lm_hex("hashcat"), "299bd128c1101fd6aad3b435b51404ee");
        // LM is case-insensitive by construction.
        assert_eq!(lm_hex("HASHCAT"), lm_hex("hashcat"));
    }

    #[test]
    fn lm_prefix_comparison_support() {
        // 16-hex target == first half of the full LM digest.
        let full = lm_hex("password");
        assert_eq!(&full[..16], "e52cac67419a9a22");
    }

    #[test]
    fn salted_digests_follow_python_order() {
        let pass = &formats::format_by_name("md5_pass_salt").unwrap();
        let salted = &formats::format_by_name("md5_salt_pass").unwrap();
        // md5("hashcat" + "salt") vs md5("salt" + "hashcat")
        assert_eq!(
            salted_hex(pass, "hashcat", "salt").unwrap(),
            hex_digest("md5", b"hashcatsalt").unwrap()
        );
        assert_eq!(
            salted_hex(salted, "hashcat", "salt").unwrap(),
            hex_digest("md5", b"salthashcat").unwrap()
        );
    }
}
