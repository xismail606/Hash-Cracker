//! Plaintext encryption at rest, byte-compatible with the Python backend:
//! scrypt (N=16384, r=8, p=1, dklen=32) → Fernet token (AES-128-CBC +
//! HMAC-SHA256) → `enc1:`-prefixed ciphertext in `matched_plaintext`.
//! See specs/003-rust-backend/contracts/storage.md.

use std::path::Path;

use aes::Aes128;
use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use base64::Engine;
use hmac::Mac;
use rand::RngCore;

use crate::store::{HistoryError, Store};

/// Ciphertext marker stored inline in `matched_plaintext`.
pub const ENCRYPT_PREFIX: &str = "enc1:";
const ENC_SALT_KEY: &str = "enc_salt";
const ENC_VERIFY_KEY: &str = "enc_verify";
/// scrypt parameters (pinned by the Python implementation).
const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const KEY_LEN: usize = 32;

type CbcEncryptor = cbc::Encryptor<Aes128>;
type CbcDecryptor = cbc::Decryptor<Aes128>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Errors from encryption helpers (messages match Python"s `HistoryError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub String);

/// Derive the 32-byte Fernet key from a passphrase and hex-encoded salt.
pub fn derive_key(passphrase: &str, salt_hex: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let salt = hex::decode(salt_hex).map_err(|_| {
        CryptoError("The stored encryption salt is invalid; history cannot be unlocked.".into())
    })?;
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|_| CryptoError("Invalid scrypt parameters.".into()))?;
    let mut out = [0u8; KEY_LEN];
    scrypt::scrypt(passphrase.as_bytes(), &salt, &params, &mut out)
        .map_err(|_| CryptoError("Key derivation failed.".into()))?;
    Ok(out)
}

/// Random 16-byte salt, hex-encoded (Python: `secrets.token_bytes(16)`).
pub fn new_salt_hex() -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    hex::encode(salt)
}

/// Random Fernet IV.
fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

/// Fernet token of `b"ok"` used as the passphrase verification record.
fn verify_token(key: &[u8; KEY_LEN]) -> Result<String, CryptoError> {
    fernet_encrypt(key, b"ok")
}

/// Build a Fernet token: version || timestamp(8B BE) || IV || ciphertext ||
/// HMAC-SHA256(signing key, version||timestamp||IV||ciphertext), urlsafe-B64.
pub fn fernet_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String, CryptoError> {
    let sign_key = &key[..16];
    let enc_key: [u8; 16] = key[16..32].try_into().expect("key length");
    let iv = random_iv();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CryptoError("System clock is before the epoch.".into()))?
        .as_secs();

    // cipher 0.5's Key/Iv are hybrid-array types; the Into target cannot be
    // inferred from slices directly (clippy sees it as a no-op conversion).
    #[allow(clippy::useless_conversion)]
    let encryptor = CbcEncryptor::new((&enc_key).into(), (&iv).into());
    let padded = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);

    let mut message = Vec::with_capacity(9 + 16 + padded.len());
    message.push(0x80u8);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&iv);
    message.extend_from_slice(&padded);

    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(sign_key)
        .map_err(|_| CryptoError("Invalid HMAC key length.".into()))?;
    mac.update(&message);
    let tag = mac.finalize().into_bytes();

    let mut token_bytes = message;
    token_bytes.extend_from_slice(&tag);
    // Python's urlsafe_b64encode emits padded tokens, and the installed
    // cryptography version requires padding — match it exactly.
    Ok(base64::engine::general_purpose::URL_SAFE.encode(token_bytes))
}

/// Verify and decrypt a Fernet token (no TTL check, matching Python usage).
pub fn fernet_decrypt(key: &[u8; KEY_LEN], token: &str) -> Result<Vec<u8>, CryptoError> {
    let sign_key = &key[..16];
    // Python emits URL-safe base64 WITH padding; accept both forms.
    let token = token.trim_end_matches('=');
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| CryptoError("The stored token is malformed.".into()))?;
    if raw.len() < 41 || raw[0] != 0x80 {
        return Err(CryptoError("The stored token is malformed.".into()));
    }
    let body_len = raw.len() - 32;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(sign_key)
        .map_err(|_| CryptoError("Invalid HMAC key length.".into()))?;
    mac.update(&raw[..body_len]);
    let expected = mac.finalize().into_bytes();
    let tag = &raw[body_len..];
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(CryptoError("Token authentication failed.".into()));
    }
    let iv = &raw[9..25];
    let ciphertext = &raw[25..body_len];
    let enc_key: [u8; 16] = key[16..32].try_into().expect("key length");
    let iv_arr: [u8; 16] = iv.try_into().expect("iv length");
    #[allow(clippy::useless_conversion)]
    let decryptor = CbcDecryptor::new((&enc_key).into(), (&iv_arr).into());
    let plaintext = decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError("The stored token is malformed.".into()))?;
    Ok(plaintext)
}

/// Ensure the per-database salt exists; returns its hex value.
pub fn ensure_salt(store: &Store) -> Result<String, HistoryError> {
    if let Some(existing) = store.meta_get(ENC_SALT_KEY)? {
        return Ok(existing);
    }
    let salt = new_salt_hex();
    store.meta_set(ENC_SALT_KEY, &salt)?;
    Ok(salt)
}

/// Unlock (or initialize) the store"s encryption with a passphrase; returns
/// the derived key. First call with a passphrase stores the verify token.
pub fn init(store: &Store, passphrase: &str) -> Result<[u8; KEY_LEN], HistoryError> {
    let salt = ensure_salt(store)?;
    let key = derive_key(passphrase, &salt)
        .map_err(|e| HistoryError(e.0))?;
    match store.meta_get(ENC_VERIFY_KEY)? {
        None => {
            let token = verify_token(&key).map_err(|e| HistoryError(e.0))?;
            store.meta_set(ENC_VERIFY_KEY, &token)?;
        }
        Some(token) => {
            let ok = fernet_decrypt(&key, &token)
                .ok()
                .filter(|plain| plain == b"ok");
            if ok.is_none() {
                return Err(HistoryError("Wrong passphrase.".to_string()));
            }
        }
    }
    Ok(key)
}

/// Encrypt a plaintext for storage: `enc1:` + Fernet token.
pub fn encrypt_stored(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String, HistoryError> {
    let token = fernet_encrypt(key, plaintext.as_bytes()).map_err(|e| HistoryError(e.0))?;
    Ok(format!("{ENCRYPT_PREFIX}{token}"))
}

/// Decrypt an `enc1:`-prefixed value; `None` when the value is not encrypted.
pub fn decrypt_stored(key: &[u8; KEY_LEN], value: &str) -> Option<Result<String, CryptoError>> {
    let rest = value.strip_prefix(ENCRYPT_PREFIX)?;
    Some(fernet_decrypt(key, rest).map(|bytes| String::from_utf8_lossy(&bytes).to_string()))
}

/// Convenience for CLI flows that already have a database path.
pub fn init_at_path(db_path: &Path, passphrase: &str) -> Result<[u8; KEY_LEN], HistoryError> {
    let store = Store::open(db_path)?;
    init(&store, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fernet_roundtrip() {
        let key = [7u8; KEY_LEN];
        let token = fernet_encrypt(&key, b"hashcat").unwrap();
        let plain = fernet_decrypt(&key, &token).unwrap();
        assert_eq!(plain, b"hashcat");
    }

    #[test]
    fn fernet_token_starts_with_version_byte() {
        use base64::Engine;
        let key = [1u8; KEY_LEN];
        let token = fernet_encrypt(&key, b"x").unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.trim_end_matches('='))
            .unwrap();
        assert_eq!(raw[0], 0x80);
    }

    #[test]
    fn fernet_rejects_tampered_token() {
        let key = [3u8; KEY_LEN];
        let token = fernet_encrypt(&key, b"secret").unwrap();
        // Flip a character in the middle of the token.
        let mut tampered: Vec<char> = token.chars().collect();
        let mid = tampered.len() / 2;
        tampered[mid] = if tampered[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = tampered.into_iter().collect();
        assert!(fernet_decrypt(&key, &tampered).is_err());
        assert!(fernet_decrypt(&[4u8; KEY_LEN], &token).is_err());
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        init(&store, "correct horse").unwrap();
        let err = init(&store, "wrong horse").unwrap_err();
        assert_eq!(err.0, "Wrong passphrase.");
    }

    #[test]
    fn stored_value_roundtrip_and_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        let key = init(&store, "pw").unwrap();
        let stored = encrypt_stored(&key, "hashcat").unwrap();
        assert!(stored.starts_with(ENCRYPT_PREFIX));
        let decrypted = decrypt_stored(&key, &stored).unwrap().unwrap();
        assert_eq!(decrypted, "hashcat");
        assert!(decrypt_stored(&key, "plain-value").is_none());
    }

    #[test]
    fn salt_is_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        let salt1 = ensure_salt(&store).unwrap();
        let salt2 = ensure_salt(&store).unwrap();
        assert_eq!(salt1, salt2);
        assert_eq!(salt1.len(), 32); // 16 bytes hex
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;

    /// Python: hashlib.scrypt(b"test1234", salt=<hex>, n=2**14, r=8, p=1, dklen=32)
    #[test]
    fn scrypt_matches_hashlib() {
        let key = derive_key(
            "test1234",
            "a1f1fb2455081a976293a1e33609ca36",
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "453d0b9e807b64c8c5a993caf101a4495ad8040286252cb1679f6ce9155cc226"
        );
    }
}

#[cfg(test)]
mod fernet_parity_tests {
    use super::*;

    /// Python: Fernet(urlsafe_b64encode(key453d...)).encrypt(b"ok")
    #[test]
    fn decrypts_python_fernet_token() {
        let key = derive_key(
            "test1234",
            "a1f1fb2455081a976293a1e33609ca36",
        )
        .unwrap();
        let token = "gAAAAABq_gp8etf3DQRZges9HdJTlUOHS0NC51XwQ2LblBBy_MTnW2NnkKq9xkAtJKxXxmg45JFr9xk5QOvnR6xJOACQP5PeEw==";
        let plain = fernet_decrypt(&key, token).expect("decrypts python token");
        assert_eq!(plain, b"ok");
    }
}

#[cfg(test)]
mod token_diag {
    use super::*;

    #[test]
    fn rust_token_structure_matches_fernet() {
        let key = derive_key("test1234", "a1f1fb2455081a976293a1e33609ca36").unwrap();
        let token = fernet_encrypt(&key, b"ok").unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.trim_end_matches('='))
            .unwrap();
        assert_eq!(raw[0], 0x80);
        // IV lives at [9..25]; HMAC is the last 32 bytes.
        assert!(raw.len() >= 41, "len {}", raw.len());
        println!("DIAG token len={} ts={:02x?}", raw.len(), &raw[1..9]);
        // Verify our own HMAC construction manually.
        let body_len = raw.len() - 32;
        let (sign_key, _) = key.split_at(16);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(sign_key).unwrap();
        mac.update(&raw[..body_len]);
        let expected = mac.finalize().into_bytes();
        assert_eq!(expected.as_slice(), &raw[body_len..]);
    }
}
