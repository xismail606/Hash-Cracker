//! Server-side encryption key cache and unlock flow.

use hc_history::Store;

/// Derive and cache the decryption key for unlocked history reads.
static KEY_CACHE: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);

/// Unlock history: verify the passphrase (or initialize encryption) and
/// cache the derived key in memory for subsequent /api/history reads.
pub fn unlock_store(store: &Store, passphrase: &str) -> Result<(), String> {
    match hc_history::init(store, passphrase) {
        Ok(key) => {
            *KEY_CACHE.lock().expect("key cache lock") = Some(key);
            Ok(())
        }
        Err(err) => Err(err.0),
    }
}

/// Cached key, if unlocked.
pub fn cached_key() -> Option<[u8; 32]> {
    *KEY_CACHE.lock().expect("key cache lock")
}
