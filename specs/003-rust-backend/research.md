# Research: Rust Backend (Phase 11)

Phase 0 output. Every decision below pins a choice the tasks can rely on. The Python backend was extracted into contract documents (`contracts/api.md`, `contracts/cli.md`, `contracts/storage.md`) via a full read of `src/hash_cracker/`; those are the parity targets, not this file.

## D1. Cargo workspace layout

**Decision**: a `rust/` workspace with four crates: `hc-core` (engine + formats + candidates + rules + benchmark), `hc-history` (SQLite store + encryption + exports + paused-job sidecar), `hc-server` (axum HTTP binary), `hc-cli` (`hashcrack-rs` binary re-using `hc-server`'s serve path).

**Rationale**: mirrors the Python module boundaries one-to-one, keeps the engine testable headlessly, and lets the CLI and server share one serve implementation. A single-crate binary would blur the parity seams and make `cargo test` slower.

**Alternatives considered**: one crate with modules (simpler but couples build of server deps into engine tests); separate repo (violates coexistence — everything must live in this tree); pyo3 embedding (rejected: user wants two independent backends, not a hybrid).

## D2. HTTP framework

**Decision**: `axum` on `tokio`, with hand-written handlers (no `tower-http::ServicesExt` magic for the API; `tower-http` only for body-limit helpers if needed).

**Rationale**: axum is the current mainstream Rust HTTP stack, supports multipart bodies natively (`axum::extract::Multipart`), and gives precise control over status codes and JSON shapes — which the contract requires (202 vs 200 vs 409 distinctions, exact error bodies).

**Alternatives considered**: actix-web (equally capable, less uniform middleware ergonomics); tiny_http + manual routing (too manual for multipart/limits); Flask-like micro frameworks (poem, salvo) — fewer eyes on them than axum.

**Parity notes to implement**: CSRF double-submit (`pa_csrf` cookie + `X-CSRF-Token` header + Origin/Referer same-host check on state-changing POSTs, exempting `/api/identify`); `Set-Cookie` with `SameSite=Strict; Path=/` and no HttpOnly; 409 single-job slot; multipart form parsing with 256 MiB cap (reject 257 MiB total content); static serving with Astro clean-URL convention (`/changelog` → `changelog/index.html`) and `Cache-Control: no-cache` headers; 503 JSON with the exact build-hint message when `static/index.html` is absent; loopback-only bind.

## D3. SQLite access

**Decision**: `rusqlite` with the `bundled` feature (compiles its own SQLite; no system-linking headaches on Windows) plus `PRAGMA` defaults matching Python's `sqlite3` behavior (WAL not used by Python — keep defaults identical to avoid file-behavior drift).

**Rationale**: the store is small and local; an async SQL layer (sqlx) adds compile weight for zero benefit here. `bundled` guarantees a working build on a fresh machine with only a C compiler present (msvc toolchain ships one).

**Alternatives considered**: sqlx (async, compile-time checked — unnecessary), diesel (ORM overhead), direct FFI (unsafe).

**Parity notes**: schema DDL byte-identical (see `contracts/storage.md`); the additive `MIGRATION_COLUMNS` mechanism (PRAGMA table_info → ALTER TABLE ADD COLUMN) must be re-implemented exactly so both backends migrate either's database; `list_runs` orders `run_id DESC` limit 100; `clear_runs` deletes both tables and returns combined rowcount; CSV column order fixed by `EXPORT_COLUMNS`.

## D4. Hash implementations (fast + salted formats)

**Decision**: RustCrypto crates — `md-5`, `sha1`, `sha2` (all digest lengths incl. SHA-512/224, SHA-512/256 via `Sha512_224`/`Sha512_256`), `ripemd`, `md-4` (NTLM = MD4 over UTF-16LE). LM: `des` crate (ECB, the two 7-byte halves expanded to 8-byte keys with odd parity) against the constant `KGS!@#$%`. Salted variants: `pass||salt` / `salt||pass` UTF-8 digests as in Python.

**Rationale**: RustCrypto digests are the de-facto standard, all in one ecosystem, and validate against the same RFC/hashcat vectors the Python suite uses.

**Alternatives considered**: Ring (no RIPEMD/MD4; rejects legacy algorithms by policy), implementing digests by hand (RIPEMD-160 pure-Python exists in-tree but Rust deserves the tested crate).

**Parity notes**: `ALGORITHM_NAMES` order, labels, digest lengths, ambiguity groups (16→lm; 32→md5,ntlm,md4,lm; 40→sha1,ripemd160; 56→sha224,sha512_224; 64→sha256,sha512_256; 96→sha384; 128→sha512) and the adaptive prefix rules (`$2`→bcrypt, `$6$`→sha512crypt, `$P$`→phpass) are pinned in `contracts/api.md` §formats — the Rust registry must reproduce them exactly. The LM 16-hex prefix comparison (hashcat mode 3000 semantics) must match `verify_candidate`.

## D5. Adaptive formats

**Decision**: `bcrypt` crate (bcrypt, `$2` prefix); `sha-crypt` crate (`sha512_crypt`, `$6$`); phpass — the crates.io `phpass` crate exists (0.1.3) but is unmaintained since 2021, so per the planned fallback the portable algorithm is implemented in-crate (MD5-based iterated `2^cost` with the `itoa64` salt alphabet `./0-9A-Za-z`), validated against Passlib-generated vectors.

**Rationale**: matches Passlib behavior for verify (adaptive formats are verify-only in this tool — no salt/length identification paths).

**Alternatives considered**: passthru to a C lib (build complexity on Windows); skipping adaptive in Rust (violates full-parity assumption in the spec).

**Parity notes**: adaptive targets never participate in shape identification or hashlists; verify semantics = Passlib `handler.verify` (constant-time compare of computed vs stored).

## D6. Encryption at rest (cross-backend compatible)

**Decision**: replicate exactly: scrypt KDF (`scrypt` crate; N=2^14, r=8, p=1, dklen=32, 16-byte random salt stored hex in `history_meta.enc_salt`) → Fernet token implemented **in-crate** (AES-128-CBC + HMAC-SHA256 via RustCrypto `aes`/`cbc`/`hmac`/`sha2`; the `fernet` crate was rejected because it pulls `openssl-sys`, which cannot build on a stock MSVC toolchain) → `enc1:`-prefixed ciphertext in `audit_runs.matched_plaintext`; verify token = Fernet encrypt of `b"ok"` in `history_meta.enc_verify`.

**Rationale**: SC-004/FR-210 demand byte-level compatibility with the Python implementation; Fernet tokens are self-describing (version byte + timestamp + IV + ciphertext + HMAC) so the two backends interoperate if parameters match.

**Alternatives considered**: age/chaCha20 (not interoperable with existing Python-encrypted rows), sqlcipher (different threat model, heavy).

**Parity notes**: `"<encrypted>"` placeholder when locked, `"<decryption failed>"` on bad row, `encrypted_count` in `/api/history`, export never decrypts. Unlock failure → `HistoryError("Wrong passphrase.")` → CLI exit 3 / API 403.

## D7. Parallelism model

**Decision**: bounded worker threads (std threads, N = `workers` 1–8, default 4) fed by a channel from the candidate source; in-flight batches capped at `max(workers*2, 4)`; batch size 8192; attempts accounting computed identically (attempts = offset + match_index + 1 on match; batch truncation to budget-remaining; max(attempts, offset+size) per completion). `rayon` is deliberately **not** used: rayon's work-stealing would break the deterministic batch-offset accounting the pause/resume semantics rely on.

**Rationale**: the Python engine's observable behavior (attempt math, resume offsets, pause between batches) is defined by its bounded out-of-order-capable pool; replicating its shape with a channel keeps parity testable, and threads are more than fast enough for the adaptive formats' cost floor.

**Alternatives considered**: rayon (parity risk on accounting), async task pool (same risk, more moving parts), single-threaded (would guarantee parity but fail SC-007 intent).

## D8. Time, ids, misc

**Decision**: `time` crate (formatting `YYYY-MM-DDTHH:MM:SS.mmmZ` UTC millisecond strings exactly like `utc_now()`), `uuid` crate v4 for job ids (lowercase hex, 32 chars) and batch ids (first 8 hex chars), `tempfile` for upload staging dirs.

## D9. Toolchain provisioning in setup scripts

**Decision**: mirror the existing Node.js pattern: if `cargo` is absent or `< some minimum` (rustup-installed stable), run rustup-init (`rustup-init.exe -y --default-toolchain stable` on Windows via PowerShell download from `https://win.rustup.rs/x86_64`; `curl https://sh.rustup.rs | sh -s -- -y` on POSIX) user-locally, then `cargo build --release` in `rust/` and copy/symlink the `hashcrack-rs` binary next to the Python entry points (Windows: `.venv/Scripts/`; POSIX: `.venv/bin/`, plus `~/.cargo/bin` is on PATH for rustup installs).

**Rationale**: the setup scripts already provision Node the same way; the operator's requirement is a prompt, not a manual toolchain walkthrough.

**Alternatives considered**: requiring preinstalled Rust (violates the auto-install expectation), packaging prebuilt binaries (no CI for that in this round; deferred).

## D10. Installer/serve script UX

**Decision** (full behavioral contract in `contracts/installer.md`): setup scripts accept `--backend python|rust|both` (and prompt interactively when absent, default Python on bare Enter); serve scripts accept `--backend python|rust` (or positional backend arg where a port arg already exists) and prompt when omitted; when only one backend is installed, they run it with a note instead of failing; detection = Python venv present (`.venv`) vs Rust binary present (`rust/target/release/hashcrack-rs(.exe)` or installed copy).

**Rationale**: keeps both existing scripts as the single entry points, honors "both exist" coexistence, and makes CI/non-interactive use possible.

## D11. Backend attribution

**Decision**: additive migration `("backend", "TEXT")` on `audit_runs` via Python's `MIGRATION_COLUMNS` (existing rows imply Python); `record_run` gains an optional `backend="python"` parameter written on every record; Rust writes `backend="rust"`; `/api/history` and both export formats gain the field (`"backend"` appended to `EXPORT_COLUMNS` after `plaintext_withheld`, before `target_count` in CSV order — final column order pinned in `contracts/storage.md`).

**Rationale**: FR-209/SC-004 need attribution without a schema break; the additive-ALTER mechanism is the established extension point.

## D12. Testing strategy

**Decision**: `cargo test` per crate (vectors for every format from RFC/hashcat/Passlib examples, candidate/rules/budget unit tests, storage tests against a temp DB, axum integration tests via `tower::ServiceExt::oneshot`); a new optional pytest file `tests/test_rust_parity.py` invoking the built `hashcrack-rs` against the Python CLI on the same temp DB (skip with a clear message when the Rust binary isn't built). Existing pytest suite must remain green (only additive changes: attribution assertions).

**Alternatives considered**: contract-test via HTTP fuzzing (deferred — the axum tests + parity shim cover the seams); CI matrix changes (deferred; no git ops this round).
