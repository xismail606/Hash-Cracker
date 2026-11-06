# Changelog

All notable changes to the Hash Cracker project are documented here.
Dates use YYYY-MM-DD. The project follows the four-phase v1 plan
([specs/001-offline-password-audit](specs/001-offline-password-audit)) and the
v2 feature-expansion plan ([specs/002-feature-expansion](specs/002-feature-expansion)).

## Unreleased

### Changed

- Increased the dashboard wordlist upload limit from 100 MiB to 256 MiB.
- Oversized upload requests now return a readable JSON `413` response that
  states the configured limit.
- Brute-force progress and ETA use the effective search limit (the smaller of
  the candidate space and configured budget).

### Fixed

- docs/index.html mobile layout: the fixed navbar no longer overflows narrow
  screens (the version pill and the Download button hide below 640px), the mock
  terminal bar stays on one line, a scroll failsafe guarantees reveal sections
  appear even when IntersectionObserver is throttled, and the hero test-count
  stat tracks the suite (145).
- Parallel audits now preserve candidate order and first-match positions,
  enforce candidate budgets at batch boundaries, and keep attempt counts exact.
  Resumable single-target runs continue from the next unprocessed candidate.
- Clearing local history also removes hashlist batch summaries.
- Withheld plaintext stays hidden in CLI and dashboard results for hashlist
  matches as well as single-target matches.
- Dashboard navigation headings now have matching section IDs; removed the
  LinkedIn footer link and added a site favicon.

### Tests

- Added regression coverage for parallel match ordering, budget truncation,
  pause/resume accounting, oversized uploads, batch-history clearing, and
  withheld hashlist plaintext.

## v2.0.0 — 2026-11-06 (Feature Expansion)

### Added

**Formats**
- RIPEMD-160 (40-hex; pure-Python, dependency-free; 40-hex is now ambiguous
  between SHA-1 and RIPEMD-160)
- SHA-512/224 (56-hex; ambiguous with SHA-224) and SHA-512/256 (64-hex;
  ambiguous with SHA-256)
- Adaptive formats verified against the full stored hash string via Passlib:
  bcrypt, sha512crypt, phpass (require the `adaptive` extra; extremely slow —
  keep budgets small)

**Salted hashes (Phase 5)**
- Eight salted fast-hash formats: `md5($pass.$salt)`, `md5($salt.$pass)`,
  `sha1($pass.$salt)`, `sha1($salt.$pass)`, `sha256($pass.$salt)`,
  `sha256($salt.$pass)`, `sha512($pass.$salt)`, `sha512($salt.$pass)`
  (hashcat modes 10/20/110/120/1410/1420/1710/1720) with `--salt` (CLI) and a
  salt field (dashboard); the salt is stored in the audit record

**Hashlist multi-target audits (Phase 6)**
- `audit --hashlist PATH`: one candidate stream compared against many targets
  in a single pass; explicit `algorithm:hash` prefixes, `#` comments, whole-file
  validation
- Per-target result tables in the CLI and dashboard; batch summaries in
  history (`audit_batches` table, `batch_id` column) and JSON export

**Rules & mutations (Phase 7)**
- `--rules PRESET` (dictionary mode): `capitalize`, `upper`, `lower`,
  `leetspeak`, `append_digits_0_99`, `append_years`, `all` — deterministic
  expansion inside the candidate budget

**Tooling & UX (Phase 8)**
- `benchmark` command: per-algorithm candidates/second on this machine
- Pause/resume for dashboard jobs with exact attempt accounting (refused for
  hashlist and rule-expanded runs; dictionary resume validates the wordlist)
- Dashboard export buttons (CSV/JSON) and `GET /api/export`
- ETA display in CLI progress and the dashboard
- `--no-store-plaintext` / dashboard checkbox: record matches without the
  plaintext (`plaintext_withheld` marker)
- LM-aware Auto-fit (suggests an uppercase-only alphabet for LM targets)

**Quality & security (Phase 9)**
- Automated pytest suite (131 tests): RFC 1320 vectors, hashcat example hashes
  for every format, engine attempt-accounting golden tests, web API behavior
- GitHub Actions CI running the suite on Windows and Linux
- Optional at-rest encryption of stored plaintexts (scrypt + Fernet,
  passphrase-derived key; `--encrypt` / `history --unlock` /
  `POST /api/history/unlock`; requires the `encrypt` extra)

### Fixed

- Engine attempt accounting when batches complete out of order (attempts are
  now monotonic in submission order; a match reports its exact position)
- Web API returned 400 instead of 413 for oversized wordlist uploads
- `/api/history` 500 when the application was created without an explicit
  database path
- Empty-string salts from form inputs are normalized to "no salt" instead of
  breaking every audit
- Frontend: the mutation-rules select and the hashlist upload input were
  silently missing from the built dashboard and are restored
- "Clear all history" state handling when a job is running

## v1.1.0 — 2026-11-05 (Format Expansion)

### Added

- SHA-1 (40-hex), SHA-224 (56-hex), SHA-384 (96-hex), SHA-512 (128-hex) via
  `hashlib`; MD4 (32-hex, raw UTF-8 — hashcat mode 900 semantics) via a
  pure-Python fallback validated against the RFC 1320 test vectors; LM
  (16-hex, first 8-byte DES block — hashcat mode 3000 semantics) via Passlib
- 32-hex hashes are now a three-way ambiguity (MD5 / NTLM / MD4)
- Validation against hashcat's official example hashes (all unsalted examples
  are `hash("hashcat")`)

### Changed

- Shape identification lists every compatible format and never guesses

## v1.0.0 — 2026-11-05 (Initial Release)

### Added

- Hash identification with honest ambiguity handling (MD5/NTLM at v1)
- Dictionary mode: UTF-8 streaming, bounded chunks, duplicates preserved,
  blank-line and invalid-UTF-8 handling
- Bounded brute-force mode: charset presets + literal characters, min/max
  length, candidate budget (default 1,000,000; hard maximum 10,000,000)
- Multiprocessing engine (1–8 workers, spawn context) with live progress,
  exact attempt accounting, cancellation
- CLI: `identify`, `audit`, `history`, `export`, `serve`
- Local web dashboard (Astro + React + Tailwind, loopback-only Flask,
  CSRF-protected, 100 MiB upload limit, one active job) with live progress,
  cancellation, per-run results, and audit history
- SQLite audit history with CSV/JSON export; successful matches store the
  plaintext/hash pair after explicit acknowledgement
- Clear-history button with confirmation modal
- Auto-fit: identifies the hash and pre-fills brute-force settings that fit
  the budget
- "Flask backend not detected" banner when the built page is served without
  the API
- CyberSec Arsenal-styled dashboard: dark/light themes, particle background,
  capsule navbar, footer, hashlist-ready layout
- Self-hosted Geist Sans/Mono fonts (no external requests at runtime)
- Full documentation: spec, plan, data model, contracts, quickstart,
  tasks (33 tasks)
