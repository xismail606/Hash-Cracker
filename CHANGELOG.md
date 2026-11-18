# Changelog

All notable changes to the Hash Cracker project are documented here.
Dates use YYYY-MM-DD. The project follows the four-phase v1 plan
([specs/001-offline-password-audit](specs/001-offline-password-audit)) and the
v2 feature-expansion plan ([specs/002-feature-expansion](specs/002-feature-expansion)).

## v3.0.0 — 2026-11-17 (Maintenance Round)

A full-project review surfaced nine defects; all nine are fixed in this
release. Each item below states the symptom and the resolution.

### Review fixes

1. **Hashlist audits ignored the worker count** — every hashlist run used four
   workers. The dashboard route now validates and honors `workers` (1–8,
   default 4) exactly like single-target runs.
2. **CSV/JSON export omitted hashlist batches** — reports contained only
   per-target run rows. Exports from both `hashcrack export` and
   `GET /api/export` now include one row per batch summary (`target_count`
   column); the JSON file is an object with `runs` and `batches` arrays.
3. **Dashboard job state was lost on a server restart** — a paused job now
   persists its record and uploaded wordlist/hashlist under
   `<database dir>/paused_jobs/`, is restored in the `paused` state on
   startup, and can be resumed or cancelled afterwards. Starting a new audit
   discards a restored paused job. Runs executing at shutdown are not
   resumable, and the encryption passphrase is never persisted.
4. **Format registries were duplicated between Python and the JSX dashboard** —
   a new `GET /api/formats` endpoint exposes algorithm labels and kinds, the
   salted-format table, charset and rule presets, and the worker/budget limits.
   The dashboard renders from it and its local tables were deleted; only
   presentational status labels remain client-side.
5. **CI gaps** — the workflow now runs pytest on Python 3.11/3.12/3.13 across
   Ubuntu and Windows, plus a `ruff check` job and a frontend `npm run build`
   job that uploads the dashboard artifact.
6. **Pause/resume was refused for hashlist and rule-expanded runs** — the
   engine checkpoints hashlist progress (including targets matched before the
   pause) and rule-expanded streams; the dashboard API and UI accept them.
   The rule-expansion budget also now honors the submitted `max_candidates`
   field, matching the CLI.
7. **LM verified only the first seven characters** — `lm_hash` now returns the
   full 32-hex two-block digest. A 16-hex target keeps hashcat mode-3000
   semantics (first DES block, first seven characters), while a 32-hex target
   compares both blocks (fourteen characters). A 32-hex value is therefore a
   four-way ambiguity: MD5 / NTLM / MD4 / full LM.
8. **The engine busy-waited at a fixed 0.1 s** — batch waits use adaptive
   backoff (10 ms doubling to a 250 ms cap), so idle polling costs almost
   nothing while cancellation and pause stay responsive. Dashboard polling
   remains at 500 ms by design (local tool, negligible cost).
9. **Documentation drift** — README, CHANGELOG, the CLI/web contracts, the
   quickstart, the v2 plan, and `docs/README.md` now match the implemented
   behavior, repository layout, and test count.

### Added

- `GET /api/formats` (see item 4) as the single source of truth for the
  dashboard's format, preset, and limit tables.
- Restart-safe paused jobs (see item 3).
- Full 32-hex LM digest support in single-target and hashlist audits.
- Linux setup installs a user-local `hashcrack` command in `~/.local/bin`; it
  runs the project CLI from any working directory without activating the
  virtual environment.
- Dashboard Auto-fit now applies charset, length, and candidate-budget values
  to the form, covering the full configured search space up to the
  10,000,000-candidate hard limit.
- `hashcrack --version` prints the program version; `pyproject.toml`, the
  package, and `frontend/package.json` all advertise `3.0.0`.
- Paused-job hygiene: kept artifacts receive owner-only POSIX permissions
  (directory `0700`, files `0600`), and abandoned paused-job records older
  than 7 days are cleaned up (with their uploads) at startup.
- Frontend quality tooling: ESLint plus Vitest/Testing Library tests
  (`npm run lint`, `npm test`) covering the audit form, server-driven rule
  presets, and server algorithm labels; both run in CI.
- A pytest-cov coverage gate (`fail_under = 75`) runs in CI.
- Mypy static type checking (`check_untyped_defs`, clean across the package)
  runs as a CI job; `mypy` and `types-passlib` are in the dev extras.

### Changed

- The dashboard now withholds plaintext by default; ticking
  "store the recovered plaintext" opts in to keeping the plaintext/hash pair.
- Engine worker processes are recycled after 1,000 batches
  (`max_tasks_per_child`), bounding worker memory growth in long audits.

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
  stat tracks the suite (167).
- Parallel audits now preserve candidate order and first-match positions,
  enforce candidate budgets at batch boundaries, and keep attempt counts exact.
  Resumable single-target runs continue from the next unprocessed candidate.
- Clearing local history also removes hashlist batch summaries.
- Withheld plaintext stays hidden in CLI and dashboard results for hashlist
  matches as well as single-target matches.
- Dashboard navigation headings now have matching section IDs; removed the
  LinkedIn footer link and added a site favicon.

### Tests

- Automated pytest suite (167 tests plus a POSIX-only permissions test).
  Added regression coverage for parallel
  match ordering, budget truncation, pause/resume accounting, hashlist and
  rules pause/resume, restart recovery of paused jobs, hashlist worker counts,
  batch-inclusive CSV/JSON export, LM 16/32-hex targets, the `/api/formats`
  registry, oversized uploads, batch-history clearing, and withheld hashlist
  plaintext.

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
- Pause/resume for dashboard jobs with exact attempt accounting (at the v2.0.0
  release only single-target dictionary/brute-force runs; hashlist and
  rule-expanded support arrived in the v3 maintenance round; dictionary resume
  validates the wordlist)
- Dashboard export buttons (CSV/JSON) and `GET /api/export`
- ETA display in CLI progress and the dashboard
- `--no-store-plaintext` / dashboard checkbox: record matches without the
  plaintext (`plaintext_withheld` marker)
- LM-aware Auto-fit (suggests an uppercase-only alphabet for LM targets)

**Quality & security (Phase 9)**
- Automated pytest suite (131 tests at the v2.0.0 release; 167 plus a
  POSIX-only permissions test after the v3
  maintenance round): RFC 1320 vectors, hashcat example hashes
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
