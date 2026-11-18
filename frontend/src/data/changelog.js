// Condensed release notes, newest first. Mirrors the repository root
// CHANGELOG.md in the same form the changelog modal used to show. Both the
// /changelog page and any future quick-view UI read from here.
export const CHANGELOG = [
  {
    version: "v3.0.0",
    date: "2026-11-17",
    title: "Maintenance Round",
    items: [
      "Nine review fixes: hashlist worker counts, batch-inclusive exports, restart-safe paused jobs, a single format registry, full CI coverage, wider pause/resume, full LM digests, adaptive engine backoff, and docs alignment",
      "Paused jobs survive a server restart — state and uploads kept in paused_jobs/, then resumable or cancellable",
      "Pause/resume now covers hashlist and rule-expanded runs, not just single-target runs",
      "Pause/resume: rule-expansion budget honors the submitted max_candidates, matching the CLI",
      "New GET /api/formats — the dashboard reads algorithm labels, salted formats, presets, and limits from Python instead of duplicating them",
      "CSV export includes hashlist batch summaries (target_count); JSON export gains a batches array",
      "LM accepts the full 32-hex digest as well as the 16-hex first block; 32-hex is a four-way ambiguity (MD5/NTLM/MD4/LM)",
      "Engine batch waits use adaptive backoff (10 ms → 250 ms) instead of a fixed 0.1 s poll",
      "CI runs pytest on Python 3.11–3.13 (Ubuntu + Windows), ruff, and a frontend build",
      "Plaintext withholding is the default; opt in per run to store the recovered pair",
      "Paused-job artifacts are owner-only, and stale paused records are cleaned after 7 days",
      "Frontend quality: ESLint + Vitest tests, and a 75% pytest-cov gate in CI",
      "Engine workers recycle after 1,000 batches to bound long-audit memory",
      "167 automated tests",
    ],
  },
  {
    version: "v2.0.0",
    date: "2026-11-06",
    title: "Feature Expansion",
    items: [
      "Salted fast-hash formats — md5/sha1/sha256/sha512 with pass-salt or salt-pass order (hashcat 10/20/110/120/1410/1420/1710/1720)",
      "Hashlist multi-target audits — one candidate stream vs many targets, per-target results, batch records",
      "Mutation rules — capitalize, upper, lower, leetspeak, digit/year suffixes, combined preset",
      "benchmark command — per-algorithm candidates/second on this machine",
      "Pause & resume for dashboard jobs with exact attempt accounting",
      "Dashboard export (CSV/JSON) and ETA display",
      "Plaintext withholding option and optional at-rest encryption (passphrase-based)",
      "New formats: RIPEMD-160, SHA-512/224, SHA-512/256, bcrypt, sha512crypt, phpass",
      "131 automated tests + GitHub Actions CI on Windows and Linux",
    ],
  },
  {
    version: "v1.1.0",
    date: "2026-11-05",
    title: "Format Expansion",
    items: [
      "SHA-1, SHA-224, SHA-384, SHA-512 via hashlib",
      "MD4 (raw UTF-8, hashcat 900) and LM (first DES block, hashcat 3000)",
      "32-hex shapes are now a three-way ambiguity: MD5 / NTLM / MD4",
      "Validated against hashcat's official example hashes",
    ],
  },
  {
    version: "v1.0.0",
    date: "2026-11-05",
    title: "Initial Release",
    items: [
      "Hash identification with honest ambiguity handling",
      "Dictionary and bounded brute-force auditing with a multiprocessing engine (1–8 workers)",
      "CLI (identify / audit / history / export / serve) and local web dashboard",
      "SQLite history with CSV/JSON export and sensitive-data warnings",
      "Clear-history confirmation, Auto-fit settings, backend-detection banner",
      "CyberSec Arsenal-styled UI: dark/light themes, particles, self-hosted fonts",
    ],
  },
];
