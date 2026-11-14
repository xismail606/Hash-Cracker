// Condensed release notes, newest first. Mirrors the repository root
// CHANGELOG.md in the same form the changelog modal used to show. Both the
// /changelog page and any future quick-view UI read from here.
export const CHANGELOG = [
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
