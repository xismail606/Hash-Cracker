# Implementation Plan: Feature Expansion (v2)

**Branch**: `002-feature-expansion` | **Date**: 2026-11-05 | **Spec**: [spec.md](spec.md)

## Summary

Five planned phases on top of the completed v1 tool: (5) salted fast hashes, (6) hashlist multi-target audits, (7) rule-based mutations, (8) tooling/UX upgrades, (9) test suite and optional plaintext encryption. A final research phase (10) quarantines speculative formats. Every phase keeps v1's contract: local-only, bounded, loopback-only, honest identification.

## Technical Context

**Language/Version**: Python 3.11+ backend (unchanged); Astro/React/JavaScript/Tailwind dashboard (unchanged); SQLite history (schema extended, see below).

**New dependencies**: none required for phases 5–8. Phase 9 uses `pytest` (dev dependency) and `cryptography` (optional extra) for at-rest encryption; phase 10 research items stay dependency-free.

**Storage**: `audit_runs` gains columns `salt TEXT`, `batch_id TEXT`, `plaintext_withheld INTEGER`; new optional `audit_batches` table. Schema changes are additive (`ALTER TABLE` / `CREATE TABLE IF NOT EXISTS`) with a lightweight migration on connect.

**Testing**: pytest suite becomes the primary gate (phase 9); manual hashcat-example validation continues for every new format.

**Performance goals**: salted hashing ≤ 1.5× unsalted cost per candidate (salt prefix/suffix append before digest); hashlist audit = one pass of the candidate stream against all targets (N-target audit ≈ single-target cost × N hashes, batched inside the worker); rule expansion adds ≤ 30% CPU overhead in the parent process.

**Constraints**: unchanged from v1 — offline, local files only, 1–8 workers, budget ≤ 10,000,000 candidates per run, dashboard on 127.0.0.1, CSRF on state-changing routes.

## Five Implementation Phases

1. **Salted fast hashes** — salt parameter across engine, CLI, web, history; eight hashcat salted modes.
2. **Hashlist multi-target audits** — one candidate stream compared against many targets; per-target results; batch reporting.
3. **Rules & mutations** — deterministic presets over dictionary candidates; budget-aware expansion.
4. **Tooling & UX** — benchmark, pause/resume, dashboard export, ETA, no-plaintext mode, LM-aware auto-fit.
5. **Security & quality** — pytest suite, CI on Windows/Linux, optional app-level plaintext encryption.
6. **Research (optional)** — RIPEMD-160, adaptive formats, SHA-512/224 & /256.

## Design Decisions

- **Salt as a run constant**: one salt per run (matches hashcat single-hash usage). The worker hashes `salt + candidate` or `candidate + salt` per the format's position. Validation lives in `algorithms.py` via a `SALTED_ALGORITHMS` registry mapping each name to (base digest, salt position) so the engine stays generic.
- **Hashlist inside the worker, not the parent**: each worker process receives the target list once and checks every candidate against all targets (dict lookup by digest) — N targets cost ≈ one hashing pass plus one dict probe, not N passes. A run ends `match` when any target matches; per-target attempts are derived from batch offsets; the match record names the winning target.
- **Mutations as a generator wrapper**: `apply_rules(batch, rules)` in a new `rules.py` wraps any batch source (wordlist or bruteforce) before submission; budget accounting counts emitted candidates, so budget-exhausted semantics stay exact. Presets are named code-defined lists (deterministic); custom rule files are out of scope for v2 (research).
- **Pause/resume**: the engine already knows submitted vs completed offsets; pause releases the pool and records the next submission offset plus, for dictionary mode, the file's byte position (validated unchanged on resume). Resume re-creates the pool with the same seed state.
- **No-plaintext mode**: a run-level flag carried through `run_audit` → history; the match record stores `plaintext_withheld=1` and NULL plaintext. The dashboard result panel shows "Match — plaintext withheld" without exposing it.
- **Encryption**: application-level Fernet (cryptography) over the `matched_plaintext` column only, keyed by an operator passphrase (Argon2id/scrypt-derived key stored alongside). Without the passphrase, rows decrypt only on demand. Full-DB SQLCipher is rejected: binary dependency, cross-platform build pain, and the sensitive surface is one column.
- **Benchmark**: runs the existing `_hash_batch` worker against a synthetic candidate set per algorithm for a fixed wall-clock slice (2 s), reports candidates/second; does not touch history.
- **Constitution**: v1 constraints (offline, bounded, loopback, honest identification) all hold; phase gates check each phase against them.

## Post-Design Constitution Check

- Local-only, offline: pass (no new network surfaces).
- Bounded work: pass (budget governs rule-expanded streams; hashlist multiplies hashing cost but not candidate count).
- Loopback + CSRF: pass (new state-changing routes follow the existing `_csrf_protected` gate).
- Plaintext handling: pass, with two new operator controls (withhold, encrypt) that *reduce* stored sensitive data.
- Honest identification: pass (salted formats declare their salt position explicitly; no shape guessing).

## Project Structure (new/changed files)

```text
src/password_audit/
├── algorithms.py        # SALTED_ALGORITHMS registry + salted validation
├── hashing.py           # salted adapters (position-aware)
├── rules.py             # NEW: mutation presets and batch expansion
├── engine.py            # multi-target worker, pause/resume, no-plaintext flag
├── candidates.py        # hashlist parsing (algorithm:hash lines)
├── benchmark.py         # NEW: per-algorithm throughput measurement
├── history.py           # additive schema migration, salt/batch columns, encryption
├── cli.py               # --salt, --hashlist, --rules, --no-store-plaintext, benchmark
├── web.py               # salt field, hashlist upload, pause/resume, export, ETA
└── static/              # rebuilt dashboard
frontend/src/components/
├── AuditDashboard.jsx   # salt field, hashlist upload, pause, export, ETA
tests/                  # NEW: pytest suite (algorithms, rules, engine, web)
.github/workflows/ci.yml  # NEW: pytest on windows-latest + ubuntu-latest
```

## Effort Estimates (working sessions)

| Phase | Scope | Estimate |
|---|---|---|
| 5. Salted hashes | registry, adapters, CLI/web/history, validation | 2–3 sessions |
| 6. Hashlist | parser, multi-target worker, UI table, batch records | 2–3 sessions |
| 7. Rules | presets, wrapper, CLI/web, validation | 1–2 sessions |
| 8. Tooling & UX | benchmark, pause/resume, export, ETA, no-plaintext | 2 sessions |
| 9. Quality | pytest suite + CI | 2 sessions |
| 9b. Encryption | Fernet plaintext column + unlock prompt | 1 session |
| 10. Research | RIPEMD-160 / adaptive / SHA-512-variants | open-ended |

Total core (5–9): roughly 7–10 working sessions.

## Risks

- Multi-target worker changes attempt accounting semantics — mitigated by phase-9 tests written *before* the change lands (tests define current behavior as golden).
- Rule expansion can explode memory if applied to huge batches — mitigated by expanding per submitted batch only.
- Encryption adds an unlock step that can frustrate — kept strictly opt-in; unencrypted mode remains the default.
- Adaptive formats (research) can stall runs for minutes per candidate — quarantined behind an explicit `--slow-formats` acknowledge flag if ever merged.

## Implementation Notes (recorded during implementation)

- Phases 8–10 completed 2026-11-06. Pause/resume works for single-target dictionary and brute-force runs (refused for hashlist and rule-expanded streams); resume validates dictionary wordlist size.
- Encryption is application-level: scrypt-derived key from an operator passphrase, Fernet over the `matched_plaintext` column only, per-database salt + verification token in a `history_meta` table. Requires the optional `encrypt` extra (`pip install password-audit[encrypt]`).
- Adaptive formats verify via Passlib handlers against the full stored hash string (`verify_candidate`); bcrypt needs the pinned `bcrypt>=3.2,<4.1` backend (`adaptive` extra) because passlib 1.7.4 breaks with bcrypt >= 4.1. Adaptive targets are recognized by prefix in `assess_hash`.
- RIPEMD-160 research (T074) succeeded: a pure-Python implementation validated against the official vectors and hashcat mode 600; 40-hex is now ambiguous between SHA-1 and RIPEMD-160. The table-authoring process initially produced wrong word-order groups; the tables were extracted programmatically from a known-good reference implementation (karpathy/cryptos) and re-validated.
- SHA-512/224 and SHA-512/256 research (T076) succeeded via hashlib on all target platforms; 56-hex is ambiguous (SHA-224/SHA-512-224) and 64-hex is ambiguous (SHA-256/SHA-512-256).
- Benchmark observed on the dev machine (in-process): SHA-256 ≈ 810k/s, MD5 ≈ 780k/s, SHA-512 ≈ 690k/s, MD4 ≈ 42k/s, NTLM (Passlib) ≈ 23k/s, LM ≈ 10k/s.
