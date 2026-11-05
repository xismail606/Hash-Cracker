# Implementation Plan: Hash Cracker

**Branch**: `001-offline-password-audit` | **Date**: 2026-11-05 | **Spec**: [spec.md](spec.md)

## Summary

Build a Python-based offline hash-cracking and credential-auditing tool with hash identification, dictionary and bounded brute-force modes, both a CLI and a local web dashboard, multiprocessing, and SQLite history. The dashboard is built with Astro, React, JavaScript, and Tailwind CSS and is served by a loopback-only Flask server. Successful matches are saved locally as plaintext/hash pairs, as requested by the project brief.

The system is restricted to one operator-selected target per run and local input data. It does not connect to authentication services or remote targets. Brute-force enumeration is limited to user-selected character sets and lengths, with a default budget of 1,000,000 and a hard ceiling of 10,000,000 candidates per run.

## Technical Context

**Language/Version**: Python 3.11+ for the engine, CLI, and backend; JavaScript for the frontend.

**Primary Dependencies**: Python standard library (`hashlib`, `argparse`, `concurrent.futures`, `multiprocessing`, `sqlite3`) plus Flask and Passlib's `nthash` implementation for NTLM. Frontend uses Astro, React, and Tailwind CSS; Node.js/npm are used to build static assets.

**Storage**: SQLite database on the local machine. It stores run metadata and successful plaintext/hash pairs; wordlists and brute-force candidate streams are not copied into the database.

**Testing**: Manual validation scenarios with synthetic hashes and small candidate spaces are described in [quickstart.md](quickstart.md). No tests are being run as part of this documentation update.

**Target Platform**: Windows, macOS, and Linux with Python 3.11+ and Node.js/npm.

**Project Type**: Python CLI and local Flask API with an Astro/React web interface.

**Performance Goals**: Complete dictionary comparison for 100,000 short entries in under 60 seconds on a typical student laptop; multiprocessing must show progress and attempts. Brute-force mode is governed by a candidate budget and may be stopped by the user.

**Constraints**: Authorized, local, offline auditing only; supported algorithms are MD5, SHA-256, and NTLM; MD5 and NTLM are ambiguous by shape; worker limit is 1–8 (default 4); brute-force budget defaults to 1,000,000 and is capped at 10,000,000; dashboard upload limit is 100 MiB; dashboard binds only to `127.0.0.1`; successful plaintext/hash pairs are persisted locally with a warning.

**Scale/Scope**: One target per run; dictionary or bounded brute-force mode; one dashboard job active at a time; a single local user and SQLite history.

## Four Assignment Phases

The implementation tasks follow the four phases from the supplied project brief:

1. **Hash Identification & Structure Analysis** — validate hash structure, recognize supported formats, and handle MD5/NTLM ambiguity.
2. **Multi-Threaded Dictionary and Brute-Force Engine** — stream wordlists, generate bounded brute-force candidates, hash candidates, and compare using multiprocessing.
3. **CLI / Web Dashboard Interface** — expose both requested interfaces, worker and mode controls, live progress, and plaintext results.
4. **Result Storage & Audit Logging** — save local match pairs, elapsed time, attempts, algorithm, mode, and run status in SQLite and support reports.

## Constitution Check

The repository constitution at `.specify/memory/constitution.md` is still an unfilled template and has no project-specific gates. The feature constraints below come from the approved project scope:

- Work only with hashes and candidate inputs the operator is authorized to audit.
- Process targets and candidate sources locally; do not test remote authentication services.
- Restrict brute-force generation by explicit charset, lengths, worker count, and candidate budget.
- Bind the dashboard to loopback and protect state-changing requests.
- Store successful plaintext/hash pairs locally because the assignment requires them; warn the operator and keep the database local.
- Report ambiguity when a hash shape does not uniquely identify its algorithm.

**Gate result**: Pass against the feature constraints; the template constitution cannot provide additional gates.

## Project Structure

### Documentation

```text
specs/001-offline-password-audit/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── cli.md
│   └── web.md
└── tasks.md
```

### Planned Source Layout

```text
pyproject.toml
README.md
src/password_audit/
├── __init__.py
├── __main__.py
├── algorithms.py       # Shape recognition and algorithm selection
├── candidates.py       # Wordlist streaming and shared candidate interface
├── bruteforce.py       # Charset/length-based bounded candidate generation
├── engine.py           # Multiprocess hashing, comparison, progress, cancellation
├── history.py          # SQLite schema, result records, and exports
├── cli.py              # Command-line interface
├── web.py              # Flask routes and local server
└── static/             # Built Astro output served by Flask
frontend/
├── package.json
├── astro.config.mjs
└── src/
    ├── pages/index.astro
    ├── components/AuditDashboard.jsx
    └── styles/global.css
```

**Structure Decision**: Keep all hash processing, candidate generation, concurrency, CLI behavior, and persistence in Python. The CLI and Flask API call the same engine. Astro builds the React dashboard into static files served by Flask. Go is not included; a second backend would add cross-language coordination without a requirement from the brief.

## Design Decisions

- Use `hashlib` for MD5 and SHA-256.
- Use Passlib's `nthash` for NTLM candidate hashing. NTLM is MD4 of UTF-16LE encoded input; its 32-character hexadecimal shape overlaps with MD5, so users must choose explicitly when ambiguous. See the [Passlib NT-HASH documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.nthash.html).
- Use a shared digest adapter so the engine compares candidates consistently regardless of selected algorithm.
- Use `ProcessPoolExecutor`/multiprocessing for CPU-bound candidate hashing, with 1–8 workers and a default of 4.
- Dictionary mode reads the supplied file incrementally in bounded chunks. It preserves duplicate entries and strips only line endings.
- Brute-force mode generates candidates from one selected alphabet and configured minimum/maximum length. It must stop at the configured candidate budget (default 1,000,000; hard maximum 10,000,000), on match, or on cancellation.
- Show progress, attempts, effective worker count, and elapsed time in both CLI and dashboard.
- The dashboard is served locally on `127.0.0.1`. Mutating routes use same-origin/CSRF protection. Web uploads are limited to 100 MiB and temporary copies are deleted after success, failure, cancellation, or shutdown.
- Store audit summaries in SQLite. On a successful match, persist plaintext and target hash together with a warning to the operator. Reports are local and should be access-controlled with normal local filesystem permissions.

## Post-Design Constitution Check

- Local-only target processing and inputs: Pass.
- Dictionary and generated candidate modes have explicit bounds: Pass.
- Process count and work budget are bounded: Pass.
- Plaintext/hash results are stored locally as required by the assignment: Pass, with an operator warning.
- Hash identification does not mislabel the MD5/NTLM overlap: Pass.
- One backend language with a separate static frontend: Pass.

## Complexity Tracking

Passlib is an additional dependency to support NTLM hashing. Multiprocessing is included to cover the assignment's multi-core requirement. Astro/React add a frontend build step, while Flask serves the built files and JSON API locally.
