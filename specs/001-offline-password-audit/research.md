# Research Decisions: Hash Cracker

## Decision: Keep the audit engine and CLI in Python

**Decision**: Use Python 3.11+ for hash identification, dictionary processing, bounded brute-force generation, multiprocessing, the CLI, Flask routes, and SQLite history.

**Rationale**: Python is the language requested by the assignment and keeps both interfaces on one shared audit engine. Go could be added later, but a second backend would create cross-language process or API coordination that is not needed for this student project.

**Alternatives considered**: A Go backend with a Python worker would add service boundaries and duplicate deployment concerns. Replacing Python entirely would no longer match the assignment's specified stack.

## Decision: Support MD5, SHA-256, and NTLM in v1

**Decision**: Support MD5 and SHA-256 using Python's `hashlib`. Use Passlib's `passlib.hash.nthash` implementation for NTLM.

**Rationale**: These are the example formats explicitly named in the brief. NTLM is calculated from UTF-16LE encoded candidate text using MD4. Passlib documents an `nthash` implementation and its 32-hex format. MD5 and NTLM have indistinguishable length/character shapes, so automatic format identification must report both and require the operator to select one.

**Alternatives considered**: Exclude NTLM because `hashlib` does not provide MD4; implement MD4 locally; support a larger set of salted/adaptive formats. Using a documented existing NTLM implementation best matches scope without hand-writing cryptographic code or expanding the project.

**Reference**: [Passlib NT-HASH documentation](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.nthash.html).

## Decision: Implement both dictionary and bounded brute-force modes

**Decision**: Dictionary mode streams a local operator-supplied wordlist. Brute-force mode generates candidates from a selected character set and minimum/maximum length. Both modes share one candidate processing contract and stop on a match, cancellation, or configured candidate budget.

**Rationale**: Both attack modes are explicit requirements in the supplied project brief. Requiring a selected alphabet, length range, and work budget makes brute-force behavior measurable and prevents an accidental unbounded run.

**Limits**: Default candidate budget is 1,000,000; the absolute maximum is 10,000,000 candidates per run. Candidate lengths and character sets are selected by the operator. Worker count is 1–8, default 4.

**Alternatives considered**: Dictionary-only mode would omit a required project capability. Unbounded generation would risk runs that consume excessive time and CPU.

## Decision: Use multiprocessing for CPU-bound comparisons

**Decision**: Use Python's process pool for parallel digest comparisons, with a single-worker mode and a configurable hard cap of 8 workers.

**Rationale**: Candidate hashing is CPU-bound, and multiprocessing allows work to use multiple CPU cores without relying on interpreter threading behavior. The same worker/candidate budget is surfaced in both interfaces.

**Alternatives considered**: Threads are simpler for I/O-bound work but may not improve CPU-bound candidate hashing. A GPU backend is outside the requested stack and project scope.

## Decision: Provide both CLI and a local web dashboard

**Decision**: Provide CLI commands for identify, audit, history, export, and serve. Provide a Flask JSON API and Astro/React dashboard for identification, dictionary/brute-force settings, progress, results, and history.

**Rationale**: The assignment permits either a CLI or web interface, and the user's later direction asks for both. Flask serves the built Astro frontend and API on loopback. JavaScript calls the local API; Tailwind CSS handles layout and feedback states.

**Alternatives considered**: CLI-only or web-only would not satisfy the user's request for both interfaces. A public server is outside the offline auditing use case.

## Decision: Store successful plaintext/hash pairs and run metadata locally

**Decision**: Use SQLite for local history. On successful match, store the recovered plaintext and corresponding target hash, algorithm, mode, worker count, attempts, elapsed time, and timestamp. Warn the operator before a run that can write sensitive results.

**Rationale**: The project brief explicitly requests successful `Plaintext : Hash` pairs, attempts, and elapsed time for administrative reporting. The database remains local and is not transmitted.

**Alternatives considered**: Redacting plaintext by default conflicts with the requested automatic successful-match record. Storing only text output would provide weaker structured history; SQLite matches the specified stack.
