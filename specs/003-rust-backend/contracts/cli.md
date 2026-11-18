# Contract: CLI surface (`hashcrack-rs`, parity target)

The Rust CLI mirrors the Python `hashcrack` CLI (prog name `hashcrack-rs`): same subcommands, same flags, same exit codes, same output structure for identical inputs. No `--json` flag exists on either CLI (JSON only via `export --format json`).

## Exit codes (identical mapping)

`0` success/no_match/budget_exhausted · `1` invalid input · `2` cancelled/interrupted · `3` history/storage failure.

## Global

`--version` prints the tool version. Ctrl+C prints `"Interrupted; the run was recorded as incomplete where possible."` and exits 2 (when a run is in flight).

## Subcommands

### `identify HASH`

Prints the shape assessment: compatible formats (uppercase labels) and, when ambiguous, a notice listing the explicit choices in `--algorithm X or --algorithm Y` form. Ambiguity groups pinned in `contracts/api.md` §identify.

### `audit [HASH]`

Flags: `--hashlist PATH` · `--rules` (default `none`; choices capitalize, upper, lower, leetspeak, append_digits_0_99, append_years, all; dictionary mode only) · `--algorithm` (choices = 23 ids) · `--mode` (required; `dictionary`|`brute-force`) · `--wordlist PATH` · `--salt VALUE` · `--charset` · `--min-length INT` · `--max-length INT` · `--max-candidates INT` (default 1,000,000) · `--workers INT` (default 4, 1–8) · `--encrypt` · `--passphrase VALUE` · `--no-store-plaintext` · `--yes` (auto-acknowledge retention warning) · `--database PATH` (default `~/.hash_cracker/history.db`).

Validation order (identical messages where shared with the API): exactly one of HASH/`--hashlist`; rules dictionary-only; hashlist forbids `--salt`/`--algorithm`; salted require `--salt` and unsalted reject it; `--encrypt` + `--no-store-plaintext` mutually exclusive (exit 1); retention warning prompt `[yes/no]` before starting unless `--yes`.

`--encrypt` prompts (passphrase + confirmation) after the run, before persisting; empty/mismatched → `"Passphrases do not match or are empty; the audit result was not saved."` exit 1. Passphrase sources in order: `--passphrase VALUE`, env `PASSWORD_AUDIT_PASSPHRASE`, `getpass`-equivalent prompt (`History encryption passphrase: `; `"Confirm passphrase: "` only when setting).

Human output sections (same labels/order as Python): `Mode      :`, `Algorithm :` / `Hashlist  : N targets`, `Workers   :`, `Charset   :`, `Lengths   :`, `Budget    :`, `Rules     :`, live progress on stderr (throttled 0.25 s, rate + ETA), then `Status    :` (labels `MATCH, NO MATCH, BUDGET EXHAUSTED, CANCELLED, INTERRUPTED, STORAGE ERROR`), `Attempts  :`, `Elapsed   :`, `Workers   :`, `Targets   : x/y matched` + per-target lines, `Plaintext :`, `Hash      :`, `Batch     : <first 8 hex of batch_id> (N target records)`.

### `history`

Flags: `--limit INT` · `--passphrase VALUE` · `--unlock` · `--database PATH`. Table columns: `ID  Started (UTC)  Status  Alg  Mode  Attempts  Elapsed  W  Hash / plaintext`; encrypted values show `<encrypted>` until unlocked; wrong passphrase → `"Unlock failed: Wrong passphrase."` exit 3.

### `export PATH`

Flags: `--format csv|json` (default csv) · `--database PATH`. Column/shape contract pinned in `contracts/storage.md`.

### `benchmark`

Flags: `--seconds FLOAT` (default 2.0) · `--algorithms CSV` (default = all unsalted formats). Prints one line per algorithm (`name, rate candidates/s (N hashed in Xms)`), skips unavailable with `"unavailable (reason)"`, ends `Fastest: <alg> at <rate> candidates/s.` Measurement semantics identical (`benchmark-sample-candidate-0001` + growing numeric suffix, wall-clock slice).

### `serve`

Flags: `--port INT` (default 8765). Binds 127.0.0.1 only, serves the same REST contract and static directory as the Flask app. (The Python binary keeps its own serve; the Rust binary's serve is what `serve.sh --backend rust` launches.)
