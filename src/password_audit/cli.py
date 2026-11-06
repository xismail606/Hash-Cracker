"""Command-line interface for the offline password audit tool.

Commands:
    identify HASH             Assess a hash shape and list compatible formats
    audit HASH ...            Run a dictionary or bounded brute-force audit
    history                   List local audit records
    export PATH [--format]    Export local history to CSV or JSON
    serve [--port]            Start the local web dashboard (loopback only)

Exit codes: 0 success/no-match/budget reached, 1 invalid input, 2 cancelled
or interrupted, 3 local history or report failure.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
import uuid
from pathlib import Path

from .algorithms import (
    ALGORITHM_NAMES,
    HashInputError,
    assess_hash,
    is_salted,
    select_algorithm,
)
from .benchmark import measure_all
from .bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    iter_bruteforce_batches,
    resolve_charset,
    validate_bruteforce_options,
)
from .candidates import count_dictionary_lines, iter_wordlist_batches, parse_hashlist
from .engine import (
    DEFAULT_WORKERS,
    EngineInputError,
    run_hashlist_audit,
    STATUS_BUDGET_EXHAUSTED,
    clamp_workers,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
    STATUS_MATCH,
    STATUS_NO_MATCH,
    STATUS_STORAGE_ERROR,
    run_audit,
)
from .rules import iter_rule_expanded, resolve_rules_preset
from .history import (
    DEFAULT_DB_PATH,
    HistoryError,
    connect,
    export_csv,
    export_json,
    list_runs,
    decrypt_stored,
    init_encryption,
    is_encrypted_value,
    record_batch,
    record_run,
    utc_now,
)

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_CANCELLED = 2
EXIT_STORAGE = 3

RETENTION_WARNING = (
    "SENSITIVE-DATA WARNING: if this audit finds a match, the recovered\n"
    "plaintext and its target hash will be saved to the local SQLite audit\n"
    "history on this machine. Nothing is sent over the network, but anyone\n"
    "with access to this computer can read the stored plaintext.\n"
)

_STATUS_LABELS = {
    STATUS_MATCH: "MATCH",
    STATUS_NO_MATCH: "NO MATCH",
    STATUS_BUDGET_EXHAUSTED: "BUDGET EXHAUSTED",
    STATUS_CANCELLED: "CANCELLED",
    STATUS_INTERRUPTED: "INTERRUPTED",
    STATUS_STORAGE_ERROR: "STORAGE ERROR",
}


def _print_progress(attempts: int, elapsed_ms: int, fraction: float | None) -> None:
    percent = f" {fraction * 100:5.1f}%" if fraction is not None else ""
    print(f"\r  Attempts: {attempts:>12,}{percent}  Elapsed: {elapsed_ms / 1000:6.1f}s",
          end="", file=sys.stderr, flush=True)


def _progress_limit(total_space: int | None, budget: int | None) -> int | None:
    if total_space is None:
        return None
    return min(total_space, budget) if budget is not None else total_space


def cmd_identify(args: argparse.Namespace) -> int:
    try:
        assessment = assess_hash(args.hash)
    except HashInputError as exc:
        print(f"Invalid hash input: {exc}", file=sys.stderr)
        return EXIT_INVALID
    if assessment.ambiguous:
        names = ", ".join(a.upper() for a in assessment.compatible_algorithms)
        choice = " or ".join(f"--algorithm {a}" for a in assessment.compatible_algorithms)
        print(f"Hash shape: {len(assessment.normalized)} hexadecimal characters.")
        print(f"Compatible supported formats: {names}")
        print(
            "This shape is ambiguous: several supported formats share it, so\n"
            "the algorithm cannot be proven from structure alone. Select one\n"
            f"explicitly when running an audit ({choice})."
        )
        return EXIT_OK
    algorithm = assessment.compatible_algorithms[0]
    print(f"Hash shape: {len(assessment.normalized)} hexadecimal characters.")
    print(f"Compatible supported format: {algorithm.upper()}")
    return EXIT_OK


def _confirm_retention(assumed_yes: bool) -> bool:
    """Print the sensitive-data warning and require explicit acknowledgement."""
    print(RETENTION_WARNING)
    if assumed_yes:
        print("Acknowledged automatically via --yes.")
        return True
    try:
        answer = input("Acknowledge local plaintext/hash retention to continue? [yes/no]: ")
    except (EOFError, KeyboardInterrupt):
        print("\nNo acknowledgement received; the audit was not started.", file=sys.stderr)
        return False
    return answer.strip().lower() in ("y", "yes")


def cmd_audit(args: argparse.Namespace) -> int:
    # Target selection: exactly one of a positional hash or --hashlist.
    if args.hashlist and args.hash:
        print("Provide either HASH or --hashlist PATH, not both.", file=sys.stderr)
        return EXIT_INVALID
    if not args.hashlist and not args.hash:
        print("Provide HASH or --hashlist PATH.", file=sys.stderr)
        return EXIT_INVALID

    # Rules apply to dictionary mode only.
    rules_name = getattr(args, "rules", "none")
    variants_for = None
    if rules_name and rules_name != "none":
        if args.mode != "dictionary":
            print("--rules applies to dictionary mode only.", file=sys.stderr)
            return EXIT_INVALID
        try:
            variants_for = resolve_rules_preset(rules_name)
        except ValueError as exc:
            print(f"Invalid audit options: {exc}", file=sys.stderr)
            return EXIT_INVALID

    salt = getattr(args, "salt", None)
    targets = None
    algorithm = None
    target_hash = None

    if args.hashlist:
        try:
            targets = parse_hashlist(args.hashlist)
        except HashInputError as exc:
            print(f"Invalid hashlist: {exc}", file=sys.stderr)
            return EXIT_INVALID
        if salt:
            print("--salt is not supported with hashlists (no per-target salt).",
                  file=sys.stderr)
            return EXIT_INVALID
        if getattr(args, "algorithm", None):
            print("--algorithm is ignored with --hashlist; each line carries its "
                  "own algorithm.", file=sys.stderr)
            return EXIT_INVALID
    else:
        try:
            assessment, algorithm = select_algorithm(args.hash, args.algorithm)
        except HashInputError as exc:
            print(f"Invalid hash input: {exc}", file=sys.stderr)
            return EXIT_INVALID
        target_hash = assessment.normalized

        if is_salted(algorithm) and not salt:
            print(
                f"Salted format {algorithm} requires --salt VALUE "
                "(the known salt stored alongside the hash).",
                file=sys.stderr,
            )
            return EXIT_INVALID
        if salt and not is_salted(algorithm):
            print(f"Algorithm {algorithm} does not take a salt; remove --salt.",
                  file=sys.stderr)
            return EXIT_INVALID

    try:
        workers = clamp_workers(args.workers)
    except EngineInputError as exc:
        print(f"Invalid audit options: {exc}", file=sys.stderr)
        return EXIT_INVALID

    try:
        if args.mode == "dictionary":
            wordlist = Path(args.wordlist)
            if not wordlist.is_file():
                print(
                    f"Invalid wordlist: {args.wordlist} is not a readable local file.",
                    file=sys.stderr,
                )
                return EXIT_INVALID
            total_space = count_dictionary_lines(wordlist)
            budget = None
            batch_source = iter_wordlist_batches(wordlist)
            if variants_for is not None:
                budget = args.max_candidates
                total_space = None
                batch_source = iter_rule_expanded(batch_source, variants_for, budget)
        elif args.mode == "brute-force":
            alphabet = resolve_charset(args.charset)
            alphabet, total_space = validate_bruteforce_options(
                args.min_length, args.max_length, args.max_candidates, alphabet
            )
            budget = args.max_candidates
            batch_source = iter_bruteforce_batches(
                alphabet, args.min_length, args.max_length, budget
            )
        else:
            print(
                f"Invalid mode: {args.mode!r}. Supported modes: dictionary, brute-force.",
                file=sys.stderr,
            )
            return EXIT_INVALID
    except HashInputError as exc:
        print(f"Invalid audit options: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if not _confirm_retention(args.yes):
        print("The audit was not started because the retention warning was not acknowledged.",
              file=sys.stderr)
        return EXIT_INVALID
    withhold = getattr(args, "no_store_plaintext", False)
    if withhold and getattr(args, "encrypt", False):
        print("--encrypt and --no-store-plaintext are mutually exclusive.", file=sys.stderr)
        return EXIT_INVALID

    mode_label = "dictionary" if args.mode == "dictionary" else "brute-force"
    print(f"Mode      : {mode_label}")
    if targets is not None:
        print(f"Hashlist  : {len(targets)} targets")
        print(f"Workers   : {workers}")
    else:
        print(f"Algorithm : {algorithm.upper()}")
        print(f"Workers   : {workers}")
    if args.mode == "brute-force":
        print(f"Charset   : {''.join(sorted(alphabet))!r} ({len(alphabet)} characters)")
        print(f"Lengths   : {args.min_length}..{args.max_length}")
        print(f"Budget    : {budget:,} candidates (hard max {HARD_MAX_BUDGET:,})")
    if variants_for is not None:
        print(f"Rules     : {rules_name}")

    cancel_event = threading.Event()
    started_at = utc_now()
    progress_limit = _progress_limit(total_space, budget)
    progress_sample = [time.monotonic(), 0]  # (monotonic timestamp, attempts)
    last_progress_at = [progress_sample[0]]

    def progress(attempts: int, elapsed_ms: int, fraction: float | None) -> None:
        now = time.monotonic()
        if now - last_progress_at[0] < 0.25:
            return
        previous_time, previous_attempts = progress_sample
        rate = (
            (attempts - previous_attempts) / (now - previous_time)
            if attempts > previous_attempts and now > previous_time
            else None
        )
        progress_fraction = (
            min(attempts / progress_limit, 1.0) if progress_limit else fraction
        )
        _print_progress(attempts, elapsed_ms, progress_fraction)
        if progress_limit is not None and attempts < progress_limit and rate:
            remaining = (progress_limit - attempts) / rate
            print(
                f"\r  ETA ~{remaining:.0f}s ({rate:,.0f} candidates/s)   ",
                end="", file=sys.stderr, flush=True,
            )
        progress_sample[:] = [now, attempts]
        last_progress_at[0] = now

    print("Starting audit; press Ctrl+C to interrupt...")
    try:
        if targets is not None:
            result = run_hashlist_audit(
                targets,
                batch_source,
                workers=workers,
                budget=budget,
                total_space=total_space,
                cancel_event=cancel_event,
                progress_callback=progress,
            )
        else:
            result = run_audit(
                target_hash,
                algorithm,
                batch_source,
                workers=workers,
                budget=budget,
                total_space=total_space,
                salt=salt,
                cancel_event=cancel_event,
                progress_callback=progress,
            )
    except EngineInputError as exc:
        print(f"Invalid audit options: {exc}", file=sys.stderr)
        return EXIT_INVALID

    print("\r" + " " * 70 + "\r", end="", file=sys.stderr)

    print(f"Status    : {_STATUS_LABELS.get(result.status, result.status)}")
    print(f"Attempts  : {result.attempts:,}")
    print(f"Elapsed   : {result.elapsed_ms / 1000:.2f}s")
    print(f"Workers   : {result.workers}")

    if targets is not None:
        matched_count = sum(1 for t in result.targets if t["status"] == STATUS_MATCH)
        print(f"Targets   : {matched_count}/{len(result.targets)} matched")
        for t in result.targets:
            mark = "MATCH   " if t["status"] == STATUS_MATCH else "no match"
            plaintext = t["matched_plaintext"] if t["matched_plaintext"] is not None else "-"
            print(
                f"  [{mark}] {t['algorithm']:<16} {t['hash'][:20]}...  "
                f"plaintext={plaintext}"
            )
    elif result.status == STATUS_MATCH:
        print(f"Plaintext : {result.matched_plaintext}")
        print(f"Hash      : {target_hash}")
        print(
            "The recovered plaintext/hash pair above was saved to local SQLite\n"
            "history as sensitive audit data."
        )

    plaintext_key = None
    if getattr(args, "encrypt", False):
        passphrase = _resolve_passphrase(args, confirm=not args.passphrase)
        if not passphrase:
            print("Passphrases do not match or are empty; the audit was not started.",
                  file=sys.stderr)
            return EXIT_INVALID
        try:
            conn = connect(args.database)
            plaintext_key = init_encryption(conn, passphrase)
            conn.close()
        except HistoryError as exc:
            print(f"History encryption failed: {exc}", file=sys.stderr)
            return EXIT_INVALID

    if withhold and targets is None and result.status == STATUS_MATCH:
        print(
            "Plaintext withheld from local history (--no-store-plaintext);\n"
            "the match above is displayed for this session only."
        )

    # Persist the terminal outcome locally.
    try:
        conn = connect(args.database)
        if targets is not None:
            batch_id = uuid.uuid4().hex
            record_batch(
                conn,
                batch_id=batch_id,
                mode=mode_label,
                status=result.status,
                attempts=result.attempts,
                elapsed_ms=result.elapsed_ms,
                worker_count=result.workers,
                started_at=started_at,
                target_count=len(result.targets),
            )
            for t in result.targets:
                record_run(
                    conn,
                    target_hash=t["hash"],
                    algorithm=t["algorithm"],
                    mode=mode_label,
                    status=t["status"],
                    attempts=(
                        t["match_at_attempt"]
                        if t["match_at_attempt"] is not None
                        else result.attempts
                    ),
                    elapsed_ms=result.elapsed_ms,
                    worker_count=result.workers,
                    started_at=started_at,
                    matched_plaintext=(
                        None if withhold else t["matched_plaintext"]
                    ),
                    batch_id=batch_id,
                    plaintext_withheld=withhold,
                    plaintext_key=plaintext_key,
                )
            print(f"Batch     : {batch_id[:8]} ({len(result.targets)} target records)")
        else:
            record_run(
                conn,
                target_hash=target_hash,
                algorithm=algorithm,
                mode=mode_label,
                status=result.status,
                attempts=result.attempts,
                elapsed_ms=result.elapsed_ms,
                worker_count=result.workers,
                started_at=started_at,
                matched_plaintext=(
                    None
                    if withhold
                    else (result.matched_plaintext if result.status == STATUS_MATCH else None)
                ),
                salt=salt,
                plaintext_withheld=withhold,
                plaintext_key=plaintext_key,
            )
        conn.close()
    except HistoryError as exc:
        print(f"History storage failed: {exc}", file=sys.stderr)
        print(
            "The audit finished but the result could not be recorded in local history.",
            file=sys.stderr,
        )
        return EXIT_STORAGE

    return _exit_for_status(result.status)
def _exit_for_status(status: str) -> int:
    if status in (STATUS_MATCH, STATUS_NO_MATCH, STATUS_BUDGET_EXHAUSTED):
        return EXIT_OK
    if status in (STATUS_CANCELLED, STATUS_INTERRUPTED):
        return EXIT_CANCELLED
    return EXIT_STORAGE if status == STATUS_STORAGE_ERROR else EXIT_INVALID


def _format_record(record, display_plaintext=None) -> str:
    plaintext = display_plaintext(record.matched_plaintext) if display_plaintext else (
        record.matched_plaintext if record.matched_plaintext is not None else "-"
    )
    return (
        f"#{record.run_id}  {record.started_at}  {record.status:<18}"
        f"  {record.algorithm:<6}  {record.mode:<11}  {record.attempts:>10,}"
        f"  {record.elapsed_ms:>8,}ms  {record.worker_count}w  "
        f"{record.target_hash[:16]}...  plaintext={plaintext}"
    )


def _resolve_passphrase(args, confirm: bool) -> str | None:
    """Passphrase from --passphrase, PASSWORD_AUDIT_PASSPHRASE, or a prompt.

    --passphrase VALUE is visible in the process list; it exists for scripted
    use on this single-user local machine. Prompting uses getpass, which on
    Windows reads the console directly.
    """
    value = getattr(args, "passphrase", None)
    if value:
        return value
    import os

    value = os.environ.get("PASSWORD_AUDIT_PASSPHRASE")
    if value:
        return value
    import getpass

    value = getpass.getpass("History encryption passphrase: ")
    if confirm:
        confirm_value = getpass.getpass("Confirm passphrase: ")
        if value != confirm_value or not value:
            return None
    return value or None


def cmd_history(args: argparse.Namespace) -> int:
    plaintext_key = None
    if getattr(args, "unlock", False):
        try:
            conn = connect(args.database)
            passphrase = _resolve_passphrase(args, confirm=False)
            plaintext_key = init_encryption(conn, passphrase)
            conn.close()
        except HistoryError as exc:
            print(f"Unlock failed: {exc}", file=sys.stderr)
            return EXIT_STORAGE

    def display_plaintext(value):
        if value is None:
            return "-"
        if is_encrypted_value(value):
            if plaintext_key is None:
                return "<encrypted>"
            return decrypt_stored(plaintext_key, value)
        return value

    try:
        conn = connect(args.database)
        records = list_runs(conn, limit=args.limit)
        conn.close()
    except HistoryError as exc:
        print(f"History storage failed: {exc}", file=sys.stderr)
        return EXIT_STORAGE
    if not records:
        print("No local audit records yet. Run an audit to create history.")
        return EXIT_OK
    print(f"Local audit history ({len(records)} record{'s' if len(records) != 1 else ''}):")
    print(
        f"{'ID':>4}  {'Started (UTC)':<23}  {'Status':<18}  {'Alg':<6}  "
        f"{'Mode':<11}  {'Attempts':>10}  {'Elapsed':>9}  W  Hash / plaintext"
    )
    for record in records:
        print(_format_record(record, display_plaintext))
    print(
        "\nSuccessful matches store the recovered plaintext/hash pair locally;\n"
        "treat this database as sensitive credential data."
    )
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    try:
        conn = connect(args.database)
        if args.format == "csv":
            target = export_csv(conn, args.path)
        else:
            target = export_json(conn, args.path)
        conn.close()
    except HistoryError as exc:
        print(f"Report export failed: {exc}", file=sys.stderr)
        return EXIT_STORAGE
    print(f"Exported local audit history to {target}")
    print("The report contains sensitive plaintext/hash pairs for successful matches.")
    return EXIT_OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    names = [n.strip().lower() for n in args.algorithms.split(",") if n.strip()]
    invalid = [n for n in names if n not in ALGORITHM_NAMES]
    if invalid:
        print(
            f"Unknown algorithms: {', '.join(invalid)}. Supported: {', '.join(ALGORITHM_NAMES)}.",
            file=sys.stderr,
        )
        return EXIT_INVALID
    print(f"Benchmarking {len(names)} algorithms, {args.seconds:.1f}s each (in-process, CPU-bound):")
    results = []
    for name in names:
        print(f"  {name:<16} ", end="", flush=True)
        try:
            r = measure_all([name], seconds=args.seconds)[0]
        except Exception as exc:
            print(f"unavailable ({exc})")
            continue
        results.append(r)
        print(f"{r['hashes_per_second']:>14,.0f} candidates/s  ({r['hashed']:,} hashed in {r['elapsed_ms']}ms)")
    if results:
        best = max(results, key=lambda r: r["hashes_per_second"])
        print(
            f"\nFastest: {best['algorithm']} at {best['hashes_per_second']:,.0f} candidates/s. "
            "Use this to pick a realistic brute-force budget on this machine."
        )
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .web import create_app

    app = create_app()
    port = args.port
    print(f"Starting the local dashboard on http://127.0.0.1:{port} (loopback only)")
    try:
        app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
    except OSError as exc:
        print(f"Cannot start the dashboard on port {port}: {exc}", file=sys.stderr)
        return EXIT_INVALID
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_audit",
        description=(
            "Offline hash identification and password auditing for authorized "
            "local targets. No remote logins, no network access."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Shared parent for commands that touch the local history database.
    db_parent = argparse.ArgumentParser(add_help=False)
    db_parent.add_argument(
        "--database",
        default=str(DEFAULT_DB_PATH),
        help="Path to the local SQLite history database (default: %(default)s)",
    )

    p_identify = subparsers.add_parser("identify", help="Assess a hash shape")
    p_identify.add_argument("hash", help="The hash value to inspect")
    p_identify.set_defaults(func=cmd_identify)

    p_audit = subparsers.add_parser(
        "audit",
        parents=[db_parent],
        help="Run a dictionary or brute-force audit",
    )
    p_audit.add_argument(
        "hash", nargs="?", default=None,
        help="The target hash to audit (or use --hashlist)",
    )
    p_audit.add_argument(
        "--hashlist",
        help="Path to a hashlist file: one target per line, optional algorithm:hash prefix",
    )
    p_audit.add_argument(
        "--rules",
        default="none",
        help="Mutation preset for dictionary mode: capitalize, upper, lower, "
        "leetspeak, append_digits_0_99, append_years, all (default: none)",
    )
    p_audit.add_argument(
        "--algorithm",
        choices=ALGORITHM_NAMES,
        help="Explicit algorithm selection (required for 32-hex MD5/NTLM ambiguity)",
    )
    p_audit.add_argument(
        "--mode",
        required=True,
        choices=("dictionary", "brute-force"),
        help="Candidate source mode",
    )
    p_audit.add_argument("--wordlist", help="Local wordlist path (dictionary mode)")
    p_audit.add_argument(
        "--salt",
        help="Salt value for salted formats such as md5_pass_salt (required for them)",
    )
    p_audit.add_argument(
        "--charset",
        help="Brute-force alphabet: preset names (lower, upper, digits, symbols) "
        "or literal characters, comma-separated (brute-force mode)",
    )
    p_audit.add_argument("--min-length", type=int, help="Minimum candidate length (brute-force)")
    p_audit.add_argument("--max-length", type=int, help="Maximum candidate length (brute-force)")
    p_audit.add_argument(
        "--max-candidates",
        type=int,
        default=DEFAULT_BUDGET,
        help=f"Brute-force candidate budget (default: {DEFAULT_BUDGET:,}, max: {HARD_MAX_BUDGET:,})",
    )
    p_audit.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Multiprocessing worker count 1-8 (default: {DEFAULT_WORKERS})",
    )
    p_audit.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the stored plaintext in history (prompts for a passphrase)",
    )
    p_audit.add_argument(
        "--passphrase",
        help="Encryption passphrase (visible in the process list; scripted use only)",
    )
    p_audit.add_argument(
        "--no-store-plaintext",
        action="store_true",
        help="Record match metadata without storing the recovered plaintext",
    )
    p_audit.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge the local plaintext/hash retention warning non-interactively",
    )
    p_audit.set_defaults(func=cmd_audit)

    p_history = subparsers.add_parser(
        "history", parents=[db_parent], help="List local audit records"
    )
    p_history.add_argument("--limit", type=int, default=None, help="Show only the newest N records")
    p_history.add_argument(
        "--passphrase",
        help="Encryption passphrase (visible in the process list; scripted use only)",
    )
    p_history.add_argument(
        "--unlock",
        action="store_true",
        help="Prompt for the encryption passphrase and decrypt stored plaintexts for display",
    )
    p_history.set_defaults(func=cmd_history)

    p_export = subparsers.add_parser(
        "export", parents=[db_parent], help="Export local history to CSV or JSON"
    )
    p_export.add_argument("path", help="Output file path (local)")
    p_export.add_argument("--format", choices=("csv", "json"), default="csv", help="Report format")
    p_export.set_defaults(func=cmd_export)

    p_benchmark = subparsers.add_parser(
        "benchmark",
        help="Measure per-algorithm hashing throughput on this machine",
    )
    p_benchmark.add_argument(
        "--seconds", type=float, default=2.0,
        help="Wall-clock slice per algorithm (default: 2.0)",
    )
    p_benchmark.add_argument(
        "--algorithms",
        default=",".join(a for a in ALGORITHM_NAMES if not is_salted(a)),
        help="Comma-separated algorithm names (default: all unsalted formats)",
    )
    p_benchmark.set_defaults(func=cmd_benchmark)

    p_serve = subparsers.add_parser("serve", help="Start the local web dashboard")
    p_serve.add_argument("--port", type=int, default=8765, help="Local port (default: 8765)")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        # Validate mode-specific options before the acknowledgement prompt.
        if args.mode == "dictionary" and not args.wordlist:
            print("Dictionary mode requires --wordlist PATH.", file=sys.stderr)
            return EXIT_INVALID
        if args.mode == "brute-force":
            missing = [
                flag
                for flag, value in (
                    ("--charset", args.charset),
                    ("--min-length", args.min_length),
                    ("--max-length", args.max_length),
                )
                if value is None
            ]
            if missing:
                print(
                    "Brute-force mode requires " + ", ".join(missing) + ".",
                    file=sys.stderr,
                )
                return EXIT_INVALID
        if args.algorithm is None and not args.hashlist:
            try:
                assessment = assess_hash(args.hash)
            except HashInputError as exc:
                print(f"Invalid hash input: {exc}", file=sys.stderr)
                return EXIT_INVALID
            if assessment.ambiguous:
                names = ", ".join(assessment.compatible_algorithms)
                print(
                    f"This hash shape matches {names}; select the algorithm "
                    "explicitly with --algorithm NAME.",
                    file=sys.stderr,
                )
                return EXIT_INVALID

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\nInterrupted; the run was recorded as incomplete where possible.",
              file=sys.stderr)
        return EXIT_CANCELLED


if __name__ == "__main__":
    raise SystemExit(main())
