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
from pathlib import Path

from .algorithms import (
    ALGORITHM_NAMES,
    HashInputError,
    assess_hash,
    is_salted,
    select_algorithm,
)
from .bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    CHARSET_PRESETS,
    iter_bruteforce_batches,
    resolve_charset,
    validate_bruteforce_options,
)
from .candidates import count_dictionary_lines, iter_wordlist_batches
from .engine import (
    DEFAULT_WORKERS,
    EngineInputError,
    STATUS_BUDGET_EXHAUSTED,
    clamp_workers,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
    STATUS_MATCH,
    STATUS_NO_MATCH,
    STATUS_STORAGE_ERROR,
    run_audit,
)
from .history import (
    DEFAULT_DB_PATH,
    HistoryError,
    connect,
    export_csv,
    export_json,
    list_runs,
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
    try:
        assessment, algorithm = select_algorithm(args.hash, args.algorithm)
    except HashInputError as exc:
        print(f"Invalid hash input: {exc}", file=sys.stderr)
        return EXIT_INVALID
    target_hash = assessment.normalized

    salt = getattr(args, "salt", None)
    if is_salted(algorithm) and not salt:
        print(
            f"Salted format {algorithm} requires --salt VALUE "
            "(the known salt stored alongside the hash).",
            file=sys.stderr,
        )
        return EXIT_INVALID
    if salt and not is_salted(algorithm):
        print(f"Algorithm {algorithm} does not take a salt; remove --salt.", file=sys.stderr)
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

    mode_label = "dictionary" if args.mode == "dictionary" else "brute-force"
    print(f"Algorithm : {algorithm.upper()}")
    print(f"Mode      : {mode_label}")
    print(f"Workers   : {workers}")
    if args.mode == "brute-force":
        print(f"Charset   : {''.join(sorted(alphabet))!r} ({len(alphabet)} characters)")
        print(f"Lengths   : {args.min_length}..{args.max_length}")
        print(f"Budget    : {budget:,} candidates (hard max {HARD_MAX_BUDGET:,})")

    cancel_event = threading.Event()
    started_at = utc_now()
    progress_at = [0.0]

    def progress(attempts: int, elapsed_ms: int, fraction: float | None) -> None:
        now = time.monotonic()
        if now - progress_at[0] >= 0.25:
            progress_at[0] = now
            _print_progress(attempts, elapsed_ms, fraction)

    print("Starting audit; press Ctrl+C to interrupt...")
    try:
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

    if result.status == STATUS_MATCH:
        print(f"Plaintext : {result.matched_plaintext}")
        print(f"Hash      : {target_hash}")
        print(
            "The recovered plaintext/hash pair above was saved to local SQLite\n"
            "history as sensitive audit data."
        )

    # Persist the terminal outcome locally.
    try:
        conn = connect(args.database)
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
                result.matched_plaintext if result.status == STATUS_MATCH else None
            ),
            salt=salt,
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


def _format_record(record) -> str:
    plaintext = record.matched_plaintext if record.matched_plaintext is not None else "-"
    return (
        f"#{record.run_id}  {record.started_at}  {record.status:<18}"
        f"  {record.algorithm:<6}  {record.mode:<11}  {record.attempts:>10,}"
        f"  {record.elapsed_ms:>8,}ms  {record.worker_count}w  "
        f"{record.target_hash[:16]}...  plaintext={plaintext}"
    )


def cmd_history(args: argparse.Namespace) -> int:
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
        print(_format_record(record))
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
    p_audit.add_argument("hash", help="The target hash to audit")
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
        "--yes",
        action="store_true",
        help="Acknowledge the local plaintext/hash retention warning non-interactively",
    )
    p_audit.set_defaults(func=cmd_audit)

    p_history = subparsers.add_parser(
        "history", parents=[db_parent], help="List local audit records"
    )
    p_history.add_argument("--limit", type=int, default=None, help="Show only the newest N records")
    p_history.set_defaults(func=cmd_history)

    p_export = subparsers.add_parser(
        "export", parents=[db_parent], help="Export local history to CSV or JSON"
    )
    p_export.add_argument("path", help="Output file path (local)")
    p_export.add_argument("--format", choices=("csv", "json"), default="csv", help="Report format")
    p_export.set_defaults(func=cmd_export)

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
        if args.algorithm is None:
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
