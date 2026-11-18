"""Cross-backend parity tests: Python <--> Rust share one history store.

These tests exercise the Phase 11 promise that both backends read and write
the same database with byte-compatible exports and encryption. They are
skipped (with a clear message) when the Rust CLI has not been built.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hash_cracker.history import connect, list_runs, record_run, utc_now

REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_DIR = REPO_ROOT / "rust"

RUST_BINARY_NAMES = ("hashcrack-rs.exe", "hashcrack-rs")


def rust_binary() -> Path | None:
    for profile in ("release", "debug"):
        for name in RUST_BINARY_NAMES:
            candidate = RUST_DIR / "target" / profile / name
            if candidate.is_file():
                return candidate
    return None


RUST_CLI = rust_binary()

pytestmark = pytest.mark.skipif(
    RUST_CLI is None,
    reason=(
        "Rust backend not built; run `cargo build --release` in rust/ "
        "(or cargo build) to enable the parity tests."
    ),
)


def run_rust(*args: str) -> subprocess.CompletedProcess:
    assert RUST_CLI is not None
    return subprocess.run(
        [str(RUST_CLI), *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )


@pytest.fixture()
def shared_db(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


def make_wordlist(tmp_path: Path) -> Path:
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("alpha\nbeta\nhashcat\n", encoding="utf-8")
    return wordlist


def test_python_reads_rust_written_run(shared_db: Path, tmp_path: Path) -> None:
    """A run recorded by the Rust CLI is readable through list_runs."""
    wordlist = make_wordlist(tmp_path)
    run_rust(
        "audit",
        "8743b52063cd84097a65d1633f5c74f5",
        "--mode",
        "dictionary",
        "--algorithm",
        "md5",
        "--wordlist",
        str(wordlist),
        "--yes",
        "--database",
        str(shared_db),
    )
    conn = connect(shared_db)
    records = list_runs(conn)
    conn.close()
    assert len(records) == 1
    record = records[0]
    assert record.status == "match"
    assert record.matched_plaintext == "hashcat"
    assert record.backend == "rust"


def test_rust_reads_python_written_run(shared_db: Path, tmp_path: Path) -> None:
    """A run recorded by the Python backend is visible to the Rust CLI."""
    conn = connect(shared_db)
    record_run(
        conn,
        target_hash="8743b52063cd84097a65d1633f5c74f5",
        algorithm="md5",
        mode="dictionary",
        status="match",
        attempts=3,
        elapsed_ms=5,
        worker_count=4,
        started_at=utc_now(),
        matched_plaintext="hashcat",
    )
    conn.close()
    result = run_rust("history", "--database", str(shared_db))
    assert "match" in result.stdout
    assert "hashcat" in result.stdout
    # Pre-Phase-11 rows carry NULL backend; the Rust export displays "python".
    export_path = tmp_path / "export.json"
    run_rust(
        "export",
        str(export_path),
        "--format",
        "json",
        "--database",
        str(shared_db),
    )
    import json

    payload = json.loads(export_path.read_text(encoding="utf-8"))
    assert payload["runs"][0]["backend"] == "python"


def test_exports_are_byte_identical(shared_db: Path, tmp_path: Path) -> None:
    """Both backends export the same database to identical CSV bytes."""
    conn = connect(shared_db)
    record_run(
        conn,
        target_hash="a9993e364706816aba3e25717850c26c9cd0d89d",
        algorithm="sha1",
        mode="dictionary",
        status="no_match",
        attempts=9,
        elapsed_ms=42,
        worker_count=2,
        started_at=utc_now(),
        salt=None,
    )
    conn.close()
    from hash_cracker.history import export_csv

    py_csv = tmp_path / "py.csv"
    export_csv(connect(shared_db), py_csv)
    rs_csv = tmp_path / "rs.csv"
    run_rust("export", str(rs_csv), "--database", str(shared_db))
    assert py_csv.read_bytes() == rs_csv.read_bytes()


def test_cross_backend_unlock(shared_db: Path, tmp_path: Path) -> None:
    """A record encrypted by one backend unlocks with the other."""
    wordlist = make_wordlist(tmp_path)
    run_rust(
        "audit",
        "8743b52063cd84097a65d1633f5c74f5",
        "--mode",
        "dictionary",
        "--algorithm",
        "md5",
        "--wordlist",
        str(wordlist),
        "--yes",
        "--encrypt",
        "--passphrase",
        "parity-passphrase",
        "--database",
        str(shared_db),
    )
    # Rust-side: stored value is ciphertext.
    conn = connect(shared_db)
    records = list_runs(conn)
    conn.close()
    assert records[0].matched_plaintext.startswith("enc1:")
    # Rust-side unlock shows plaintext.
    result = run_rust(
        "history",
        "--unlock",
        "--passphrase",
        "parity-passphrase",
        "--database",
        str(shared_db),
    )
    assert "plaintext=hashcat" in result.stdout
    # Python-side unlock shows the same plaintext.
    from hash_cracker.history import init_encryption

    conn = connect(shared_db)
    key = init_encryption(conn, "parity-passphrase")
    records = list_runs(conn)
    from hash_cracker.history import decrypt_stored

    plaintext = decrypt_stored(key, records[0].matched_plaintext)
    conn.close()
    assert plaintext == "hashcat"
