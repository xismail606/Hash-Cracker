import pytest

from hash_cracker.cli import _progress_limit


@pytest.mark.parametrize(
    ("total_space", "budget", "expected"),
    [
        (2_821_109_907_456, 10_000, 10_000),
        (100, 1_000, 100),
        (None, 1_000, None),
    ],
)
def test_progress_limit_follows_known_run_boundaries(total_space, budget, expected):
    assert _progress_limit(total_space, budget) == expected


def test_hashlist_no_store_option_omits_match_plaintext_from_history(tmp_path, capsys):
    from hashlib import md5

    from hash_cracker.cli import main
    from hash_cracker.history import connect, list_runs

    wordlist = tmp_path / "words.txt"
    hashlist = tmp_path / "hashes.txt"
    database = tmp_path / "history.db"
    wordlist.write_text("hashcat\n", encoding="utf-8")
    hashlist.write_text(
        f"md5:{md5(b'hashcat').hexdigest()}\n", encoding="utf-8"
    )

    exit_code = main(
        [
            "audit",
            "--hashlist",
            str(hashlist),
            "--mode",
            "dictionary",
            "--wordlist",
            str(wordlist),
            "--database",
            str(database),
            "--no-store-plaintext",
            "--yes",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Targets   : 1/1 matched" in output
    conn = connect(database)
    try:
        record = list_runs(conn)[0]
    finally:
        conn.close()
    assert record.status == "match"
    assert record.matched_plaintext is None
    assert record.as_dict()["plaintext_withheld"] is True


def test_single_target_dictionary_audit_matches_and_records_history(tmp_path, capsys):
    """Regression: a single-hash audit must not crash before running."""
    from hashlib import md5

    from hash_cracker.cli import main
    from hash_cracker.history import connect, list_runs

    wordlist = tmp_path / "words.txt"
    database = tmp_path / "history.db"
    wordlist.write_text("wrong\nhashcat\n", encoding="utf-8")
    target = md5(b"hashcat").hexdigest()

    exit_code = main(
        [
            "audit",
            target,
            "--algorithm",
            "md5",
            "--mode",
            "dictionary",
            "--wordlist",
            str(wordlist),
            "--database",
            str(database),
            "--yes",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Status    : MATCH" in output
    assert "Plaintext : hashcat" in output

    conn = connect(database)
    try:
        record = list_runs(conn)[0]
    finally:
        conn.close()
    assert record.status == "match"
    assert record.matched_plaintext == "hashcat"


def test_version_flag_prints_package_version(capsys):
    from hash_cracker import __version__
    from hash_cracker.cli import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_declared_versions_agree():
    """pyproject, the package, and the dashboard must advertise one version."""
    import json
    import tomllib
    from pathlib import Path

    from hash_cracker import __version__

    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_json = json.loads(
        (root / "frontend" / "package.json").read_text(encoding="utf-8")
    )
    assert pyproject["project"]["version"] == __version__
    assert package_json["version"] == __version__


def test_export_includes_hashlist_batches_in_csv_and_json(tmp_path, capsys):
    import csv
    import json
    from hashlib import md5

    from hash_cracker.cli import main

    wordlist = tmp_path / "words.txt"
    hashlist = tmp_path / "hashes.txt"
    database = tmp_path / "history.db"
    wordlist.write_text("hashcat\n", encoding="utf-8")
    hashlist.write_text(
        f"md5:{md5(b'hashcat').hexdigest()}\n", encoding="utf-8"
    )

    exit_code = main(
        [
            "audit",
            "--hashlist",
            str(hashlist),
            "--mode",
            "dictionary",
            "--wordlist",
            str(wordlist),
            "--database",
            str(database),
            "--yes",
        ]
    )
    assert exit_code == 0
    capsys.readouterr()

    csv_path = tmp_path / "report.csv"
    json_path = tmp_path / "report.json"
    assert main(["export", str(csv_path), "--format", "csv",
                 "--database", str(database)]) == 0
    assert main(["export", str(json_path), "--format", "json",
                 "--database", str(database)]) == 0

    with open(csv_path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    batch_rows = [row for row in rows if row["target_count"]]
    assert len(batch_rows) == 1
    assert batch_rows[0]["target_count"] == "1"

    with open(json_path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert len(payload["runs"]) == 1
    assert len(payload["batches"]) == 1
    assert payload["batches"][0]["target_count"] == 1
