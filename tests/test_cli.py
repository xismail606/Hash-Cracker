import pytest

from password_audit.cli import _progress_limit


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

    from password_audit.cli import main
    from password_audit.history import connect, list_runs

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
