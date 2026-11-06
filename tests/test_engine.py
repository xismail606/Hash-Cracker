"""Golden tests for engine attempt accounting and terminal states.

These lock in v1 behavior BEFORE the multi-target/salted engine changes land
(T044, T036). Attempts are counted in submission order; a match reports the
exact candidate position (offset within the stream + index within its batch).
"""

import hashlib
import threading

import pytest

from password_audit.bruteforce import iter_bruteforce_batches, resolve_charset
from password_audit.candidates import iter_wordlist_batches
from password_audit.engine import (
    EngineInputError,
    STATUS_BUDGET_EXHAUSTED,
    STATUS_CANCELLED,
    STATUS_MATCH,
    STATUS_NO_MATCH,
    STATUS_PAUSED,
    clamp_workers,
    run_audit,
)


def write_wordlist(tmp_path, words):
    path = tmp_path / "wordlist.txt"
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


class TestClampWorkers:
    def test_valid_range_passes(self):
        for n in (1, 4, 8):
            assert clamp_workers(n) == n

    @pytest.mark.parametrize("bad", (0, 9, -1))
    def test_out_of_range_raises(self, bad):
        with pytest.raises(EngineInputError, match="between 1 and 8"):
            clamp_workers(bad)


class TestDictionaryAccounting:
    def test_match_reports_exact_position(self, tmp_path):
        path = write_wordlist(tmp_path, ["alpha", "bravo", "charlie", "delta"])
        target = hashlib.sha256(b"charlie").hexdigest()
        result = run_audit(
            target, "sha256", iter_wordlist_batches(path), workers=2
        )
        assert result.status == STATUS_MATCH
        assert result.attempts == 3  # 'charlie' is the 3rd candidate
        assert result.matched_plaintext == "charlie"
        assert result.workers == 2

    def test_no_match_counts_every_entry(self, tmp_path):
        path = write_wordlist(tmp_path, ["alpha", "bravo", "charlie", "delta"])
        target = hashlib.sha256(b"absent").hexdigest()
        result = run_audit(target, "sha256", iter_wordlist_batches(path), workers=4)
        assert result.status == STATUS_NO_MATCH
        assert result.attempts == 4

    def test_workers_one_matches_parallel(self, tmp_path):
        path = write_wordlist(tmp_path, ["alpha", "bravo", "charlie", "delta"])
        target = hashlib.sha256(b"charlie").hexdigest()
        single = run_audit(target, "sha256", iter_wordlist_batches(path), workers=1)
        multi = run_audit(target, "sha256", iter_wordlist_batches(path), workers=4)
        assert single.attempts == multi.attempts == 3

    def test_parallel_duplicate_match_reports_first_source_position(self):
        from passlib.hash import bcrypt

        plaintext = "synthetic-secret"
        target = bcrypt.using(rounds=4).hash(plaintext)
        source = iter([["not-it"] * 511 + [plaintext], [plaintext]])

        result = run_audit(target, "bcrypt", source, workers=2, total_space=513)

        assert result.status == STATUS_MATCH
        assert result.attempts == 512
        assert result.matched_plaintext == plaintext

    def test_budget_truncates_oversized_source_batch(self):
        plaintext = "match-after-budget"
        target = hashlib.sha256(plaintext.encode()).hexdigest()
        source = iter([["first", plaintext, "last"]])

        result = run_audit(
            target, "sha256", source, workers=1, budget=1, total_space=3
        )

        assert result.status == STATUS_BUDGET_EXHAUSTED
        assert result.attempts == 1
        assert result.matched_plaintext is None


class TestBruteforceAccounting:
    def test_budget_exhausted_reports_exact_budget(self):
        alphabet = resolve_charset("lower")
        target = hashlib.md5(b"zzz-not-reachable").hexdigest()
        result = run_audit(
            target,
            "md5",
            iter_bruteforce_batches(alphabet, 1, 4, 1000),
            workers=2,
            budget=1000,
            total_space=475_254,
        )
        assert result.status == STATUS_BUDGET_EXHAUSTED
        assert result.attempts == 1000

    def test_match_reports_lexicographic_position(self):
        alphabet = resolve_charset("lower")
        target = hashlib.md5(b"abc").hexdigest()
        result = run_audit(
            target,
            "md5",
            iter_bruteforce_batches(alphabet, 1, 4, 1000),
            workers=4,
            budget=1000,
            total_space=475_254,
        )
        assert result.status == STATUS_MATCH
        assert result.attempts == 731  # 26 + 676 + 28 + 1
        assert result.matched_plaintext == "abc"

    def test_fully_covered_space_reports_no_match(self):
        alphabet = resolve_charset("ab")
        target = hashlib.md5(b"zz").hexdigest()
        result = run_audit(
            target,
            "md5",
            iter_bruteforce_batches(alphabet, 1, 2, 1000),
            workers=2,
            budget=1000,
            total_space=2 + 4,
        )
        assert result.status == STATUS_NO_MATCH
        assert result.attempts == 6


class TestCancellation:
    def test_preset_cancel_event_reports_cancelled(self):
        alphabet = resolve_charset("lower")
        target = hashlib.md5(b"unreachable").hexdigest()
        cancel = threading.Event()
        cancel.set()
        result = run_audit(
            target,
            "md5",
            iter_bruteforce_batches(alphabet, 1, 4, 10_000),
            workers=2,
            budget=10_000,
            total_space=475_254,
            cancel_event=cancel,
        )
        assert result.status == STATUS_CANCELLED
        assert result.attempts == 0

    def test_cancel_during_run_stops_scheduling(self):
        alphabet = resolve_charset("lower")
        target = hashlib.md5(b"unreachable").hexdigest()
        cancel = threading.Event()

        def progress(attempts, elapsed_ms, fraction):
            if attempts >= 100:
                cancel.set()

        result = run_audit(
            target,
            "md5",
            iter_bruteforce_batches(alphabet, 1, 8, 10_000_000),
            workers=2,
            budget=10_000_000,
            total_space=36 + sum(36**l for l in range(2, 9)),
            cancel_event=cancel,
            progress_callback=progress,
        )
        assert result.status == STATUS_CANCELLED
        assert 0 < result.attempts < 10_000_000


class TestResumeAccounting:
    def test_match_attempt_count_includes_prior_pass(self):
        plaintext = "resumed-match"
        target = hashlib.sha256(plaintext.encode()).hexdigest()
        source = iter([["already-tried"] * 100, ["not-it", plaintext]])

        result = run_audit(
            target,
            "sha256",
            source,
            workers=1,
            budget=500,
            total_space=200,
            resume_state={"attempts_base": 100, "skip_source": 100},
        )

        assert result.status == STATUS_MATCH
        assert result.attempts == 102
        assert result.matched_plaintext == plaintext

    def test_pause_after_completed_batch_preserves_every_submitted_candidate(self):
        pause = threading.Event()

        def request_pause(attempts, elapsed_ms, fraction):
            pause.set()

        source = iter([[f"wrong-{batch}-{index}" for index in range(2)] for batch in range(12)])

        result = run_audit(
            hashlib.sha256(b"absent").hexdigest(),
            "sha256",
            source,
            workers=1,
            budget=100,
            total_space=200,
            pause_event=pause,
            progress_callback=request_pause,
        )

        assert result.status == STATUS_PAUSED
        assert result.attempts == 8
        assert result.resume == {"attempts_base": 8, "skip_source": 8}


class TestHashlistAudit:
    def test_multi_target_single_pass(self):
        from password_audit.engine import run_hashlist_audit

        targets = [
            {"id": 0, "algorithm": "md5", "hash": hashlib.md5(b"hashcat").hexdigest()},
            {"id": 1, "algorithm": "sha256", "hash": hashlib.sha256(b"hashcat").hexdigest()},
            {"id": 2, "algorithm": "ntlm", "hash": "b4b9b02e6f09a9bd760f388b67351e2b"},
        ]
        source = iter([["hashcat"], ["unrelated"]])
        result = run_hashlist_audit(targets, source, workers=2)
        assert result.status == STATUS_MATCH
        assert result.attempts == 1  # one candidate matched all three targets
        statuses = {t["id"]: t for t in result.targets}
        assert all(statuses[i]["status"] == STATUS_MATCH for i in (0, 1, 2))
        assert statuses[0]["matched_plaintext"] == "hashcat"
        assert statuses[0]["match_at_attempt"] == 1

    def test_different_targets_match_later_in_the_same_batch(self):
        from password_audit.engine import run_hashlist_audit

        targets = [
            {"id": 0, "algorithm": "md5", "hash": hashlib.md5(b"first").hexdigest()},
            {"id": 1, "algorithm": "sha256", "hash": hashlib.sha256(b"second").hexdigest()},
        ]

        result = run_hashlist_audit(targets, iter([["first", "second"]]), workers=2)

        assert result.status == STATUS_MATCH
        assert result.attempts == 2
        by_id = {target["id"]: target for target in result.targets}
        assert by_id[0]["match_at_attempt"] == 1
        assert by_id[1]["match_at_attempt"] == 2
        assert by_id[0]["matched_plaintext"] == "first"
        assert by_id[1]["matched_plaintext"] == "second"

    def test_budget_truncates_oversized_hashlist_batch(self):
        from password_audit.engine import run_hashlist_audit

        targets = [
            {"id": 0, "algorithm": "sha256", "hash": hashlib.sha256(b"later").hexdigest()}
        ]

        result = run_hashlist_audit(
            targets, iter([["first", "later"]]), workers=1, budget=1, total_space=2
        )

        assert result.status == STATUS_BUDGET_EXHAUSTED
        assert result.attempts == 1
        assert result.targets[0]["status"] == STATUS_NO_MATCH

    def test_fully_covered_hashlist_search_is_no_match(self):
        from password_audit.engine import run_hashlist_audit

        targets = [
            {"id": 0, "algorithm": "sha256", "hash": hashlib.sha256(b"absent").hexdigest()}
        ]

        result = run_hashlist_audit(
            targets, iter([["one", "two"]]), workers=1, budget=2, total_space=2
        )

        assert result.status == STATUS_NO_MATCH
        assert result.attempts == 2

    def test_partial_match_exhaustion(self):
        from password_audit.engine import STATUS_NO_MATCH, run_hashlist_audit

        targets = [
            {"id": 0, "algorithm": "md5", "hash": hashlib.md5(b"hashcat").hexdigest()},
            {"id": 1, "algorithm": "sha256", "hash": hashlib.sha256(b"absent").hexdigest()},
        ]
        source = iter([["hashcat"]])
        result = run_hashlist_audit(targets, source, workers=2)
        assert result.status == STATUS_MATCH  # run-level: at least one match
        by_id = {t["id"]: t for t in result.targets}
        assert by_id[0]["status"] == STATUS_MATCH
        assert by_id[1]["status"] == STATUS_NO_MATCH

    def test_all_miss_reports_no_match(self):
        from password_audit.engine import STATUS_NO_MATCH, run_hashlist_audit

        targets = [{"id": 0, "algorithm": "md5", "hash": hashlib.md5(b"absent").hexdigest()}]
        result = run_hashlist_audit(targets, iter([["one", "two"]]), workers=1)
        assert result.status == STATUS_NO_MATCH
        assert result.attempts == 2
        assert result.targets[0]["status"] == STATUS_NO_MATCH
