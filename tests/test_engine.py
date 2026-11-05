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
