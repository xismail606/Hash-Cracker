"""Bounded brute-force generation tests: charset, budget, order."""

import pytest

from password_audit.algorithms import HashInputError
from password_audit.bruteforce import (
    DEFAULT_BUDGET,
    HARD_MAX_BUDGET,
    iter_bruteforce_batches,
    resolve_charset,
    validate_bruteforce_options,
)


class TestResolveCharset:
    def test_presets_combine_deduplicated(self):
        alphabet = resolve_charset("lower,digits,lower")
        assert len(alphabet) == 36  # 26 + 10, no duplicates
        assert set("abcdefghijklmnopqrstuvwxyz0123456789") == set(alphabet)

    def test_literal_characters(self):
        assert resolve_charset("abc123") == "abc123"

    def test_empty_raises(self):
        with pytest.raises(HashInputError):
            resolve_charset("   ")

    def test_commas_only_raise(self):
        with pytest.raises(HashInputError):
            resolve_charset(",,,")


class TestValidateBruteforceOptions:
    def test_valid_options_return_space(self):
        alphabet, total = validate_bruteforce_options(1, 2, 1000, "abc")
        assert total == 3 + 9  # 3^1 + 3^2

    def test_max_below_min_raises(self):
        with pytest.raises(HashInputError, match="Maximum length"):
            validate_bruteforce_options(3, 2, 1000, "abc")

    def test_min_below_one_raises(self):
        with pytest.raises(HashInputError, match="at least 1"):
            validate_bruteforce_options(0, 2, 1000, "abc")

    def test_budget_over_hard_max_raises(self):
        with pytest.raises(HashInputError, match="hard maximum"):
            validate_bruteforce_options(1, 2, HARD_MAX_BUDGET + 1, "abc")

    def test_budget_below_one_raises(self):
        with pytest.raises(HashInputError, match="at least 1"):
            validate_bruteforce_options(1, 2, 0, "abc")


class TestIterBruteforceBatches:
    def test_generation_order_and_count(self):
        batches = list(iter_bruteforce_batches("abc", 1, 2, budget=1000, batch_size=4))
        candidates = [c for batch in batches for c in batch]
        assert candidates == ["a", "b", "c", "aa", "ab", "ac", "ba", "bb", "bc", "ca", "cb", "cc"]

    def test_budget_truncates_exactly(self):
        candidates = [c for batch in iter_bruteforce_batches("abc", 1, 3, budget=5) for c in batch]
        assert candidates == ["a", "b", "c", "aa", "ab"]

    def test_budget_never_exceeded(self):
        total = sum(len(b) for b in iter_bruteforce_batches("ab", 1, 4, budget=10))
        assert total == 10

    def test_space_smaller_than_budget_covers_all(self):
        candidates = [c for batch in iter_bruteforce_batches("ab", 1, 2, budget=1000) for c in batch]
        assert len(candidates) == 2 + 4

    def test_default_budget_constant(self):
        assert DEFAULT_BUDGET == 1_000_000
        assert HARD_MAX_BUDGET == 10_000_000
