"""Tests for hash structure analysis and algorithm selection."""

import pytest

from password_audit.algorithms import (
    ALGORITHM_LENGTHS,
    ALGORITHM_NAMES,
    HashInputError,
    assess_hash,
    normalize_hash,
    select_algorithm,
)


class TestNormalizeHash:
    def test_trims_and_lowercases(self):
        assert normalize_hash("  ABCDEF0123  ") == "abcdef0123"

    def test_empty_raises(self):
        with pytest.raises(HashInputError):
            normalize_hash("   ")

    def test_non_string_raises(self):
        with pytest.raises(HashInputError):
            normalize_hash(123)

    def test_non_hex_raises(self):
        with pytest.raises(HashInputError):
            normalize_hash("zzzz")
        with pytest.raises(HashInputError):
            normalize_hash("$2a$05$MBCzKhG1KhezLh")


class TestAssessHash:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("299bd128c1101fd6", ("lm",)),  # 16 hex
            ("8743b52063cd84097a65d1633f5c74f5", ("md5", "ntlm", "md4")),  # 32 hex
            ("b89eaac7e61417341b710b727768294d0e6a277b", ("sha1", "ripemd160")),  # 40 hex
            ("e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198", ("sha224", "sha512_224")),
            ("1" * 64, ("sha256", "sha512_256")),
            ("2" * 96, ("sha384",)),
            ("3" * 128, ("sha512",)),
        ],
    )
    def test_shape_mapping(self, value, expected):
        assessment = assess_hash(value)
        assert assessment.compatible_algorithms == expected
        assert assessment.ambiguous == (len(expected) > 1)
        assert assessment.normalized == value.lower()

    def test_unsupported_length_raises(self):
        with pytest.raises(HashInputError, match="Unsupported hash shape"):
            assess_hash("a" * 41)
        with pytest.raises(HashInputError, match="Unsupported hash shape"):
            assess_hash("a" * 8)

    def test_non_hex_rejected(self):
        with pytest.raises(HashInputError, match="not hexadecimal"):
            assess_hash("z" * 32)


class TestSelectAlgorithm:
    def test_unambiguous_shape_auto_selects(self):
        assessment, algorithm = select_algorithm("2" * 96, None)
        assert algorithm == "sha384"

    def test_ambiguous_shape_requires_explicit(self):
        with pytest.raises(HashInputError, match="Select an algorithm"):
            select_algorithm("8743b52063cd84097a65d1633f5c74f5", None)

    def test_explicit_selection_accepted(self):
        for algorithm in ("md5", "ntlm", "md4"):
            assessment, selected = select_algorithm(
                "8743b52063cd84097a65d1633f5c74f5", algorithm
            )
            assert selected == algorithm

    def test_wrong_length_for_algorithm_rejected(self):
        with pytest.raises(HashInputError, match="does not match the md5 format"):
            select_algorithm("b89eaac7e61417341b710b727768294d0e6a277b", "md5")

    def test_unsupported_shape_rejected_before_length_check(self):
        with pytest.raises(HashInputError, match="Unsupported hash shape"):
            select_algorithm("abc", "md5")

    def test_unknown_algorithm_rejected(self):
        with pytest.raises(HashInputError, match="Unsupported algorithm"):
            select_algorithm("1" * 64, "rot13")


def test_algorithm_registry_is_consistent():
    from password_audit.algorithms import is_adaptive

    # Adaptive formats verify against full hash strings; they have no fixed
    # digest length entry.
    assert set(ALGORITHM_LENGTHS) == set(ALGORITHM_NAMES) - {
        n for n in ALGORITHM_NAMES if is_adaptive(n)
    }
    for name in ALGORITHM_LENGTHS:
        assert ALGORITHM_LENGTHS[name] > 0
