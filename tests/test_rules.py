"""Tests for hashlist parsing and rule-based mutations."""

import pytest

from password_audit.algorithms import HashInputError
from password_audit.candidates import parse_hashlist
from password_audit.rules import iter_rule_expanded, resolve_rules_preset


class TestParseHashlist:
    def test_prefixed_and_bare_lines(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text(
            "md5:8743b52063cd84097a65d1633f5c74f5\n"
            "# a comment\n"
            "\n"
            "sha256:127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935\n",
            encoding="utf-8",
        )
        entries = parse_hashlist(path)
        assert [(e["algorithm"], e["hash"]) for e in entries] == [
            ("md5", "8743b52063cd84097a65d1633f5c74f5"),
            ("sha256", "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"),
        ]
        assert [e["id"] for e in entries] == [0, 1]

    def test_bare_ambiguous_shape_rejected(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("8743b52063cd84097a65d1633f5c74f5\n", encoding="utf-8")
        with pytest.raises(HashInputError, match="more than one supported format"):
            parse_hashlist(path)

    def test_unknown_algorithm_rejected_with_line_number(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("rot13:abcdef\n", encoding="utf-8")
        with pytest.raises(HashInputError, match="line 1"):
            parse_hashlist(path)

    def test_salted_algorithm_rejected(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("md5_pass_salt:8743b52063cd84097a65d1633f5c74f5\n", encoding="utf-8")
        with pytest.raises(HashInputError, match="salt"):
            parse_hashlist(path)

    def test_empty_file_rejected(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("# only comments\n\n", encoding="utf-8")
        with pytest.raises(HashInputError, match="no targets"):
            parse_hashlist(path)

    def test_wrong_length_hash_rejected(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("sha256:abc123\n", encoding="utf-8")
        with pytest.raises(HashInputError, match="line 1"):
            parse_hashlist(path)


class TestRulePresets:
    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown rules preset"):
            resolve_rules_preset("reverse")

    def test_none_preset_returns_none(self):
        assert resolve_rules_preset("none") is None

    def test_capitalize_variants(self):
        variants_for = resolve_rules_preset("capitalize")
        assert variants_for("hashcat") == ["Hashcat"]
        assert variants_for("Hashcat") == []  # no duplicate of the original

    def test_append_digits_range(self):
        variants_for = resolve_rules_preset("append_digits_0_99")
        assert variants_for("ab") == [f"ab{i}" for i in range(100)]

    def test_leetspeak_substitutes(self):
        variants_for = resolve_rules_preset("leetspeak")
        assert variants_for("password") == ["p455w0rd"]
        assert variants_for("xyz") == []


class TestIterRuleExpanded:
    def test_expansion_includes_original_first(self):
        source = iter([["hashcat"]])
        expanded = [c for batch in iter_rule_expanded(source, resolve_rules_preset("capitalize"), 100) for c in batch]
        assert expanded[0] == "hashcat"
        assert "Hashcat" in expanded

    def test_budget_truncates_exactly(self):
        source = iter([["ab"]])
        expanded = [c for batch in iter_rule_expanded(source, resolve_rules_preset("append_digits_0_99"), 7) for c in batch]
        assert len(expanded) == 7
        assert expanded[:3] == ["ab", "ab0", "ab1"]

    def test_batch_independence_keeps_memory_bounded(self):
        # Two large incoming batches expand independently; total respects budget.
        source = iter([["w1"] * 50, ["w2"] * 50])
        expanded_batches = list(iter_rule_expanded(source, resolve_rules_preset("capitalize"), 60))
        total = sum(len(b) for b in expanded_batches)
        assert total == 60
