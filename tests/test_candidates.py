"""Wordlist streaming tests: chunking, line handling, encoding resilience."""

from password_audit.candidates import count_dictionary_lines, iter_wordlist_batches


def write_wordlist(tmp_path, text):
    path = tmp_path / "wordlist.txt"
    path.write_bytes(text.encode("utf-8"))
    return path


class TestIterWordlistBatches:
    def test_batching_respects_batch_size(self, tmp_path):
        path = write_wordlist(tmp_path, "\n".join(f"word{i}" for i in range(10)) + "\n")
        batches = list(iter_wordlist_batches(path, batch_size=3))
        assert [len(b) for b in batches] == [3, 3, 3, 1]
        flattened = [c for batch in batches for c in batch]
        assert flattened == [f"word{i}" for i in range(10)]

    def test_strips_only_line_endings(self, tmp_path):
        path = write_wordlist(tmp_path, "  padded \r\n\ttabbed\nplain")
        candidates = [c for batch in iter_wordlist_batches(path) for c in batch]
        assert candidates == ["  padded ", "\ttabbed", "plain"]

    def test_blank_lines_become_empty_candidates(self, tmp_path):
        path = write_wordlist(tmp_path, "a\n\nb\n")
        candidates = [c for batch in iter_wordlist_batches(path) for c in batch]
        assert candidates == ["a", "", "b"]

    def test_duplicates_preserved(self, tmp_path):
        path = write_wordlist(tmp_path, "x\nx\nx\n")
        candidates = [c for batch in iter_wordlist_batches(path) for c in batch]
        assert candidates == ["x", "x", "x"]

    def test_final_line_without_newline_included(self, tmp_path):
        path = write_wordlist(tmp_path, "a\nb")
        candidates = [c for batch in iter_wordlist_batches(path) for c in batch]
        assert candidates == ["a", "b"]

    def test_invalid_utf8_replaced_not_fatal(self, tmp_path):
        path = tmp_path / "wordlist.txt"
        path.write_bytes(b"good\n\xff\xfebad\ngood2\n")
        candidates = [c for batch in iter_wordlist_batches(path) for c in batch]
        assert candidates[0] == "good"
        assert candidates[2] == "good2"


class TestCountDictionaryLines:
    def test_counts_newlines(self, tmp_path):
        path = write_wordlist(tmp_path, "a\nb\nc\n")
        assert count_dictionary_lines(path) == 3

    def test_unreadable_returns_none(self, tmp_path):
        assert count_dictionary_lines(tmp_path / "missing.txt") is None
