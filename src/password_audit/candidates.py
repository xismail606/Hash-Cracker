"""Wordlist streaming for dictionary mode.

The wordlist is read incrementally in bounded batches so arbitrarily large
local files can be audited without loading them into memory. Behavior for
irregular dictionary data:

- Only line terminators (``\\r\\n`` / ``\\n``) are stripped; all other
  whitespace and characters are preserved as part of the candidate.
- Duplicate entries are preserved and attempted in file order.
- Blank lines become empty-string candidates and count as attempts.
- Bytes that are not valid UTF-8 are decoded with replacement characters so
  one malformed line cannot abort the whole audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

DEFAULT_BATCH_SIZE = 8192


def iter_wordlist_batches(
    path: str | Path,
    batch_size: int = DEFAULT_BATCH_SIZE,
    encoding: str = "utf-8",
) -> Iterator[list[str]]:
    """Yield bounded batches of candidates read from a UTF-8 wordlist."""
    batch: list[str] = []
    with open(path, "r", encoding=encoding, errors="replace", newline="") as handle:
        for line in handle:
            batch.append(line.rstrip("\r\n"))
            if len(batch) >= batch_size:
                yield batch
                batch = []
    if batch:
        yield batch


def count_dictionary_lines(path: str | Path) -> int | None:
    """Best-effort total line count for progress reporting, or ``None``."""
    try:
        with open(path, "rb") as handle:
            count = 0
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                count += chunk.count(b"\n")
            return count
    except OSError:
        return None
