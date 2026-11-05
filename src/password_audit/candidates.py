"""Wordlist streaming and hashlist parsing for dictionary mode.

The wordlist is read incrementally in bounded batches so arbitrarily large
local files can be audited without loading them into memory. Behavior for
irregular dictionary data:

- Only line terminators (``\\r\\n`` / ``\\n``) are stripped; all other
  whitespace and characters are preserved as part of the candidate.
- Duplicate entries are preserved and attempted in file order.
- Blank lines become empty-string candidates and count as attempts.
- Bytes that are not valid UTF-8 are decoded with replacement characters so
  one malformed line cannot abort the whole audit.

Hashlists (one audit target per line) are fully validated up front: lines may
carry an explicit ``algorithm:hash`` prefix or a bare hash that resolves to a
single supported format. Blank lines and ``#`` comments are skipped. A bare
32-hex line is rejected because MD5/NTLM/MD4 cannot be distinguished by shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .algorithms import (
    ALGORITHM_NAMES,
    HashInputError,
    is_adaptive,
    is_salted,
    select_algorithm,
)

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


def parse_hashlist(path: str | Path) -> list[dict]:
    """Parse and fully validate a hashlist file before any processing.

    Each non-empty, non-comment line is one target: either
    ``algorithm:hash`` (explicit selection, e.g. ``md5:8743b520...``) or a
    bare hash whose shape resolves to exactly one supported format. Salted
    formats are rejected because a hashlist carries no per-target salt.

    Returns a list of ``{"algorithm", "hash", "line"}`` entries. Raises
    :class:`HashInputError` with the offending line number for any invalid
    line, an ambiguous bare shape, or an empty file.
    """
    entries: list[dict] = []
    try:
        handle = open(path, "r", encoding="utf-8")
    except OSError as exc:
        raise HashInputError(f"Cannot read the hashlist file: {exc}") from exc
    with handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                algorithm, _, value = line.partition(":")
                algorithm = algorithm.strip().lower()
                if algorithm not in ALGORITHM_NAMES:
                    raise HashInputError(
                        f"Hashlist line {lineno}: unknown algorithm {algorithm!r}."
                    )
                if is_salted(algorithm) or is_adaptive(algorithm):
                    raise HashInputError(
                        f"Hashlist line {lineno}: format {algorithm} is not "
                        "supported in hashlists."
                    )
                try:
                    assessment, algorithm = select_algorithm(value, algorithm)
                except HashInputError as exc:
                    raise HashInputError(f"Hashlist line {lineno}: {exc}") from exc
            else:
                try:
                    assessment, algorithm = select_algorithm(line, None)
                except HashInputError as exc:
                    raise HashInputError(f"Hashlist line {lineno}: {exc}") from exc
            entries.append(
                {
                    "id": len(entries),
                    "algorithm": algorithm,
                    "hash": assessment.normalized,
                    "line": lineno,
                }
            )
    if not entries:
        raise HashInputError("The hashlist file contains no targets.")
    return entries
