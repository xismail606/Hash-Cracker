"""Bounded brute-force candidate generation.

Candidates are generated deterministically from one selected alphabet and a
minimum/maximum length range. Every run stops at the configured candidate
budget (default 1,000,000; hard maximum 10,000,000) so a search can never
run unbounded.
"""

from __future__ import annotations

import string
from itertools import product
from typing import Iterator

from .algorithms import HashInputError

DEFAULT_BUDGET = 1_000_000
HARD_MAX_BUDGET = 10_000_000

CHARSET_PRESETS: dict[str, str] = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}


def resolve_charset(spec: str) -> str:
    """Resolve a charset specification into a single deduplicated alphabet.

    The specification may name presets (``lower``, ``upper``, ``digits``,
    ``symbols``) or supply literal characters, separated by commas. For
    example ``lower,digits`` or ``abc123``. Comma itself cannot be included
    as a literal character; supply ``symbols`` presets for punctuation.
    """
    if not spec or not spec.strip():
        raise HashInputError(
            "Brute-force mode requires a non-empty character set "
            "(preset names lower, upper, digits, symbols, or literal characters)."
        )
    alphabet = ""
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        alphabet += CHARSET_PRESETS.get(token, token)
    seen: dict[str, None] = {}
    for ch in alphabet:
        seen.setdefault(ch, None)
    resolved = "".join(seen)
    if not resolved:
        raise HashInputError(
            "The selected character set resolved to an empty alphabet. "
            "Use preset names (lower, upper, digits, symbols) or literal characters."
        )
    return resolved


def validate_bruteforce_options(
    min_length: int,
    max_length: int,
    budget: int,
    alphabet: str | None = None,
) -> tuple[str, int]:
    """Validate length range and candidate budget; return (alphabet, total_space)."""
    if not isinstance(min_length, int) or not isinstance(max_length, int):
        raise HashInputError("Minimum and maximum lengths must be integers.")
    if min_length < 1:
        raise HashInputError("Minimum candidate length must be at least 1.")
    if max_length < min_length:
        raise HashInputError(
            f"Maximum length ({max_length}) must be greater than or equal to "
            f"the minimum length ({min_length})."
        )
    if not isinstance(budget, int):
        raise HashInputError("The candidate budget must be an integer.")
    if budget < 1:
        raise HashInputError("The candidate budget must be at least 1.")
    if budget > HARD_MAX_BUDGET:
        raise HashInputError(
            f"The candidate budget {budget:,} exceeds the hard maximum of "
            f"{HARD_MAX_BUDGET:,} candidates per run."
        )
    if alphabet is None:
        raise HashInputError("Brute-force mode requires a resolved alphabet.")
    total_space = sum(len(alphabet) ** length for length in range(min_length, max_length + 1))
    return alphabet, total_space


def iter_bruteforce_batches(
    alphabet: str,
    min_length: int,
    max_length: int,
    budget: int = DEFAULT_BUDGET,
    batch_size: int = 8192,
) -> Iterator[list[str]]:
    """Yield bounded batches of generated candidates up to ``budget``.

    Candidates are produced in increasing length order and lexicographic
    order within each length. The generator never yields more candidates
    than the configured budget.
    """
    emitted = 0
    for length in range(min_length, max_length + 1):
        batch: list[str] = []
        for tuple_candidate in product(alphabet, repeat=length):
            batch.append("".join(tuple_candidate))
            emitted += 1
            if emitted >= budget:
                if batch:
                    yield batch
                return
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch
