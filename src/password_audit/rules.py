"""Rule-based dictionary mutations.

A preset maps each wordlist word to a deterministic list of variants. The
expanded stream (original word first, then variants) is what the engine
audits, so the candidate budget governs the expanded count exactly.

Presets are code-defined and deterministic; custom rule files are out of
scope for v2. Preset composition (e.g. capitalize + append digits) is
expressed as dedicated presets rather than a rule language.
"""

from __future__ import annotations

from collections.abc import Iterator

LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})


def _variants_capitalize(word: str) -> list[str]:
    variant = word.capitalize()
    return [variant] if variant != word else []


def _variants_upper(word: str) -> list[str]:
    variant = word.upper()
    return [variant] if variant != word else []


def _variants_lower(word: str) -> list[str]:
    variant = word.lower()
    return [variant] if variant != word else []


def _variants_leetspeak(word: str) -> list[str]:
    translated = word.translate(LEET_MAP)
    return [translated] if translated != word else []


def _make_append_digits(start: int, stop: int):
    def variants(word: str) -> list[str]:
        return [f"{word}{n}" for n in range(start, stop + 1)]

    return variants


def _variants_append_years(word: str) -> list[str]:
    return [f"{word}{year}" for year in range(1990, 2030)]


RULE_PRESETS: dict[str, callable] = {
    "capitalize": _variants_capitalize,
    "upper": _variants_upper,
    "lower": _variants_lower,
    "leetspeak": _variants_leetspeak,
    "append_digits_0_99": _make_append_digits(0, 99),
    "append_years": _variants_append_years,
}


def _make_all_variants(word: str) -> list[str]:
    seen: dict[str, None] = {}
    for preset_name, variants_for in RULE_PRESETS.items():
        if preset_name == "all":
            continue
        for variant in variants_for(word):
            seen.setdefault(variant, None)
    return list(seen)


RULE_PRESETS["all"] = _make_all_variants


def resolve_rules_preset(name: str) -> callable:
    """Return the variant function for a preset name; raise ValueError if unknown."""
    if name == "none":
        return None
    variants_for = RULE_PRESETS.get(name)
    if variants_for is None:
        known = ", ".join(sorted(RULE_PRESETS))
        raise ValueError(f"Unknown rules preset {name!r}. Known presets: {known}.")
    return variants_for


def iter_rule_expanded(
    batch_source: Iterator[list[str]],
    variants_for: callable,
    budget: int,
) -> Iterator[list[str]]:
    """Yield rule-expanded batches, truncated at the candidate budget.

    Each incoming batch is expanded independently (original word first, then
    its variants) so memory stays bounded regardless of wordlist size. The
    yielded candidate count never exceeds ``budget``.
    """
    emitted = 0
    for batch in batch_source:
        expanded: list[str] = []
        for word in batch:
            expanded.append(word)
            emitted += 1
            if emitted >= budget:
                if expanded:
                    yield expanded
                return
            for variant in variants_for(word):
                expanded.append(variant)
                emitted += 1
                if emitted >= budget:
                    if expanded:
                        yield expanded
                    return
        if expanded:
            yield expanded
