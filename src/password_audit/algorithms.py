"""Hash structure analysis and algorithm selection.

Supported formats in v1 are MD5 (32 hex), NTLM (32 hex), and SHA-256 (64 hex).
MD5 and NTLM share the same 32-character hexadecimal shape, so structure alone
cannot distinguish them; callers must ask the operator to choose explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALGORITHM_NAMES = (
    "md5",
    "sha256",
    "ntlm",
    "sha1",
    "sha224",
    "sha384",
    "sha512",
    "md4",
    "lm",
    "md5_pass_salt",
    "md5_salt_pass",
    "sha1_pass_salt",
    "sha1_salt_pass",
    "sha256_pass_salt",
    "sha256_salt_pass",
    "sha512_pass_salt",
    "sha512_salt_pass",
)

# Digest length in hexadecimal characters per supported algorithm.
ALGORITHM_LENGTHS = {
    "md5": 32,
    "sha256": 64,
    "ntlm": 32,
    "sha1": 40,
    "sha224": 56,
    "sha384": 96,
    "sha512": 128,
    "md4": 32,
    "lm": 16,
    "md5_pass_salt": 32,
    "md5_salt_pass": 32,
    "sha1_pass_salt": 40,
    "sha1_salt_pass": 40,
    "sha256_pass_salt": 64,
    "sha256_salt_pass": 64,
    "sha512_pass_salt": 128,
    "sha512_salt_pass": 128,
}

# Algorithms compatible with each hexadecimal digest length. Note that a
# 32-character shape maps to three supported algorithms (MD5, NTLM, and MD4).
# Salted formats are selected explicitly by name (shape identification lists
# only the unsalted base formats).
ALGORITHMS_BY_LENGTH = {
    16: ("lm",),
    32: ("md5", "ntlm", "md4"),
    40: ("sha1",),
    56: ("sha224",),
    64: ("sha256",),
    96: ("sha384",),
    128: ("sha512",),
}

# Salted formats: name -> (base digest algorithm, salt position relative to
# the candidate). hashcat modes: md5_pass_salt=10, md5_salt_pass=20,
# sha1_pass_salt=110, sha1_salt_pass=120, sha256_pass_salt=1410,
# sha256_salt_pass=1420, sha512_pass_salt=1710, sha512_salt_pass=1720.
SALTED_ALGORITHMS = {
    "md5_pass_salt": ("md5", "pass_salt"),
    "md5_salt_pass": ("md5", "salt_pass"),
    "sha1_pass_salt": ("sha1", "pass_salt"),
    "sha1_salt_pass": ("sha1", "salt_pass"),
    "sha256_pass_salt": ("sha256", "pass_salt"),
    "sha256_salt_pass": ("sha256", "salt_pass"),
    "sha512_pass_salt": ("sha512", "pass_salt"),
    "sha512_salt_pass": ("sha512", "salt_pass"),
}


def is_salted(algorithm: str) -> bool:
    """Return True when the algorithm needs a user-supplied salt."""
    return algorithm in SALTED_ALGORITHMS


class HashInputError(ValueError):
    """Raised when a submitted hash value is malformed or unsupported."""


@dataclass
class HashAssessment:
    """Result of inspecting a submitted hash value's structure."""

    submitted: str
    normalized: str
    compatible_algorithms: tuple[str, ...] = ()
    ambiguous: bool = False
    error: str | None = None
    # Non-hex characters found in the value, used for error messages.
    invalid_characters: tuple[str, ...] = field(default_factory=tuple)


def normalize_hash(value: str) -> str:
    """Trim outer whitespace and lowercase the submitted hash string.

    Raises :class:`HashInputError` for empty or non-hex values.
    """
    if not isinstance(value, str):
        raise HashInputError("The hash value must be a string.")
    trimmed = value.strip()
    if not trimmed:
        raise HashInputError(
            "The hash value is empty. Provide a hexadecimal digest such as "
            "a 32-character (MD5/NTLM/MD4) or 64-character (SHA-256) value."
        )
    invalid = tuple(sorted({ch for ch in trimmed if ch not in "0123456789abcdefABCDEF"}))
    if invalid:
        shown = ", ".join(repr(ch) for ch in invalid[:8])
        raise HashInputError(
            "The hash value contains characters that are not hexadecimal "
            f"({shown}). Supported formats use 0-9 and a-f only."
        )
    return trimmed.lower()


def assess_hash(value: str) -> HashAssessment:
    """Inspect a submitted hash and report compatible supported algorithms.

    The assessment never claims that a shape uniquely proves an algorithm.
    A 32-hex value is always reported as ambiguous between MD5, NTLM, and MD4.
    """
    normalized = normalize_hash(value)
    length = len(normalized)
    candidates = ALGORITHMS_BY_LENGTH.get(length, ())
    if not candidates:
        expected = ", ".join(str(n) for n in sorted(ALGORITHMS_BY_LENGTH))
        raise HashInputError(
            f"Unsupported hash shape: {length} hexadecimal characters. "
            f"Supported formats are {expected} characters long "
            "(LM: 16, MD5/NTLM/MD4: 32, SHA-1: 40, SHA-224: 56, SHA-256: 64, "
            "SHA-384: 96, SHA-512: 128)."
        )
    return HashAssessment(
        submitted=value,
        normalized=normalized,
        compatible_algorithms=candidates,
        ambiguous=len(candidates) > 1,
    )


def select_algorithm(value: str, algorithm: str | None) -> tuple[HashAssessment, str]:
    """Validate a submitted hash against an explicitly selected algorithm.

    ``algorithm`` must name one supported format. When the hash shape matches
    more than one supported format (the 32-hex MD5/NTLM overlap), an explicit
    selection is required — passing ``None`` raises :class:`HashInputError`
    instead of guessing.
    """
    assessment = assess_hash(value)
    if algorithm is None:
        if assessment.ambiguous:
            names = " or ".join(assessment.compatible_algorithms)
            raise HashInputError(
                "This hash shape matches more than one supported format "
                f"({', '.join(assessment.compatible_algorithms)}). "
                f"Select an algorithm explicitly (--algorithm {names}) before auditing."
            )
        algorithm = assessment.compatible_algorithms[0]
    algorithm = algorithm.strip().lower()
    if algorithm not in ALGORITHM_NAMES:
        supported = ", ".join(ALGORITHM_NAMES)
        raise HashInputError(
            f"Unsupported algorithm {algorithm!r}. Supported formats: {supported}."
        )
    expected = ALGORITHM_LENGTHS[algorithm]
    if len(assessment.normalized) != expected:
        raise HashInputError(
            f"The hash does not match the {algorithm} format: expected "
            f"{expected} hexadecimal characters, got {len(assessment.normalized)}."
        )
    # Salted formats share their base digest's shape but are opt-in explicit
    # selections, so the shape-compatibility check does not apply to them.
    if algorithm not in assessment.compatible_algorithms and not is_salted(algorithm):
        raise HashInputError(
            f"The hash shape is not compatible with {algorithm}. Compatible "
            f"formats for this shape: {', '.join(assessment.compatible_algorithms)}."
        )
    return assessment, algorithm
