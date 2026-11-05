"""Digest adapters for the supported audit algorithms.

MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 use Python's ``hashlib``.
NTLM is MD4 over UTF-16LE encoded input; the plan calls for Passlib's
``nthash`` implementation. Passlib 1.7.4 fails to import on Python 3.13
because the standard-library ``crypt`` module was removed, so this module
uses Passlib when available and falls back to a small pure-Python MD4
implementation of the same NTLM calculation. MD4 (mode 900, raw MD4 over the
UTF-8 bytes) reuses the same fallback implementation. LM hashes come from
Passlib's ``lmhash`` (pure-Python DES; requires Passlib to be importable).
"""

from __future__ import annotations

import hashlib
import struct

from .algorithms import SALTED_ALGORITHMS

_ALGORITHM_MAP = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
}


def hash_candidate(candidate: str, algorithm: str, salt: str | None = None) -> str:
    """Return the lowercase hexadecimal digest for one candidate string.

    The candidate is hashed exactly as written (no trimming) so dictionary
    entries keep the value stored in the wordlist. Salted formats combine
    ``candidate`` and ``salt`` per the registry's salt position; the salt is
    required for them and must not be supplied for unsalted formats.
    """
    if algorithm in _ALGORITHM_MAP:
        if salt is not None:
            raise ValueError(f"Algorithm {algorithm!r} does not take a salt.")
        return hashlib.new(_ALGORITHM_MAP[algorithm], candidate.encode("utf-8")).hexdigest()
    if algorithm in SALTED_ALGORITHMS:
        if not salt:
            raise ValueError(f"Algorithm {algorithm!r} requires a salt.")
        base, position = SALTED_ALGORITHMS[algorithm]
        material = (
            f"{candidate}{salt}" if position == "pass_salt" else f"{salt}{candidate}"
        ).encode("utf-8")
        return hashlib.new(_ALGORITHM_MAP[base], material).hexdigest()
    if algorithm == "ntlm":
        if salt is not None:
            raise ValueError(f"Algorithm {algorithm!r} does not take a salt.")
        return ntlm_hash(candidate)
    if algorithm == "md4":
        if salt is not None:
            raise ValueError(f"Algorithm {algorithm!r} does not take a salt.")
        return _md4_hex(candidate.encode("utf-8"))
    if algorithm == "lm":
        if salt is not None:
            raise ValueError(f"Algorithm {algorithm!r} does not take a salt.")
        return lm_hash(candidate)
    raise ValueError(f"Unsupported algorithm: {algorithm!r}")


# --- NTLM and LM -------------------------------------------------------

try:  # pragma: no cover - exercised only on interpreters where Passlib works
    from passlib.hash import lmhash as _passlib_lmhash
    from passlib.hash import nthash as _passlib_nthash

    def ntlm_hash(candidate: str) -> str:
        """Return the NTLM digest (MD4 of UTF-16LE input) via Passlib."""
        return _passlib_nthash.hash(candidate).lower()

    def lm_hash(candidate: str) -> str:
        """Return the LAN Manager digest via Passlib (uppercase, 14-byte key).

        Only the first 8-byte DES block (16 hex characters) is returned,
        matching the 16-hex LM format hashcat uses. The first block depends
        solely on the first seven characters of the candidate, so a 16-hex
        LM target identifies passwords by their first seven characters.
        """
        return _passlib_lmhash.hash(candidate).lower()[:16]

except Exception:  # pragma: no cover - fallback path for Python 3.13+
    def ntlm_hash(candidate: str) -> str:
        """Return the NTLM digest using the built-in MD4 fallback."""
        return _md4_hex(candidate.encode("utf-16-le"))

    def lm_hash(candidate: str) -> str:
        """LM hashing requires Passlib; it is unavailable without it."""
        raise ValueError(
            "LM hashing requires Passlib, which could not be imported on this "
            "interpreter. Use MD4/NTLM/SHA family formats instead."
        )


def _md4_hex(data: bytes) -> str:  # pragma: no cover - exercised by fallback
    """Compute an MD4 digest with a compact pure-Python implementation."""
    return _md4_digest(data).hex()


def _md4_digest(data: bytes) -> bytes:
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    a0, b0, c0, d0 = state
    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[offset:offset + 64])
        a, b, c, d = a0, b0, c0, d0
        for k in range(16):  # Round 1: shifts cycle 3, 7, 11, 19
            a = _rol((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, (3, 7, 11, 19)[k % 4])
            a, d, c, b = d, c, b, a
        for k in range(16):  # Round 2: word order 0,4,8,12.. shifts cycle 3, 5, 9, 13
            i = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)[k]
            a = _rol((a + _g(b, c, d) + x[i] + 0x5A827999) & 0xFFFFFFFF, (3, 5, 9, 13)[k % 4])
            a, d, c, b = d, c, b, a
        for k in range(16):  # Round 3: word order 0,8,4,12.. shifts cycle 3, 9, 11, 15
            i = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[k]
            a = _rol((a + _h(b, c, d) + x[i] + 0x6ED9EBA1) & 0xFFFFFFFF, (3, 9, 11, 15)[k % 4])
            a, d, c, b = d, c, b, a
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z) & 0xFFFFFFFF


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
