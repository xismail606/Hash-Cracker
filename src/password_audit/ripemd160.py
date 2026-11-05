"""Pure-Python RIPEMD-160 implementation.

RIPEMD-160 is no longer exposed by OpenSSL 3's default provider (so
``hashlib.new("ripemd160")`` fails on modern interpreters), and the plan's
research phase calls for a dependency-free implementation.

The tables below were cross-checked against a known-good reference
implementation (karpathy/cryptos ripemd160.py) and validated against the
official RIPEMD-160 test vectors.
"""

from __future__ import annotations

import struct

# Left-line message word order (80 steps).
_R_L = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)

# Right-line message word order.
_R_R = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)

# Left-line rotate amounts.
_S_L = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)

# Right-line rotate amounts.
_S_R = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)

_K_L = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_K_R = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
    """Round function selected per 16-step round (0-4), shared by both lines."""
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & z)
    if j == 2:
        return (x | ~y) ^ z
    if j == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(data: bytes) -> bytes:
    """Return the 20-byte RIPEMD-160 digest of ``data``."""
    h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[offset:offset + 64])
        a_l, b_l, c_l, d_l, e_l = h
        a_r, b_r, c_r, d_r, e_r = h
        for j in range(80):
            round_index = j // 16
            # Left line
            tmp = (
                _rol(
                    (
                        a_l
                        + _f(round_index, b_l, c_l, d_l)
                        + x[_R_L[j]]
                        + _K_L[round_index]
                    )
                    & 0xFFFFFFFF,
                    _S_L[j],
                )
                + e_l
            ) & 0xFFFFFFFF
            a_l, e_l, d_l, c_l, b_l = e_l, d_l, _rol(c_l, 10), b_l, tmp
            # Right line (round functions in reverse order)
            tmp = (
                _rol(
                    (
                        a_r
                        + _f(4 - round_index, b_r, c_r, d_r)
                        + x[_R_R[j]]
                        + _K_R[round_index]
                    )
                    & 0xFFFFFFFF,
                    _S_R[j],
                )
                + e_r
            ) & 0xFFFFFFFF
            a_r, e_r, d_r, c_r, b_r = e_r, d_r, _rol(c_r, 10), b_r, tmp
        h = (
            (h[1] + c_l + d_r) & 0xFFFFFFFF,
            (h[2] + d_l + e_r) & 0xFFFFFFFF,
            (h[3] + e_l + a_r) & 0xFFFFFFFF,
            (h[4] + a_l + b_r) & 0xFFFFFFFF,
            (h[0] + b_l + c_r) & 0xFFFFFFFF,
        )
    return struct.pack("<5I", *h)


def ripemd160_hex(data: bytes) -> str:
    return ripemd160(data).hex()
