"""Digest adapter tests: RFC 1320 MD4 vectors and hashcat example hashes.

Every hashcat example used here is the digest of the plaintext ``hashcat``
(the convention for hashcat's unsalted example-hash list).
"""

import hashlib
from typing import ClassVar

import pytest

from hash_cracker.hashing import _md4_hex, hash_candidate, verify_candidate

RFC1320_VECTORS = {
    b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
    b"a": "bde52cb31de33e46245e05fbdbd6fb24",
    b"abc": "a448017aaf21d8525fc10ae87aa6729d",
    b"message digest": "d9130a8164549fe818874806e1c7014b",
    b"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "043f8582f241db351ce627e153e7f0e4",
    b"1234567890" * 8: "e33b4ddc9c38f2199c3e7b164fcc0536",
}

# (algorithm, hashcat mode, expected digest of "hashcat")
HASHCAT_EXAMPLES = [
    ("md5", 0, "8743b52063cd84097a65d1633f5c74f5"),
    ("ntlm", 1000, "b4b9b02e6f09a9bd760f388b67351e2b"),
    ("md4", 900, "afe04867ec7a3845145579a95f72eca7"),
    ("sha1", 100, "b89eaac7e61417341b710b727768294d0e6a277b"),
    ("sha224", 1300, "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198"),
    ("sha256", 1400, "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"),
    ("sha384", None, hashlib.sha384(b"hashcat").hexdigest()),
    ("sha512", 1700, "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"),
]

# LM digests of "hashcat": hashcat mode 3000 publishes the first DES block
# (16 hex); the full 32-hex digest appends the null-block second half
# because "hashcat" is only seven characters long.
LM_FULL_HASHCAT = "299bd128c1101fd6aad3b435b51404ee"


class TestMD4Fallback:
    @pytest.mark.parametrize(("data", "expected"), sorted(RFC1320_VECTORS.items()))
    def test_rfc1320_vectors(self, data, expected):
        assert _md4_hex(data) == expected


class TestHashcatExamples:
    @pytest.mark.parametrize(("algorithm", "mode", "expected"), HASHCAT_EXAMPLES)
    def test_hashcat_example_hash(self, algorithm, mode, expected):
        assert hash_candidate("hashcat", algorithm) == expected

    def test_candidate_is_not_trimmed(self):
        # A trailing space changes the digest; candidates are hashed as-is.
        assert hash_candidate("hashcat ", "md5") != hash_candidate("hashcat", "md5")

    def test_md4_differs_from_ntlm(self):
        # MD4 hashes UTF-8 bytes; NTLM hashes UTF-16LE encoding.
        assert hash_candidate("hashcat", "md4") != hash_candidate("hashcat", "ntlm")

    def test_lm_full_digest_is_two_des_blocks(self):
        assert hash_candidate("hashcat", "lm") == LM_FULL_HASHCAT

    def test_lm_empty_password_null_blocks(self):
        # An empty password produces the known null-block constant twice.
        assert hash_candidate("", "lm") == "aad3b435b51404ee" * 2

    def test_verify_candidate_accepts_hashcat_style_16hex_lm_target(self):
        assert verify_candidate("hashcat", "lm", "299bd128c1101fd6") is True

    def test_verify_candidate_16hex_target_matches_first_seven_chars(self):
        # A candidate sharing only the first seven characters matches the
        # 16-hex (first-block) target but not the full 32-hex digest.
        longer = "hashcat123"
        assert verify_candidate(longer, "lm", "299bd128c1101fd6") is True

    def test_digest_bytes_matches_hash_candidate_for_fast_formats(self):
        # The batch fast path (pre-encoded bytes) must agree with the
        # per-candidate path for every hashlib-backed algorithm.
        from hash_cracker.hashing import digest_bytes

        for algorithm, _, _ in HASHCAT_EXAMPLES:
            if algorithm in ("ntlm", "md4", "lm"):
                continue
            encoded = b"hashcat"
            assert digest_bytes(encoded, algorithm) == hash_candidate(
                "hashcat", algorithm
            )

    def test_digest_bytes_returns_none_for_non_hashlib_formats(self):
        from hash_cracker.hashing import digest_bytes

        assert digest_bytes(b"hashcat", "ntlm") is None
        assert digest_bytes(b"hashcat", "md4") is None
        assert digest_bytes(b"hashcat", "lm") is None
        assert digest_bytes(b"hashcat", "ripemd160") is None

    def test_verify_candidate_32hex_lm_target_is_exact(self):
        assert verify_candidate("hashcat", "lm", LM_FULL_HASHCAT) is True
        assert verify_candidate("hashcat123", "lm", LM_FULL_HASHCAT) is False

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_candidate("x", "rot13")


class TestSaltedFormats:
    # hashcat salted example hashes for plaintext "hashcat".
    HASHCAT_SALTED: ClassVar[list[tuple]] = [
        ("md5_pass_salt", 10, "343141", "3d83c8e717ff0e7ecfe187f088d69954"),
        ("md5_salt_pass", 20, "4247", "57ab8499d08c59a7211c77f557bf9425"),
        ("sha1_pass_salt", 110, "30007548152", "848952984db93bdd2d0151d4ecca6ea44fcf49e3"),
        ("sha1_salt_pass", 120, "465727565", "a428863972744b16afef28e0087fc094b44bb7b1"),
        ("sha256_pass_salt", 1410, "12480864321", "5bb7456f43e3610363f68ad6de82b8b96f3fc9ad24e9d1f1f8d8bd89638db7c0"),
        ("sha256_salt_pass", 1420, "36176620", "816d1ded1d621873595048912ea3405d9d42afd3b57665d9f5a2db4d89720854"),
        ("sha512_pass_salt", 1710, "388026522082", "3f749c84d00c6f94a6651b5c195c71dacae08f3cea6fed760232856cef701f7bf60d7f38a587f69f159d4e4cbe00435aeb9c8c0a4927b252d76a744e16e87e91"),
        ("sha512_salt_pass", 1720, "812", "efc5dd0e4145970917abdc311e1d4e23ba0afa9426d960cb28569f4d585cb031af5c936f57fbcb0a08368a1b302573cf582100d40bd7c632f3d8aecd1a1a8eb1"),
    ]

    @pytest.mark.parametrize(("algorithm", "mode", "salt", "expected"), HASHCAT_SALTED)
    def test_hashcat_salted_examples(self, algorithm, mode, salt, expected):
        assert hash_candidate("hashcat", algorithm, salt) == expected

    def test_salt_position_matters(self):
        with_salt_first = hash_candidate("hashcat", "md5_salt_pass", "1234")
        with_salt_last = hash_candidate("hashcat", "md5_pass_salt", "1234")
        assert with_salt_first != with_salt_last

    def test_wrong_salt_does_not_match(self):
        correct = hash_candidate("hashcat", "md5_pass_salt", "343141")
        assert hash_candidate("hashcat", "md5_pass_salt", "wrong") != correct

    def test_salted_requires_salt(self):
        with pytest.raises(ValueError, match="requires a salt"):
            hash_candidate("hashcat", "md5_pass_salt")

    def test_unsalted_rejects_salt(self):
        with pytest.raises(ValueError, match="does not take a salt"):
            hash_candidate("hashcat", "md5", "343141")


class TestPhase10Formats:
    def test_ripemd160_hashcat_example(self):
        # hashcat mode 600: RIPEMD-160 of "hashcat"
        assert hash_candidate("hashcat", "ripemd160") == "012cb9b334ec1aeb71a9c8ce85586082467f7eb6"

    def test_sha512_variants_match_hashlib(self):
        import hashlib

        for algorithm, digest_name in (("sha512_224", "sha512_224"), ("sha512_256", "sha512_256")):
            assert hash_candidate("hashcat", algorithm) == hashlib.new(
                digest_name, b"hashcat"
            ).hexdigest()

    def test_adaptive_bcrypt_verify(self):
        stored = "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
        assert verify_candidate("hashcat", "bcrypt", stored) is True
        assert verify_candidate("nope", "bcrypt", stored) is False

    def test_adaptive_phpass_verify(self):
        stored = "$P$946647711V1klyitUYhtB8Yw5DMA/w."
        assert verify_candidate("hashcat", "phpass", stored) is True
        assert verify_candidate("nope", "phpass", stored) is False

    def test_adaptive_sha512crypt_verify(self):
        stored = (
            "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzf"
            "REv8z6wVl0jRFX40/KnYVvK4829kD1"
        )
        # hashcat mode 1800 example (plaintext "hashcat")
        assert verify_candidate("hashcat", "sha512crypt", stored) is True
        assert verify_candidate("nope", "sha512crypt", stored) is False

    def test_adaptive_prefix_detection(self):
        from hash_cracker.algorithms import assess_hash

        stored = "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
        assessment = assess_hash(stored)
        assert assessment.compatible_algorithms == ("bcrypt",)
        assert assessment.normalized == stored

    def test_verify_candidate_fast_formats(self):
        assert verify_candidate("hashcat", "md5", "8743b52063cd84097a65d1633f5c74f5") is True
        assert verify_candidate("nope", "md5", "8743b52063cd84097a65d1633f5c74f5") is False
