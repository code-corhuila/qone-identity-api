"""Core level: the password format and the constant-time check."""

import secrets

from identity.domain.model.credentials import ITERATIONS, hash_password, verify_password

PASSWORD = "x" + secrets.token_urlsafe(16)  # generated per session; the letter keeps swapcase() different


def test_the_hash_is_salt_and_hex_and_differs_per_salt():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    salt, _, digest = first.partition("$")
    assert len(salt) == 32 and len(digest) == 64
    assert first != second, "a fresh 16-byte salt per user"


def test_verify_accepts_the_password_and_rejects_others():
    stored = hash_password(PASSWORD)
    assert verify_password(PASSWORD, stored)
    assert not verify_password(PASSWORD.swapcase(), stored)
    assert not verify_password(PASSWORD, "not-a-hash")


def test_the_seed_format_of_qone_identity_db_is_the_same():
    stored = hash_password("rebuild-check", salt="0" * 32)
    assert verify_password("rebuild-check", stored) and ITERATIONS == 200_000
