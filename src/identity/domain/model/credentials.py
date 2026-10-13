"""Passwords (07-api/authentication.md §1): PBKDF2-HMAC-SHA256, 200,000 iterations, a 16-byte
random salt, stored as `salt$hex` and compared in constant time. Standard library only; the
same format qone-identity-db's scripts/hash-password.py produces for the seed."""

import hashlib
import hmac
import secrets

ITERATIONS = 200_000
SALT_BYTES = 16
PASSWORD_MIN, PASSWORD_MAX = 8, 128


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """True when the password matches; the comparison takes the same time either way."""
    salt, _, digest = stored.partition("$")
    if not salt or not digest:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS).hex()
    return hmac.compare_digest(candidate, digest)
