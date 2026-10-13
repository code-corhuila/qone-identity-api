"""Fakes of the trivial ports and the seed people for the core and HTTP tests."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from identity.domain.model.credentials import hash_password
from identity.domain.model.token import TokenClaims
from identity.domain.model.user import Role, User

DEMO_PASSWORD = "Qampus2026!"
DEMO_HASH = hash_password(DEMO_PASSWORD)  # once per test session: PBKDF2 is deliberately slow
CREATED_AT = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


def person(
    user_id: str, email: str, name: str, role: Role, code: str | None = None, semester: int | None = None
) -> User:
    program = "Ingeniería de Software" if role is Role.STUDENT else None
    return User(UUID(user_id), email, name, DEMO_HASH, role, code, program, semester, CREATED_AT, CREATED_AT)


LAURA = person(
    "11111111-1111-4111-8111-111111111111", "laura.gomez@uni.edu.co", "Laura Gómez", Role.STUDENT, "202110342", 6
)
SANTIAGO = person(
    "11111111-1111-4111-8111-111111111112", "santiago.rojas@uni.edu.co", "Santiago Rojas", Role.STUDENT, "202201983", 5
)
CARLOS = person("22222222-2222-4222-8222-222222222221", "carlos.ramirez@uni.edu.co", "Carlos Ramírez", Role.PROFESSOR)
PATRICIA = person("33333333-3333-4333-8333-333333333331", "admin@uni.edu.co", "Patricia Mora", Role.ADMIN)
SEED = [LAURA, SANTIAGO, CARLOS, PATRICIA]


class FixedClock:
    def __init__(self, start: datetime = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)) -> None:
        self.current = start

    def now(self) -> datetime:
        return self.current

    def tick(self, **delta) -> datetime:
        self.current = self.current + timedelta(**delta)
        return self.current


class SequenceIds:
    def __init__(self, start: int = 1) -> None:
        self.next = start

    def new_id(self) -> UUID:
        value = UUID(f"99999999-9999-4999-8999-9999999999{self.next:02d}")
        self.next += 1
        return value


class FakeSigner:
    """A readable stand-in for the RS256 signer: the claims as JSON after a marker."""

    def __init__(self) -> None:
        self.signed: list[TokenClaims] = []

    def sign(self, claims: TokenClaims) -> str:
        self.signed.append(claims)
        return "signed:" + json.dumps(claims.as_dict(), ensure_ascii=False)
