"""What the identity service needs (Annex C, outbound ports): the stores, the signer that holds
the private key, a clock and an id generator."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from identity.domain.model.idempotency import IdempotencyKey
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.token import TokenClaims
from identity.domain.model.user import User


class DuplicateEmail(Exception):
    """The unique index on the e-mail fired under a race the use case's own check did not see."""


class DuplicateStudentCode(Exception):
    """The unique index on the student code fired: another account carries that code."""


@dataclass(frozen=True)
class Claimed[R]:
    """What an owner's Idempotency-Key points to: the resource its first request created and the
    fingerprint of that request (code-corhuila/qone-docs#55)."""

    resource: R
    fingerprint: str


class UserStore(Protocol):
    def find_by_key(self, owner: str, key: str) -> Claimed[User] | None: ...

    def find_by_email(self, email: str) -> User | None: ...

    def find(self, user_id: UUID) -> User | None: ...

    def create(self, user: User, key: IdempotencyKey) -> tuple[Claimed[User], bool]:
        """Stores the user and its key (owner, key, fingerprint) in ONE transaction. Returns
        (the user, True), or (what the owner's key claimed first, False) when the key was taken.
        Raises DuplicateEmail or DuplicateStudentCode."""

    def page(self, role: str | None, q: str | None, page: int, limit: int) -> tuple[list[User], int]:
        """Newest first, one page, and the total count."""


class ServiceTokenStore(Protocol):
    def find_by_key(self, owner: str, key: str) -> Claimed[ServiceToken] | None: ...

    def create(self, token: ServiceToken, key: IdempotencyKey) -> tuple[Claimed[ServiceToken], bool]: ...


class TokenSigner(Protocol):
    def sign(self, claims: TokenClaims) -> str:
        """The compact RS256 JWT of the claims; the adapter alone holds the private key."""


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new_id(self) -> UUID: ...


class DependencyProbe(Protocol):
    """A dependency the service needs to take traffic (HU-PLT-004): `ping` returns when it answers
    within the adapter's short timeout and raises otherwise."""

    name: str

    def ping(self) -> None: ...
