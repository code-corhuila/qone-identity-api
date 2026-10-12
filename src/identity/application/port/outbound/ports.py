"""What the identity service needs (Annex C, outbound ports): the stores, the signer that holds
the private key, a clock and an id generator."""

from datetime import datetime
from typing import Protocol
from uuid import UUID

from identity.domain.model.service_token import ServiceToken
from identity.domain.model.token import TokenClaims
from identity.domain.model.user import User


class DuplicateEmail(Exception):
    """The unique index on the e-mail fired under a race the use case's own check did not see."""


class UserStore(Protocol):
    def find_by_key(self, idempotency_key: str) -> User | None: ...

    def find_by_email(self, email: str) -> User | None: ...

    def find(self, user_id: UUID) -> User | None: ...

    def create(self, user: User, idempotency_key: str) -> tuple[User, bool]:
        """Stores the user and its key in ONE transaction. Returns (user, True), or (the user the
        key created first, False) when the key was taken. Raises DuplicateEmail."""

    def page(self, role: str | None, q: str | None, page: int, limit: int) -> tuple[list[User], int]:
        """Newest first, one page, and the total count."""


class ServiceTokenStore(Protocol):
    def find_by_key(self, idempotency_key: str) -> ServiceToken | None: ...

    def create(self, token: ServiceToken, idempotency_key: str) -> tuple[ServiceToken, bool]: ...


class TokenSigner(Protocol):
    def sign(self, claims: TokenClaims) -> str:
        """The compact RS256 JWT of the claims; the adapter alone holds the private key."""


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdGenerator(Protocol):
    def new_id(self) -> UUID: ...
