"""What the identity service offers (Annex C, inbound ports): ID-02..ID-07 as commands,
queries, results and the use-case interface the HTTP adapter depends on."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from identity.application.port.inbound.caller import Caller
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import User

DEFAULT_LIMIT = 20
MAX_LIMIT = 100


@dataclass(frozen=True)
class Register:
    name: str
    email: str
    password: str
    student_code: str
    program: str
    semester: int = 1


@dataclass(frozen=True)
class Login:
    email: str
    password: str


@dataclass(frozen=True)
class IssueServiceToken:
    service: str
    ttl_hours: int = 720


@dataclass(frozen=True)
class Authenticated:
    user: User
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class Registered:
    auth: Authenticated
    created: bool
    """False when the Idempotency-Key had been used: the account is the one created first."""


@dataclass(frozen=True)
class IssuedServiceToken:
    service_token: ServiceToken
    token: str | None
    """The JWT, present only when this call created it; a replay returns metadata only."""
    created: bool


@dataclass(frozen=True)
class Page:
    items: list[User]
    page: int
    limit: int
    total: int

    @property
    def total_pages(self) -> int:
        return -(-self.total // self.limit) if self.total else 0


class IdentityUseCases(Protocol):
    def register(self, command: Register, idempotency_key: str) -> Registered:
        """ID-02, public. Students only; a used e-mail is a BusinessRuleViolation; replay by key."""

    def login(self, command: Login) -> Authenticated:
        """ID-03, public. AuthenticationFailed for an unknown e-mail or a wrong password alike."""

    def me(self, caller: Caller) -> User:
        """ID-04, any person."""

    def users(self, caller: Caller, role: str | None, q: str | None, page: int, limit: int) -> Page:
        """ID-05, ADMIN. Newest first; `role` filters; `q` is a case-insensitive prefix of name or e-mail."""

    def get_user(self, caller: Caller, user_id: UUID) -> User:
        """ID-06, ADMIN or SERVICE."""

    def issue_service_token(
        self, caller: Caller, command: IssueServiceToken, idempotency_key: str
    ) -> IssuedServiceToken:
        """ID-07, ADMIN. The token value is returned once; a replay returns the metadata."""
