"""In-memory stores: the fakes of the ports for the core and HTTP tests, with the semantics the
PostgreSQL adapter must keep: a key used once, a unique e-mail, newest first."""

from uuid import UUID

from identity.application.port.outbound.ports import DuplicateEmail, DuplicateStudentCode
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import User


class InMemoryUserStore:
    def __init__(self, users: list[User] | None = None) -> None:
        self._users: dict[UUID, User] = {u.id: u for u in users or []}
        self._keys: dict[str, UUID] = {}

    def find_by_key(self, idempotency_key: str) -> User | None:
        user_id = self._keys.get(idempotency_key)
        return self._users.get(user_id) if user_id else None

    def find_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if u.email == email), None)

    def find(self, user_id: UUID) -> User | None:
        return self._users.get(user_id)

    def create(self, user: User, idempotency_key: str) -> tuple[User, bool]:
        earlier = self.find_by_key(idempotency_key)
        if earlier is not None:
            return earlier, False
        if self.find_by_email(user.email) is not None:
            raise DuplicateEmail()
        if user.student_code and any(u.student_code == user.student_code for u in self._users.values()):
            raise DuplicateStudentCode()
        self._users[user.id] = user
        self._keys[idempotency_key] = user.id
        return user, True

    def page(self, role: str | None, q: str | None, page: int, limit: int) -> tuple[list[User], int]:
        rows = [
            u
            for u in self._users.values()
            if (role is None or u.role.value == role)
            and (q is None or u.name.lower().startswith(q) or u.email.startswith(q))
        ]
        rows.sort(key=lambda u: (u.created_at, str(u.id)), reverse=True)
        start = (page - 1) * limit
        return rows[start : start + limit], len(rows)


class InMemoryServiceTokenStore:
    def __init__(self) -> None:
        self._tokens: dict[UUID, ServiceToken] = {}
        self._keys: dict[str, UUID] = {}

    def find_by_key(self, idempotency_key: str) -> ServiceToken | None:
        token_id = self._keys.get(idempotency_key)
        return self._tokens.get(token_id) if token_id else None

    def create(self, token: ServiceToken, idempotency_key: str) -> tuple[ServiceToken, bool]:
        earlier = self.find_by_key(idempotency_key)
        if earlier is not None:
            return earlier, False
        self._tokens[token.id] = token
        self._keys[idempotency_key] = token.id
        return token, True
