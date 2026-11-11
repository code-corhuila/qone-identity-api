"""In-memory stores: the fakes of the ports for the core and HTTP tests, with the semantics the
PostgreSQL adapter must keep: a key used once per owner with the fingerprint of its request, a
unique e-mail, newest first."""

from uuid import UUID

from identity.application.port.outbound.ports import Claimed, DuplicateEmail, DuplicateStudentCode
from identity.domain.model.idempotency import IdempotencyKey
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import User


class InMemoryUserStore:
    def __init__(self, users: list[User] | None = None) -> None:
        self._users: dict[UUID, User] = {u.id: u for u in users or []}
        self._keys: dict[tuple[str, str], tuple[UUID, str]] = {}

    def find_by_key(self, owner: str, key: str) -> Claimed[User] | None:
        return _claimed(self._keys, self._users, owner, key)

    def find_by_email(self, email: str) -> User | None:
        return next((u for u in self._users.values() if u.email == email), None)

    def find(self, user_id: UUID) -> User | None:
        return self._users.get(user_id)

    def create(self, user: User, key: IdempotencyKey) -> tuple[Claimed[User], bool]:
        earlier = _claimed(self._keys, self._users, key.owner, key.key)
        if earlier is not None:
            return earlier, False
        if self.find_by_email(user.email) is not None:
            raise DuplicateEmail()
        if user.student_code and any(u.student_code == user.student_code for u in self._users.values()):
            raise DuplicateStudentCode()
        self._users[user.id] = user
        self._keys[(key.owner, key.key)] = (user.id, key.fingerprint)
        return Claimed(user, key.fingerprint), True

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
        self._keys: dict[tuple[str, str], tuple[UUID, str]] = {}

    def find_by_key(self, owner: str, key: str) -> Claimed[ServiceToken] | None:
        return _claimed(self._keys, self._tokens, owner, key)

    def create(self, token: ServiceToken, key: IdempotencyKey) -> tuple[Claimed[ServiceToken], bool]:
        earlier = _claimed(self._keys, self._tokens, key.owner, key.key)
        if earlier is not None:
            return earlier, False
        self._tokens[token.id] = token
        self._keys[(key.owner, key.key)] = (token.id, key.fingerprint)
        return Claimed(token, key.fingerprint), True


def _claimed[R](
    keys: dict[tuple[str, str], tuple[UUID, str]], rows: dict[UUID, R], owner: str, key: str
) -> Claimed[R] | None:
    entry = keys.get((owner, key))
    return Claimed(rows[entry[0]], entry[1]) if entry else None


class InMemoryProbe:
    """The ready probe of a service without a database: the in-memory store is always there."""

    name = "database"

    def ping(self) -> None:
        return None
