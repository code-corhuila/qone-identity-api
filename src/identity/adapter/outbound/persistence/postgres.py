"""The stores over PostgreSQL (schema `identity` of qone-identity-db) with psycopg 3 and a pool
(Annex C limits). Idempotent creation (norm 5.3.8): the row and its key go in ONE transaction;
a used key rolls back and returns the row the key created first; the unique index on the
e-mail surfaces as DuplicateEmail."""

from datetime import UTC
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from identity.application.port.outbound.ports import DuplicateEmail, DuplicateStudentCode
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import Role, User

USER_COLUMNS = "id, email, name, password_hash, role, student_code, program, semester, created_at, updated_at"
TOKEN_COLUMNS = "id, service, token_hash, expires_at, revoked_at, created_at"


def connect(
    url: str, max_size: int = 10, wait_seconds: float = 5.0, statement_timeout_ms: int = 5000
) -> ConnectionPool:
    return ConnectionPool(
        conninfo=url,
        min_size=1,
        max_size=max_size,
        timeout=wait_seconds,
        kwargs={"options": f"-c statement_timeout={statement_timeout_ms}", "row_factory": dict_row},
        open=True,
    )


class _KeyAlreadyUsed(Exception):
    """Raised inside the transaction to roll it back when the Idempotency-Key existed."""


def _claim_key(conn: psycopg.Connection, key: str, resource_type: str, resource_id: UUID) -> None:
    taken = conn.execute(
        "INSERT INTO identity.idempotency_key (key, resource_type, resource_id) VALUES (%s, %s, %s) "
        "ON CONFLICT (key) DO NOTHING RETURNING key",
        (key, resource_type, resource_id),
    ).fetchone()
    if taken is None:
        raise _KeyAlreadyUsed()


class PostgresUserStore:
    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def find_by_key(self, idempotency_key: str) -> User | None:
        return self._one(
            f"SELECT {USER_COLUMNS} FROM identity.app_user WHERE id = "
            "(SELECT resource_id FROM identity.idempotency_key WHERE key = %s AND resource_type = 'app_user')",
            (idempotency_key,),
        )

    def find_by_email(self, email: str) -> User | None:
        return self._one(f"SELECT {USER_COLUMNS} FROM identity.app_user WHERE email = %s", (email,))

    def find(self, user_id: UUID) -> User | None:
        return self._one(f"SELECT {USER_COLUMNS} FROM identity.app_user WHERE id = %s", (user_id,))

    def create(self, user: User, idempotency_key: str) -> tuple[User, bool]:
        try:
            with self._pool.connection() as conn, conn.transaction():
                try:
                    conn.execute(
                        f"INSERT INTO identity.app_user ({USER_COLUMNS}) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            user.id,
                            user.email,
                            user.name,
                            user.password_hash,
                            user.role.value,
                            user.student_code,
                            user.program,
                            user.semester,
                            user.created_at,
                            user.updated_at,
                        ),
                    )
                except psycopg.errors.UniqueViolation as cause:
                    if cause.diag.constraint_name == "ux_app_user_student_code":
                        raise DuplicateStudentCode() from cause
                    raise DuplicateEmail() from cause
                _claim_key(conn, idempotency_key, "app_user", user.id)
        except _KeyAlreadyUsed:
            earlier = self.find_by_key(idempotency_key)
            assert earlier is not None
            return earlier, False
        return user, True

    def page(self, role: str | None, q: str | None, page: int, limit: int) -> tuple[list[User], int]:
        clauses, params = ["TRUE"], []
        if role:
            clauses.append("role = %s")
            params.append(role)
        if q:
            clauses.append("(lower(name) LIKE %s OR email LIKE %s)")
            pattern = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params.extend([pattern, pattern])
        where = " AND ".join(clauses)
        with self._pool.connection() as conn:
            total = conn.execute(f"SELECT count(*) AS n FROM identity.app_user WHERE {where}", params).fetchone()["n"]
            rows = conn.execute(
                f"SELECT {USER_COLUMNS} FROM identity.app_user WHERE {where} "
                "ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
                (*params, limit, (page - 1) * limit),
            ).fetchall()
        return [_user(r) for r in rows], int(total)

    def _one(self, sql: str, params: tuple) -> User | None:
        with self._pool.connection() as conn:
            row = conn.execute(sql, params).fetchone()
        return _user(row) if row else None


class PostgresServiceTokenStore:
    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def find_by_key(self, idempotency_key: str) -> ServiceToken | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                f"SELECT {TOKEN_COLUMNS} FROM identity.service_token WHERE id = "
                "(SELECT resource_id FROM identity.idempotency_key WHERE key = %s AND resource_type = 'service_token')",
                (idempotency_key,),
            ).fetchone()
        return _token(row) if row else None

    def create(self, token: ServiceToken, idempotency_key: str) -> tuple[ServiceToken, bool]:
        try:
            with self._pool.connection() as conn, conn.transaction():
                conn.execute(
                    f"INSERT INTO identity.service_token ({TOKEN_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s)",
                    (token.id, token.service, token.token_hash, token.expires_at, token.revoked_at, token.created_at),
                )
                _claim_key(conn, idempotency_key, "service_token", token.id)
        except _KeyAlreadyUsed:
            earlier = self.find_by_key(idempotency_key)
            assert earlier is not None
            return earlier, False
        return token, True


def _user(row: dict) -> User:
    return User(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        password_hash=row["password_hash"],
        role=Role(row["role"]),
        student_code=row["student_code"],
        program=row["program"],
        semester=row["semester"],
        created_at=row["created_at"].astimezone(UTC),
        updated_at=row["updated_at"].astimezone(UTC),
    )


def _token(row: dict) -> ServiceToken:
    return ServiceToken(
        id=row["id"],
        service=row["service"],
        token_hash=row["token_hash"],
        expires_at=row["expires_at"].astimezone(UTC),
        revoked_at=row["revoked_at"].astimezone(UTC) if row["revoked_at"] else None,
        created_at=row["created_at"].astimezone(UTC),
    )
