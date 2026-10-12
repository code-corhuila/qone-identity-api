"""The composition root (Annex C): the only module that knows every concrete type and every
limit. The private key reaches this service alone (JWT_PRIVATE_KEY_FILE, norm 5.9.2)."""

import json
import logging
import os
import sys
from datetime import UTC, datetime, timedelta

from identity.adapter.inbound.http.app import create_app
from identity.adapter.inbound.http.auth import TokenVerifier
from identity.adapter.outbound.jwt.rs256 import Rs256Signer
from identity.adapter.outbound.persistence.memory import InMemoryServiceTokenStore, InMemoryUserStore
from identity.adapter.outbound.runtime import SystemClock, Uuid4Generator
from identity.application.usecase.identity import IdentityService

# Explicit limits (norm 5.3.10, Annex C), declared here with their values.
DB_POOL_MAX = 10
DB_WAIT_SECONDS = 5.0
DB_STATEMENT_TIMEOUT_MS = 5000
HTTP_KEEP_ALIVE_SECONDS = 60
HTTP_GRACEFUL_SHUTDOWN_SECONDS = 20


class Settings:
    def __init__(self, env: dict[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        self.database_url = env.get("IDENTITY_DATABASE_URL", "").strip()
        self.private_key = _private_key(env)
        self.token_lifetime = timedelta(hours=int(env.get("TOKEN_LIFETIME_HOURS", "8")))
        self.demo_password = env.get("DEMO_PASSWORD", "").strip()
        self.port = int(env.get("PORT", "8000"))
        self.log_level = env.get("LOG_LEVEL", "info").lower()


def _private_key(env: dict[str, str]) -> str:
    path = env.get("JWT_PRIVATE_KEY_FILE", "").strip()
    if not path:
        raise SystemExit("JWT_PRIVATE_KEY_FILE is required: identity is the only piece that signs tokens")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def build_app(settings: Settings | None = None):
    settings = settings or Settings()
    configure_logging(settings.log_level)
    log = logging.getLogger("identity")
    signer = Rs256Signer(settings.private_key)
    if settings.database_url and settings.database_url != "memory":
        from identity.adapter.outbound.persistence.postgres import PostgresServiceTokenStore, PostgresUserStore, connect

        pool = connect(settings.database_url, DB_POOL_MAX, DB_WAIT_SECONDS, DB_STATEMENT_TIMEOUT_MS)
        users, tokens = PostgresUserStore(pool), PostgresServiceTokenStore(pool)
        log.info("store: postgresql (pool max %s, statement timeout %s ms)", DB_POOL_MAX, DB_STATEMENT_TIMEOUT_MS)
    else:
        if not settings.demo_password:
            raise SystemExit("DEMO_PASSWORD is required with the in-memory store (development only)")
        users, tokens = InMemoryUserStore(_demo_people(settings.demo_password)), InMemoryServiceTokenStore()
        log.warning("store: in memory with the demo people (IDENTITY_DATABASE_URL not set); development only")
    service = IdentityService(users, tokens, signer, SystemClock(), Uuid4Generator(), settings.token_lifetime)
    return create_app(service, TokenVerifier(signer.public_key_pem()))


def _demo_people(password: str):
    """The seed of qone-identity-db, for a service started without a database."""
    from uuid import UUID

    from identity.domain.model.credentials import hash_password
    from identity.domain.model.user import Role, User

    digest, created = hash_password(password), datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    program = "Ingeniería de Software"
    rows = [
        ("11111111-1111-4111-8111-111111111111", "laura.gomez@uni.edu.co", "Laura Gómez", Role.STUDENT, "202110342", 6),
        (
            "11111111-1111-4111-8111-111111111112",
            "santiago.rojas@uni.edu.co",
            "Santiago Rojas",
            Role.STUDENT,
            "202201983",
            5,
        ),
        (
            "11111111-1111-4111-8111-111111111113",
            "maria.cabrera@uni.edu.co",
            "María José Cabrera",
            Role.STUDENT,
            "202111205",
            6,
        ),
        (
            "11111111-1111-4111-8111-111111111114",
            "andres.pineda@uni.edu.co",
            "Andrés Pineda",
            Role.STUDENT,
            "202008761",
            7,
        ),
        (
            "11111111-1111-4111-8111-111111111115",
            "valentina.suarez@uni.edu.co",
            "Valentina Suárez",
            Role.STUDENT,
            "202009114",
            7,
        ),
        (
            "22222222-2222-4222-8222-222222222221",
            "carlos.ramirez@uni.edu.co",
            "Carlos Ramírez",
            Role.PROFESSOR,
            None,
            None,
        ),
        ("22222222-2222-4222-8222-222222222222", "ana.torres@uni.edu.co", "Ana Torres", Role.PROFESSOR, None, None),
        ("22222222-2222-4222-8222-222222222223", "jorge.medina@uni.edu.co", "Jorge Medina", Role.PROFESSOR, None, None),
        ("33333333-3333-4333-8333-333333333331", "admin@uni.edu.co", "Patricia Mora", Role.ADMIN, None, None),
    ]
    return [
        User(UUID(i), e, n, digest, r, c, program if r is Role.STUDENT else None, s, created, created)
        for i, e, n, r, c, s in rows
    ]


class JsonFormatter(logging.Formatter):
    """One JSON line per record with the traceId (norm 5.3.9)."""

    def format(self, record: logging.LogRecord) -> str:
        line = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("traceId", "method", "path", "status", "durationMs"):
            if hasattr(record, key):
                line[key] = getattr(record, key)
        if record.exc_info:
            line["exception"] = self.formatException(record.exc_info)
        return json.dumps(line, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").disabled = True
