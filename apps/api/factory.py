"""The composition root (Annex C): the only module that knows every concrete type and every
limit. The private key reaches this service alone (JWT_PRIVATE_KEY_FILE, norm 5.9.2).

APP_ENV decides how strict the start is (code-corhuila/qone-docs#55): the in-memory runtime and
its demo people exist only in `develop`; the ADMIN is bootstrapped from BOOTSTRAP_ADMIN_EMAIL and
BOOTSTRAP_ADMIN_PASSWORD, and outside develop a bad value stops the service before it opens
anything, with a log line that names the variable and never its value."""

import json
import logging
import os
import sys
from datetime import UTC, datetime, timedelta

from identity.adapter.inbound.http.app import create_app
from identity.adapter.inbound.http.auth import TokenVerifier
from identity.adapter.outbound.jwt.rs256 import Rs256Signer
from identity.adapter.outbound.persistence.memory import InMemoryProbe, InMemoryServiceTokenStore, InMemoryUserStore
from identity.adapter.outbound.runtime import SystemClock, Uuid4Generator
from identity.application.usecase.bootstrap import BootstrapAdmin, BootstrapRefused, check_configuration
from identity.application.usecase.identity import IdentityService
from identity.application.usecase.readiness import CheckReadiness

# Explicit limits (norm 5.3.10, Annex C), declared here with their values.
DB_POOL_MAX = 10
DB_WAIT_SECONDS = 5.0
DB_STATEMENT_TIMEOUT_MS = 5000
HTTP_KEEP_ALIVE_SECONDS = 60
HTTP_GRACEFUL_SHUTDOWN_SECONDS = 20
READY_TIMEOUT_SECONDS = 2.0  # deadline of the ready probe (connection and SELECT 1)
DEVELOP = "develop"


class Settings:
    def __init__(self, env: dict[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        self.database_url = env.get("IDENTITY_DATABASE_URL", "").strip()
        self.private_key = _private_key(env)
        self.token_lifetime = timedelta(hours=int(env.get("TOKEN_LIFETIME_HOURS", "8")))
        self.demo_password = env.get("DEMO_PASSWORD", "").strip()
        self.app_env = env.get("APP_ENV", "").strip().lower()
        self.admin_email = env.get("BOOTSTRAP_ADMIN_EMAIL", "").strip()
        self.admin_password = env.get("BOOTSTRAP_ADMIN_PASSWORD", "")
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
    develop = settings.app_env == DEVELOP
    in_memory = not settings.database_url or settings.database_url == "memory"
    if in_memory and not develop:
        _refuse(log, "the in-memory store (no IDENTITY_DATABASE_URL) is allowed only with APP_ENV=develop")
    if not develop:  # the configuration of the ADMIN is checked before any connection is opened
        try:
            check_configuration(
                settings.admin_email, settings.admin_password, develop=False, demo_password=settings.demo_password
            )
        except BootstrapRefused as refused:
            _refuse(log, refused.message)
    if not in_memory:
        from identity.adapter.outbound.persistence.postgres import (
            PostgresProbe,
            PostgresServiceTokenStore,
            PostgresUserStore,
            connect,
        )

        pool = connect(settings.database_url, DB_POOL_MAX, DB_WAIT_SECONDS, DB_STATEMENT_TIMEOUT_MS)
        users, tokens = PostgresUserStore(pool), PostgresServiceTokenStore(pool)
        probe = PostgresProbe(pool, READY_TIMEOUT_SECONDS)
        log.info("store: postgresql (pool max %s, statement timeout %s ms)", DB_POOL_MAX, DB_STATEMENT_TIMEOUT_MS)
    else:
        if not settings.demo_password:
            raise SystemExit("DEMO_PASSWORD is required with the in-memory store (development only)")
        users, tokens = InMemoryUserStore(_demo_people(settings.demo_password)), InMemoryServiceTokenStore()
        probe = InMemoryProbe()
        log.warning("store: in memory with the demo people (IDENTITY_DATABASE_URL not set); development only")
    _bootstrap(log, BootstrapAdmin(users, SystemClock()), settings, develop)
    service = IdentityService(users, tokens, signer, SystemClock(), Uuid4Generator(), settings.token_lifetime)
    return create_app(service, TokenVerifier(signer.public_key_pem()), CheckReadiness([probe]))


def _refuse(log: logging.Logger, reason: str) -> None:
    log.error("refusing to start: %s", reason)
    raise SystemExit(f"qone-identity-api refuses to start: {reason}")


def _bootstrap(log: logging.Logger, bootstrap: BootstrapAdmin, settings: Settings, develop: bool) -> None:
    try:
        outcome = bootstrap.run(
            settings.admin_email, settings.admin_password, develop=develop, demo_password=settings.demo_password
        )
    except BootstrapRefused as refused:
        _refuse(log, refused.message)
    if outcome == "skipped":
        log.warning("no ADMIN bootstrapped: BOOTSTRAP_ADMIN_PASSWORD is empty (develop)")
    else:
        log.info("ADMIN bootstrap: %s", outcome)


def _demo_people(password: str):
    """The develop seed of qone-identity-db (synthetic identities, no ADMIN: the ADMIN comes from
    the bootstrap), for a service started without a database in develop."""
    from uuid import UUID

    from identity.domain.model.credentials import hash_password
    from identity.domain.model.user import Role, User

    digest, created = hash_password(password), datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    program = "Ingeniería de Software"
    rows = [
        (
            "11111111-1111-4111-8111-111111111111",
            "estudiante.01@qampus.test",
            "Estudiante Demo 01",
            Role.STUDENT,
            "2099000001",
            6,
        ),
        (
            "11111111-1111-4111-8111-111111111112",
            "estudiante.02@qampus.test",
            "Estudiante Demo 02",
            Role.STUDENT,
            "2099000002",
            5,
        ),
        (
            "11111111-1111-4111-8111-111111111113",
            "estudiante.03@qampus.test",
            "Estudiante Demo 03",
            Role.STUDENT,
            "2099000003",
            6,
        ),
        (
            "11111111-1111-4111-8111-111111111114",
            "estudiante.04@qampus.test",
            "Estudiante Demo 04",
            Role.STUDENT,
            "2099000004",
            7,
        ),
        (
            "11111111-1111-4111-8111-111111111115",
            "estudiante.05@qampus.test",
            "Estudiante Demo 05",
            Role.STUDENT,
            "2099000005",
            7,
        ),
        (
            "22222222-2222-4222-8222-222222222221",
            "profesor.01@qampus.test",
            "Profesor Demo 01",
            Role.PROFESSOR,
            None,
            None,
        ),
        (
            "22222222-2222-4222-8222-222222222222",
            "profesor.02@qampus.test",
            "Profesor Demo 02",
            Role.PROFESSOR,
            None,
            None,
        ),
        (
            "22222222-2222-4222-8222-222222222223",
            "profesor.03@qampus.test",
            "Profesor Demo 03",
            Role.PROFESSOR,
            None,
            None,
        ),
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
