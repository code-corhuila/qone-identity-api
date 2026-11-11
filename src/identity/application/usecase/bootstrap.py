"""The ADMIN by bootstrap (code-corhuila/qone-docs#55): no seed and no repository carries the
administrator or its password. The service creates it at start, with a fixed id, from
BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD, hashed then. It is idempotent: an existing
account is kept and its password never overwritten. Outside develop both values are required,
and the password has at least 12 characters and is not the demo password; otherwise the
service refuses to start. A message names the variable, never its value."""

from typing import Literal
from uuid import UUID

from identity.application.port.outbound.ports import Clock, DuplicateEmail, UserStore
from identity.domain.model.errors import ValidationError
from identity.domain.model.user import User

ADMIN_ID = UUID("33333333-3333-4333-8333-333333333331")
DEVELOP_ADMIN_EMAIL = "admin@qampus.test"
STRICT_PASSWORD_MIN = 12
EMAIL_VARIABLE, PASSWORD_VARIABLE = "BOOTSTRAP_ADMIN_EMAIL", "BOOTSTRAP_ADMIN_PASSWORD"

Outcome = Literal["created", "kept", "skipped"]


class BootstrapRefused(Exception):
    """The configuration of the ADMIN is not acceptable: the service must not start."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class BootstrapAdmin:
    def __init__(self, users: UserStore, clock: Clock) -> None:
        self._users = users
        self._clock = clock

    def run(self, email: str, password: str, *, develop: bool, demo_password: str = "") -> Outcome:
        """`created`, `kept` (the account existed) or `skipped` (develop without a password)."""
        configured = check_configuration(email, password, develop=develop, demo_password=demo_password)
        if configured is None:
            return "skipped"
        email, password = configured
        if self._users.find(ADMIN_ID) is not None:
            return "kept"
        try:
            admin = User.administrator(ADMIN_ID, email, password, self._clock.now())
        except ValidationError as invalid:
            variables = {"email": EMAIL_VARIABLE, "password": PASSWORD_VARIABLE}
            named = ", ".join(f"{variables[d.field]} {d.message}" for d in invalid.details)
            raise BootstrapRefused(f"cannot bootstrap the ADMIN: {named}") from None
        try:
            return "created" if self._users.add(admin) else "kept"
        except DuplicateEmail:
            raise BootstrapRefused(f"cannot bootstrap the ADMIN: {EMAIL_VARIABLE} belongs to another account") from None


def check_configuration(email: str, password: str, *, develop: bool, demo_password: str = "") -> tuple[str, str] | None:
    """The e-mail and password to bootstrap with, None when develop has no password, or
    BootstrapRefused. Touches nothing: the service checks it before opening any connection."""
    email, password = (email or "").strip(), password or ""
    if develop:
        return (email or DEVELOP_ADMIN_EMAIL, password) if password else None
    _check_strict(email, password, demo_password)
    return email, password


def _check_strict(email: str, password: str, demo_password: str) -> None:
    if not email:
        raise BootstrapRefused(f"{EMAIL_VARIABLE} is required outside APP_ENV=develop")
    if not password:
        raise BootstrapRefused(f"{PASSWORD_VARIABLE} is required outside APP_ENV=develop")
    if len(password) < STRICT_PASSWORD_MIN:
        raise BootstrapRefused(
            f"{PASSWORD_VARIABLE} must have at least {STRICT_PASSWORD_MIN} characters outside APP_ENV=develop"
        )
    if demo_password and password == demo_password:
        raise BootstrapRefused(f"{PASSWORD_VARIABLE} must not be the DEMO_PASSWORD outside APP_ENV=develop")
