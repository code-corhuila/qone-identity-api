"""Service tokens (ID-07, 07-api/authentication.md §2): issued once per environment to
qone-workflow, qone-worker and qone-advisor-api. Only the SHA-256 of the JWT is kept; the value
is shown once. `sub` is the service name, never an app_user row."""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from identity.domain.model.errors import FieldError, ValidationError

SERVICES = ("qone-workflow", "qone-worker", "qone-advisor-api")
TTL_DEFAULT_HOURS, TTL_MIN_HOURS, TTL_MAX_HOURS = 720, 1, 8760


@dataclass(frozen=True)
class ServiceToken:
    id: UUID
    service: str
    token_hash: str
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime

    @staticmethod
    def issue(token_id: UUID, service: str, ttl_hours: int, token: str, now: datetime) -> "ServiceToken":
        details: list[FieldError] = []
        if service not in SERVICES:
            details.append(FieldError("service", f"must be one of {', '.join(SERVICES)}"))
        if (
            isinstance(ttl_hours, bool)
            or not isinstance(ttl_hours, int)
            or not TTL_MIN_HOURS <= ttl_hours <= TTL_MAX_HOURS
        ):
            details.append(FieldError("ttlHours", f"must be an integer between {TTL_MIN_HOURS} and {TTL_MAX_HOURS}"))
        if details:
            raise ValidationError(details)
        moment = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        return ServiceToken(
            id=token_id,
            service=service,
            token_hash=digest_of(token),
            expires_at=moment + timedelta(hours=ttl_hours),
            revoked_at=None,
            created_at=moment,
        )


def digest_of(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
