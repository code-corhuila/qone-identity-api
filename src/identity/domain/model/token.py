"""The claims of every Qampus token (07-api/authentication.md §1): iss, sub, role, name, iat,
exp. User tokens live 8 hours; service tokens carry role SERVICE and the service name as sub.
Signing is a port: the domain decides the claims, an adapter signs them with the private key."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from identity.domain.model.user import User

ISSUER = "qone-identity-api"
USER_TOKEN_LIFETIME = timedelta(hours=8)


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    role: str
    name: str
    issued_at: datetime
    expires_at: datetime
    iss: str = ISSUER

    @staticmethod
    def for_user(user: User, now: datetime, lifetime: timedelta = USER_TOKEN_LIFETIME) -> "TokenClaims":
        moment = _utc(now)
        return TokenClaims(
            sub=str(user.id), role=user.role.value, name=user.name, issued_at=moment, expires_at=moment + lifetime
        )

    @staticmethod
    def for_service(service: str, now: datetime, ttl: timedelta) -> "TokenClaims":
        moment = _utc(now)
        return TokenClaims(sub=service, role="SERVICE", name=service, issued_at=moment, expires_at=moment + ttl)

    def as_dict(self) -> dict:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "role": self.role,
            "name": self.name,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
        }


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
