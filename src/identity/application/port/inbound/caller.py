"""Who calls a use case: the subject and the role of a validated token. SERVICE is a token
role only (07-api/authentication.md); `subject` is a user id or a service name."""

from dataclasses import dataclass
from enum import StrEnum


class TokenRole(StrEnum):
    STUDENT = "STUDENT"
    PROFESSOR = "PROFESSOR"
    ADMIN = "ADMIN"
    SERVICE = "SERVICE"


@dataclass(frozen=True)
class Caller:
    subject: str
    role: TokenRole
    name: str = ""
