"""The User aggregate (06-data/models.md schema identity, contract RegisterRequest).

Pure Python (Annex C). Self-registration creates students only; professors and admins are
seeded or created by an ADMIN. The e-mail is the login identity, stored lower-case and unique
(the use case checks it, the database's unique index is the last line). The password is
hashed at registration and never leaves the aggregate as text."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from identity.domain.model.credentials import PASSWORD_MAX, PASSWORD_MIN, hash_password, verify_password
from identity.domain.model.errors import FieldError, ValidationError

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
STUDENT_CODE_PATTERN = re.compile(r"^[0-9]{6,20}$")


class Role(StrEnum):
    """Roles a person can have. SERVICE exists only in tokens (07-api/authentication.md)."""

    STUDENT = "STUDENT"
    PROFESSOR = "PROFESSOR"
    ADMIN = "ADMIN"


@dataclass(frozen=True)
class User:
    id: UUID
    email: str
    name: str
    password_hash: str
    role: Role
    student_code: str | None
    program: str | None
    semester: int | None
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def register(
        user_id: UUID,
        name: str,
        email: str,
        password: str,
        student_code: str,
        program: str,
        semester: int,
        now: datetime,
    ) -> "User":
        """A new STUDENT, or ValidationError naming every invalid field at once."""
        details: list[FieldError] = []
        clean_name = name.strip() if isinstance(name, str) else ""
        if not 2 <= len(clean_name) <= 120:
            details.append(FieldError("name", "must have 2 to 120 characters"))
        clean_email = email.strip().lower() if isinstance(email, str) else ""
        if not clean_email or len(clean_email) > 120 or not EMAIL_PATTERN.match(clean_email):
            details.append(FieldError("email", "must be a valid e-mail of at most 120 characters"))
        if not isinstance(password, str) or not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
            details.append(FieldError("password", f"must have {PASSWORD_MIN} to {PASSWORD_MAX} characters"))
        clean_code = student_code.strip() if isinstance(student_code, str) else ""
        if not STUDENT_CODE_PATTERN.match(clean_code):
            details.append(FieldError("studentCode", "must match ^[0-9]{6,20}$"))
        clean_program = program.strip() if isinstance(program, str) else ""
        if not 2 <= len(clean_program) <= 80:
            details.append(FieldError("program", "must have 2 to 80 characters"))
        if isinstance(semester, bool) or not isinstance(semester, int) or not 1 <= semester <= 12:
            details.append(FieldError("semester", "must be an integer between 1 and 12"))
        if details:
            raise ValidationError(details)
        moment = _utc(now)
        return User(
            id=user_id,
            email=clean_email,
            name=clean_name,
            password_hash=hash_password(password),
            role=Role.STUDENT,
            student_code=clean_code,
            program=clean_program,
            semester=semester,
            created_at=moment,
            updated_at=moment,
        )

    def password_matches(self, password: str) -> bool:
        return verify_password(password, self.password_hash)


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
