"""Typed errors of the identity domain. The domain raises these; it does not know HTTP. The
inbound HTTP adapter translates each one to a status code and the envelope in one place."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FieldError:
    field: str
    message: str


class DomainError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class ValidationError(DomainError):
    """The shape of the input is invalid: one entry per field."""

    details: list[FieldError] = field(default_factory=list)

    def __init__(self, details: list[FieldError]) -> None:
        super().__init__("the request has invalid fields")
        self.details = details


class BusinessRuleViolation(DomainError):
    """An invariant of the domain forbids the operation (a second account with the same e-mail)."""
