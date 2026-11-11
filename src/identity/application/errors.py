"""Errors of the application layer; the HTTP adapter translates them (401, 403, 404, 422, 503) in
one place. The use cases never mention a status code."""


class AuthenticationFailed(Exception):
    """Wrong e-mail or wrong password: the same neutral message for both (ID-03)."""

    def __init__(self, message: str = "invalid e-mail or password") -> None:
        super().__init__(message)
        self.message = message


class Forbidden(Exception):
    def __init__(self, message: str = "this role may not perform the operation") -> None:
        super().__init__(message)
        self.message = message


class NotFound(Exception):
    def __init__(self, message: str = "resource not found") -> None:
        super().__init__(message)
        self.message = message


class IdempotencyKeyReused(Exception):
    """The caller's Idempotency-Key already stands for another request, or (registration) the
    password does not prove the account the key created: nothing is created or returned (422)."""

    def __init__(self, message: str = "this Idempotency-Key was already used for another request") -> None:
        super().__init__(message)
        self.message = message


class DependencyUnavailable(Exception):
    """A dependency the service needs (the database) did not answer: alive, but not ready (503)."""

    def __init__(self, dependency: str) -> None:
        self.dependency = dependency
        self.message = f"{dependency} is not reachable"
        super().__init__(self.message)
