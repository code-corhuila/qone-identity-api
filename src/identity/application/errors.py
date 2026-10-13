"""Errors of the application layer; the HTTP adapter translates them (401, 403, 404) in one
place. The use cases never mention a status code."""


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
