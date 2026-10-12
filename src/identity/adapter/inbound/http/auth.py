"""Token verification (norm 5.3.7): identity validates the tokens it issued like any other
service does, with the public key. `alg` must be exactly RS256; `exp` and `sub` are required;
30 s of clock skew. The subject is a user id or a service name."""

import base64
import json

import jwt

from identity.application.port.inbound.caller import Caller, TokenRole

ALGORITHMS = ["RS256"]
LEEWAY_SECONDS = 30


class AuthError(Exception):
    def __init__(self, message: str = "missing or invalid token") -> None:
        super().__init__(message)
        self.message = message


class TokenVerifier:
    def __init__(self, public_key_pem: str) -> None:
        self._key = public_key_pem

    def verify(self, authorization: str | None) -> Caller:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthError()
        token = authorization[len("Bearer ") :].strip()
        if _declared_alg(token) != "RS256":
            raise AuthError()
        try:
            claims = jwt.decode(
                token, self._key, algorithms=ALGORITHMS, leeway=LEEWAY_SECONDS, options={"require": ["exp", "sub"]}
            )
            return Caller(str(claims["sub"]), TokenRole(claims.get("role", "")), str(claims.get("name", "")))
        except (jwt.PyJWTError, ValueError) as cause:
            raise AuthError() from cause


def _declared_alg(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None
    return header.get("alg") if isinstance(header, dict) else None
