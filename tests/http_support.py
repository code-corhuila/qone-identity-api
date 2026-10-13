"""Support for the HTTP and contract tests: an RSA pair per test session (nothing versioned),
the application over the in-memory stores seeded with the demo people, and tokens minted with
the same key or with another one."""

import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from identity.adapter.inbound.http.app import create_app
from identity.adapter.inbound.http.auth import TokenVerifier
from identity.adapter.outbound.jwt.rs256 import Rs256Signer
from identity.adapter.outbound.persistence.memory import InMemoryServiceTokenStore, InMemoryUserStore
from identity.adapter.outbound.runtime import SystemClock, Uuid4Generator
from identity.application.usecase.identity import IdentityService
from tests.fakes import SEED


def _pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


PRIVATE_PEM = _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
OTHER_PRIVATE_PEM = _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
SIGNER = Rs256Signer(PRIVATE_PEM)
PUBLIC_PEM = SIGNER.public_key_pem()


def mint(
    sub: str, role: str, name: str = "", minutes: int = 60, alg: str = "RS256", key: str | None = None, **extra
) -> str:
    now = int(time.time())
    claims = {"iss": "qone-identity-api", "sub": sub, "role": role, "name": name, "iat": now, "exp": now + minutes * 60}
    claims.update(extra)
    if alg == "HS256":
        return jwt.encode(claims, "not-a-secret", algorithm="HS256")
    return jwt.encode(claims, key or PRIVATE_PEM, algorithm=alg)


def bearer(sub: str, role: str, name: str = "", **kw) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint(sub, role, name, **kw)}"}


def make_client() -> TestClient:
    service = IdentityService(
        InMemoryUserStore(list(SEED)), InMemoryServiceTokenStore(), SIGNER, SystemClock(), Uuid4Generator()
    )
    return TestClient(create_app(service, TokenVerifier(PUBLIC_PEM)), raise_server_exceptions=False)
