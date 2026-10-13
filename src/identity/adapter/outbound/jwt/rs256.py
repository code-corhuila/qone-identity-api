"""The TokenSigner over PyJWT: RS256 (RSA 2048, PKCS#1 v1.5 with SHA-256) with the private
key this service alone holds (07-api/authentication.md §2). The public half is derived here
for this service's own verifier; qone-infra hands the same PEM to every other service."""

import jwt
from cryptography.hazmat.primitives import serialization

from identity.domain.model.token import TokenClaims


class Rs256Signer:
    def __init__(self, private_key_pem: str) -> None:
        self._private = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)

    def sign(self, claims: TokenClaims) -> str:
        return jwt.encode(claims.as_dict(), self._private, algorithm="RS256")

    def public_key_pem(self) -> str:
        return (
            self._private.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("utf-8")
        )
