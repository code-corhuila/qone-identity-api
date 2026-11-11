"""An Idempotency-Key as the service remembers it (norm 5.3.8, code-corhuila/qone-docs#55): the key
belongs to whoever sent it, and it stands for ONE request. The owner is the subject of the token,
or ANONYMOUS for the public registration; the fingerprint is the SHA-256 of the canonical request,
so the same owner and key with another request is told apart from a retry. Pure Python."""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

ANONYMOUS = "anonymous"
"""The owner of the keys of the public registration, which has no caller."""


@dataclass(frozen=True)
class IdempotencyKey:
    owner: str
    key: str
    fingerprint: str

    def same_request(self, fingerprint: str) -> bool:
        return self.fingerprint == fingerprint


def fingerprint_of(request: Mapping[str, object]) -> str:
    """SHA-256 (hex) of the request as canonical JSON: sorted fields, no spaces, types kept."""
    canonical = json.dumps(dict(request), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
