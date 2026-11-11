"""Domain level: the fingerprint of a request that an Idempotency-Key remembers (qone-docs#55, F1)."""

import re

from identity.domain.model.idempotency import ANONYMOUS, IdempotencyKey, fingerprint_of


def test_the_fingerprint_is_a_sha256_of_the_canonical_request_whatever_the_field_order():
    one = fingerprint_of({"service": "qone-worker", "ttlHours": 720})
    assert re.fullmatch(r"[0-9a-f]{64}", one)
    assert one == fingerprint_of({"ttlHours": 720, "service": "qone-worker"})


def test_any_other_value_is_another_fingerprint():
    base = {"name": "Nuevo Estudiante", "email": "nuevo@uni.edu.co", "semester": 1}
    assert fingerprint_of(base) != fingerprint_of({**base, "semester": 2})
    assert fingerprint_of(base) != fingerprint_of({**base, "email": "otro@uni.edu.co"})
    assert fingerprint_of({"semester": 1}) != fingerprint_of({"semester": "1"})


def test_a_key_belongs_to_its_owner_and_the_public_registration_has_one_owner():
    key = IdempotencyKey(ANONYMOUS, "register-0001", fingerprint_of({}))
    assert key.owner == "anonymous" and key.key == "register-0001"
    assert key.same_request(fingerprint_of({})) and not key.same_request(fingerprint_of({"x": 1}))
