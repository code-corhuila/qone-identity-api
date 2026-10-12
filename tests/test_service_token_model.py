"""Core level: service tokens keep only the digest and bound their lifetime."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from identity.domain.model.errors import ValidationError
from identity.domain.model.service_token import ServiceToken, digest_of

NOW = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)


def test_issue_keeps_the_sha256_of_the_token_and_the_expiry():
    token = ServiceToken.issue(uuid4(), "qone-workflow", 720, "eyJ.token.value", NOW)
    assert token.token_hash == digest_of("eyJ.token.value") and len(token.token_hash) == 64
    assert token.expires_at == NOW + timedelta(hours=720) and token.revoked_at is None


@pytest.mark.parametrize(
    ("service", "ttl", "field"),
    [("qone-front", 720, "service"), ("qone-worker", 0, "ttlHours"), ("qone-worker", 8761, "ttlHours")],
)
def test_the_service_and_the_ttl_are_bounded(service, ttl, field):
    with pytest.raises(ValidationError) as caught:
        ServiceToken.issue(uuid4(), service, ttl, "t", NOW)
    assert [d.field for d in caught.value.details] == [field]
