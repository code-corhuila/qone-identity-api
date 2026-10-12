"""Core level: the claims every validator in the platform expects."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from identity.domain.model.token import TokenClaims
from identity.domain.model.user import Role, User

NOW = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)
LAURA = User(
    UUID("11111111-1111-4111-8111-111111111111"),
    "laura.gomez@uni.edu.co",
    "Laura Gómez",
    "s$h",
    Role.STUDENT,
    "202110342",
    "Ingeniería de Software",
    6,
    NOW,
    NOW,
)


def test_a_user_token_carries_sub_role_name_and_eight_hours():
    claims = TokenClaims.for_user(LAURA, NOW).as_dict()
    assert claims == {
        "iss": "qone-identity-api",
        "sub": "11111111-1111-4111-8111-111111111111",
        "role": "STUDENT",
        "name": "Laura Gómez",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(hours=8)).timestamp()),
    }


def test_a_service_token_has_the_service_as_subject_and_role_service():
    claims = TokenClaims.for_service("qone-workflow", NOW, timedelta(hours=720)).as_dict()
    assert claims["sub"] == "qone-workflow" and claims["role"] == "SERVICE" and claims["name"] == "qone-workflow"
    assert claims["exp"] - claims["iat"] == 720 * 3600
