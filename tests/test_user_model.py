"""Core level: the User aggregate alone."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from identity.domain.model.errors import ValidationError
from identity.domain.model.user import Role, User

NOW = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)


def register(**overrides):
    args = dict(
        user_id=uuid4(),
        name="Nuevo Estudiante",
        email="Nuevo.Estudiante@uni.edu.co",
        password="Qampus2026!",
        student_code="202300001",
        program="Ingeniería de Software",
        semester=1,
        now=NOW,
    )
    args.update(overrides)
    return User.register(**args)


def test_registration_creates_a_student_with_a_hashed_password_and_a_lower_case_email():
    user = register()
    assert user.role is Role.STUDENT
    assert user.email == "nuevo.estudiante@uni.edu.co"
    assert user.password_hash != "Qampus2026!" and "$" in user.password_hash
    assert user.password_matches("Qampus2026!") and not user.password_matches("wrong")
    assert user.created_at == NOW == user.updated_at


def test_name_and_program_are_trimmed():
    user = register(name="  Nuevo Estudiante ", program=" Ingeniería de Software ")
    assert user.name == "Nuevo Estudiante" and user.program == "Ingeniería de Software"


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"name": "N"}, "name"),
        ({"name": "x" * 121}, "name"),
        ({"email": "not-an-email"}, "email"),
        ({"email": "a@" + "b" * 118 + ".co"}, "email"),
        ({"password": "short"}, "password"),
        ({"password": "p" * 129}, "password"),
        ({"student_code": "2021-10342"}, "studentCode"),
        ({"student_code": "12345"}, "studentCode"),
        ({"program": "I"}, "program"),
        ({"semester": 0}, "semester"),
        ({"semester": 13}, "semester"),
        ({"semester": True}, "semester"),
    ],
)
def test_an_invalid_field_is_named(overrides, field):
    with pytest.raises(ValidationError) as caught:
        register(**overrides)
    assert [d.field for d in caught.value.details] == [field]


def test_every_invalid_field_is_reported_at_once():
    with pytest.raises(ValidationError) as caught:
        register(name="", email="x", password="", student_code="", program="", semester=0)
    assert [d.field for d in caught.value.details] == [
        "name",
        "email",
        "password",
        "studentCode",
        "program",
        "semester",
    ]
