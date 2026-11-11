"""Core level: the User aggregate alone."""

import secrets
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from identity.domain.model.errors import ValidationError
from identity.domain.model.user import Role, User

NOW = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)
PASSWORD = secrets.token_urlsafe(16)  # generated per test session: no password is a literal here
ADMIN_ID = UUID("33333333-3333-4333-8333-333333333331")


def register(**overrides):
    args = dict(
        user_id=uuid4(),
        name="Nuevo Estudiante",
        email="Nuevo.Estudiante@uni.edu.co",
        password=PASSWORD,
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
    assert user.password_hash != PASSWORD and "$" in user.password_hash
    assert user.password_matches(PASSWORD) and not user.password_matches("wrong")
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


class TestAdministrator:
    """The ADMIN is not seeded: the service creates it at start from its configuration (#55)."""

    def test_the_administrator_is_an_admin_with_a_hashed_password_and_no_student_fields(self):
        password = secrets.token_urlsafe(16)
        admin = User.administrator(ADMIN_ID, " Admin@Qampus.test ", password, NOW)
        assert admin.id == ADMIN_ID and admin.role is Role.ADMIN and admin.name == "Administrador"
        assert admin.email == "admin@qampus.test" and admin.password_matches(password)
        assert password not in admin.password_hash
        assert (admin.student_code, admin.program, admin.semester) == (None, None, None)

    @pytest.mark.parametrize(
        ("email", "password", "fields"),
        [
            ("not-an-email", "x" * 16, ["email"]),
            ("admin@qampus.test", "short", ["password"]),
            ("", "", ["email", "password"]),
        ],
    )
    def test_an_invalid_email_or_password_is_named(self, email, password, fields):
        with pytest.raises(ValidationError) as caught:
            User.administrator(ADMIN_ID, email, password, NOW)
        assert [d.field for d in caught.value.details] == fields
