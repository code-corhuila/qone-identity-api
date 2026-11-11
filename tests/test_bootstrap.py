"""Use-case level: the ADMIN is created by the service at start, never by a seed
(code-corhuila/qone-docs#55). Idempotent, never overwrites a password, strict outside develop."""

import secrets
from uuid import UUID

import pytest

from identity.adapter.outbound.persistence.memory import InMemoryServiceTokenStore, InMemoryUserStore
from identity.application.port.inbound.identity import Login
from identity.application.usecase.bootstrap import ADMIN_ID, DEVELOP_ADMIN_EMAIL, BootstrapAdmin, BootstrapRefused
from identity.application.usecase.identity import IdentityService
from identity.domain.model.user import Role
from tests.fakes import LAURA, FakeSigner, FixedClock, SequenceIds

STRONG = secrets.token_urlsafe(18)
DEMO = secrets.token_urlsafe(18)


@pytest.fixture
def users():
    return InMemoryUserStore([LAURA])


def run(users, email="admin@qampus.test", password=STRONG, develop=False, demo=DEMO):
    return BootstrapAdmin(users, FixedClock()).run(email, password, develop=develop, demo_password=demo)


class TestCreation:
    def test_the_admin_is_created_once_with_its_fixed_id_and_can_sign_in(self, users):
        assert run(users) == "created"
        admin = users.find(ADMIN_ID)
        assert ADMIN_ID == UUID("33333333-3333-4333-8333-333333333331")
        assert admin.role is Role.ADMIN and admin.email == "admin@qampus.test"
        service = IdentityService(users, InMemoryServiceTokenStore(), FakeSigner(), FixedClock(), SequenceIds())
        assert service.login(Login("admin@qampus.test", STRONG)).user.id == ADMIN_ID

    def test_a_second_start_keeps_the_account_and_never_overwrites_its_password(self, users):
        run(users)
        first = users.find(ADMIN_ID)
        assert run(users, password=secrets.token_urlsafe(18)) == "kept"
        assert users.find(ADMIN_ID) == first and first.password_matches(STRONG)

    def test_an_email_that_belongs_to_another_account_refuses_the_start(self, users):
        with pytest.raises(BootstrapRefused) as caught:
            run(users, email=LAURA.email)
        assert "BOOTSTRAP_ADMIN_EMAIL" in caught.value.message and users.find(ADMIN_ID) is None


class TestOutsideDevelop:
    @pytest.mark.parametrize(
        ("email", "password", "variable"),
        [
            ("", STRONG, "BOOTSTRAP_ADMIN_EMAIL"),
            ("admin@qampus.test", "", "BOOTSTRAP_ADMIN_PASSWORD"),
            ("admin@qampus.test", "eleven-char", "BOOTSTRAP_ADMIN_PASSWORD"),
            ("admin@qampus.test", DEMO, "BOOTSTRAP_ADMIN_PASSWORD"),
            ("not-an-email", STRONG, "BOOTSTRAP_ADMIN_EMAIL"),
        ],
    )
    def test_a_missing_short_or_demo_password_or_a_bad_email_refuses_the_start(self, users, email, password, variable):
        with pytest.raises(BootstrapRefused) as caught:
            run(users, email=email, password=password)
        assert variable in caught.value.message and users.find(ADMIN_ID) is None
        assert password not in caught.value.message or not password, "the message never repeats a password"

    def test_twelve_characters_different_from_the_demo_password_are_enough(self, users):
        assert run(users, password="twelve-chars") == "created"


class TestDevelop:
    def test_the_email_defaults_and_eight_characters_are_enough(self, users):
        assert run(users, email="", password="eight-ch", develop=True) == "created"
        assert users.find(ADMIN_ID).email == DEVELOP_ADMIN_EMAIL == "admin@qampus.test"

    def test_without_a_password_nothing_is_bootstrapped(self, users):
        assert run(users, email="", password="", develop=True) == "skipped"
        assert users.find(ADMIN_ID) is None

    def test_an_invalid_password_still_refuses(self, users):
        with pytest.raises(BootstrapRefused):
            run(users, password="short", develop=True)
