"""Core level (Annex C): the use cases over the in-memory stores and fakes of the ports."""

import json
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from identity.adapter.outbound.persistence.memory import InMemoryServiceTokenStore, InMemoryUserStore
from identity.application.errors import AuthenticationFailed, Forbidden, NotFound
from identity.application.port.inbound.caller import Caller, TokenRole
from identity.application.port.inbound.identity import IssueServiceToken, Login, Register
from identity.application.usecase.identity import IdentityService
from identity.domain.model.errors import BusinessRuleViolation, ValidationError
from identity.domain.model.user import Role
from tests.fakes import CARLOS, DEMO_PASSWORD, LAURA, PATRICIA, SANTIAGO, SEED, FakeSigner, FixedClock, SequenceIds

admin = Caller(str(PATRICIA.id), TokenRole.ADMIN, "Patricia Mora")
laura = Caller(str(LAURA.id), TokenRole.STUDENT, "Laura Gómez")
professor = Caller(str(CARLOS.id), TokenRole.PROFESSOR, "Carlos Ramírez")
service = Caller("qone-workflow", TokenRole.SERVICE, "qone-workflow")
KEY = "register-6f1d2c3e-9b7a-4e1f-8c2d-0a1b2c3d4e5f"
NEW = Register(
    "Nuevo Estudiante", "Nuevo.Estudiante@uni.edu.co", "Qampus2026!", "202300001", "Ingeniería de Software", 1
)


@pytest.fixture
def world():
    users, tokens, signer, clock = (
        InMemoryUserStore(list(SEED)),
        InMemoryServiceTokenStore(),
        FakeSigner(),
        FixedClock(),
    )
    return users, tokens, signer, clock, IdentityService(users, tokens, signer, clock, SequenceIds())


def claims_of(token: str) -> dict:
    return json.loads(token.removeprefix("signed:"))


class TestRegister:
    def test_a_student_is_created_and_signed_in_for_eight_hours(self, world):
        users, _, _, clock, service_ = world
        result = service_.register(NEW, KEY)
        assert result.created is True
        user = result.auth.user
        assert user.id == UUID("99999999-9999-4999-8999-999999999901") and user.role is Role.STUDENT
        assert user.email == "nuevo.estudiante@uni.edu.co" and users.find(user.id) == user
        claims = claims_of(result.auth.token)
        assert claims["sub"] == str(user.id) and claims["role"] == "STUDENT" and claims["name"] == "Nuevo Estudiante"
        assert result.auth.expires_at == clock.now() + timedelta(hours=8)

    def test_a_replayed_key_returns_the_same_account_with_a_fresh_token(self, world):
        _, _, signer, _, service_ = world
        first = service_.register(NEW, KEY)
        again = service_.register(Register("Other", "other@uni.edu.co", "Qampus2026!", "202300002", "X Y", 2), KEY)
        assert again.created is False and again.auth.user == first.auth.user
        assert len(signer.signed) == 2, "a fresh token each time; the account is the first one"

    def test_a_used_email_is_a_business_rule_violation(self, world):
        _, _, _, _, service_ = world
        with pytest.raises(BusinessRuleViolation):
            service_.register(
                Register("Laura Dos", "LAURA.GOMEZ@uni.edu.co", "Qampus2026!", "202300003", "X Y", 1), KEY
            )

    @pytest.mark.parametrize("key", ["", "short", "k" * 129])
    def test_the_key_is_bounded(self, world, key):
        _, _, _, _, service_ = world
        with pytest.raises(ValidationError) as caught:
            service_.register(NEW, key)
        assert caught.value.details[0].field == "Idempotency-Key"

    def test_invalid_fields_come_from_the_aggregate(self, world):
        _, _, _, _, service_ = world
        with pytest.raises(ValidationError) as caught:
            service_.register(Register("N", "x", "short", "1", "", 0), KEY)
        assert [d.field for d in caught.value.details] == [
            "name",
            "email",
            "password",
            "studentCode",
            "program",
            "semester",
        ]


class TestLogin:
    def test_the_right_password_signs_in(self, world):
        _, _, _, clock, service_ = world
        auth = service_.login(Login("Laura.Gomez@uni.edu.co ", DEMO_PASSWORD))
        assert auth.user == LAURA and claims_of(auth.token)["sub"] == str(LAURA.id)
        assert auth.expires_at == clock.now() + timedelta(hours=8)

    @pytest.mark.parametrize(
        "command", [Login("laura.gomez@uni.edu.co", "wrong"), Login("nobody@uni.edu.co", DEMO_PASSWORD), Login("", "")]
    )
    def test_a_wrong_password_and_an_unknown_email_fail_the_same_way(self, world, command):
        _, _, signer, _, service_ = world
        with pytest.raises(AuthenticationFailed) as caught:
            service_.login(command)
        assert caught.value.message == "invalid e-mail or password" and signer.signed == []


class TestMe:
    def test_a_person_reads_itself_and_a_service_may_not(self, world):
        _, _, _, _, service_ = world
        assert service_.me(laura) == LAURA and service_.me(professor) == CARLOS
        with pytest.raises(Forbidden):
            service_.me(service)

    def test_a_subject_without_a_row_is_not_found(self, world):
        _, _, _, _, service_ = world
        with pytest.raises(NotFound):
            service_.me(Caller(str(uuid4()), TokenRole.STUDENT))


class TestUsers:
    def test_an_admin_lists_newest_first_with_filters(self, world):
        _, _, _, clock, service_ = world
        clock.tick(days=1)
        new = service_.register(NEW, KEY).auth.user
        page = service_.users(admin, None, None, 1, 20)
        assert page.items[0] == new and page.total == 5 and page.total_pages == 1
        assert [u.email for u in service_.users(admin, "PROFESSOR", None, 1, 20).items] == ["carlos.ramirez@uni.edu.co"]
        assert [u.name for u in service_.users(admin, None, "LAU", 1, 20).items] == ["Laura Gómez"]
        assert [u.name for u in service_.users(admin, None, "admin@", 1, 20).items] == ["Patricia Mora"]
        second = service_.users(admin, None, None, 2, 2)
        assert len(second.items) == 2 and second.total_pages == 3

    @pytest.mark.parametrize(
        ("page", "limit", "role", "q", "field"),
        [
            (0, 20, None, None, "page"),
            (1, 101, None, None, "limit"),
            (1, 20, "KING", None, "role"),
            (1, 20, None, "x" * 121, "q"),
        ],
    )
    def test_bounds_use_the_contract_field_names(self, world, page, limit, role, q, field):
        _, _, _, _, service_ = world
        with pytest.raises(ValidationError) as caught:
            service_.users(admin, role, q, page, limit)
        assert [d.field for d in caught.value.details] == [field]

    @pytest.mark.parametrize("caller", [laura, professor, service])
    def test_only_an_admin_lists(self, world, caller):
        _, _, _, _, service_ = world
        with pytest.raises(Forbidden):
            service_.users(caller, None, None, 1, 20)


class TestGetUser:
    def test_an_admin_or_a_service_reads_one_user(self, world):
        _, _, _, _, service_ = world
        assert service_.get_user(admin, CARLOS.id) == CARLOS
        assert service_.get_user(service, CARLOS.id) == CARLOS
        with pytest.raises(NotFound):
            service_.get_user(admin, uuid4())

    @pytest.mark.parametrize("caller", [laura, professor])
    def test_a_person_may_not(self, world, caller):
        _, _, _, _, service_ = world
        with pytest.raises(Forbidden):
            service_.get_user(caller, SANTIAGO.id)


class TestServiceTokens:
    def test_an_admin_issues_a_token_once_and_the_replay_hides_its_value(self, world):
        _, tokens, _, clock, service_ = world
        issued = service_.issue_service_token(admin, IssueServiceToken("qone-workflow", 720), "svc-key-0001")
        assert issued.created is True and issued.token is not None
        claims = claims_of(issued.token)
        assert claims["sub"] == "qone-workflow" and claims["role"] == "SERVICE"
        assert claims["exp"] - claims["iat"] == 720 * 3600
        assert issued.service_token.expires_at == clock.now() + timedelta(hours=720)
        again = service_.issue_service_token(admin, IssueServiceToken("qone-workflow", 720), "svc-key-0001")
        assert again.created is False and again.token is None and again.service_token == issued.service_token
        assert tokens.find_by_key("svc-key-0001") == issued.service_token

    def test_the_service_and_the_ttl_are_validated_before_signing(self, world):
        _, _, signer, _, service_ = world
        with pytest.raises(ValidationError) as caught:
            service_.issue_service_token(admin, IssueServiceToken("qone-front", 0), "svc-key-0002")
        assert [d.field for d in caught.value.details] == ["service", "ttlHours"] and signer.signed == []

    @pytest.mark.parametrize("caller", [laura, professor, service])
    def test_only_an_admin_issues(self, world, caller):
        _, _, _, _, service_ = world
        with pytest.raises(Forbidden):
            service_.issue_service_token(caller, IssueServiceToken("qone-worker"), "svc-key-0003")
