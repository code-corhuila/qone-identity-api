"""Core level (Annex C): the use cases over the in-memory stores and fakes of the ports."""

import json
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from identity.adapter.outbound.persistence.memory import InMemoryServiceTokenStore, InMemoryUserStore
from identity.application.errors import AuthenticationFailed, Forbidden, IdempotencyKeyReused, NotFound
from identity.application.port.inbound.caller import Caller, TokenRole
from identity.application.port.inbound.identity import IssueServiceToken, Login, Register
from identity.application.usecase.identity import IdentityService
from identity.domain.model.errors import BusinessRuleViolation, ValidationError
from identity.domain.model.user import Role
from tests.fakes import CARLOS, LAURA, PASSWORD, PATRICIA, SANTIAGO, SEED, FakeSigner, FixedClock, SequenceIds

admin = Caller(str(PATRICIA.id), TokenRole.ADMIN, "Patricia Mora")
laura = Caller(str(LAURA.id), TokenRole.STUDENT, "Laura Gómez")
professor = Caller(str(CARLOS.id), TokenRole.PROFESSOR, "Carlos Ramírez")
service = Caller("qone-workflow", TokenRole.SERVICE, "qone-workflow")
other_admin = Caller("33333333-3333-4333-8333-333333333332", TokenRole.ADMIN, "Otra Admin")
KEY = "register-6f1d2c3e-9b7a-4e1f-8c2d-0a1b2c3d4e5f"
NEW = Register("Nuevo Estudiante", "Nuevo.Estudiante@uni.edu.co", PASSWORD, "202300001", "Ingeniería de Software", 1)


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


class RacingUserStore(InMemoryUserStore):
    """Lookups that miss what a concurrent request has just written: only the claim of the key in
    create() sees it, as with two identical requests racing over PostgreSQL."""

    stale = False

    def find_by_key(self, owner: str, key: str):
        return None if self.stale else super().find_by_key(owner, key)

    def find_by_email(self, email: str):
        return None if self.stale else super().find_by_email(email)


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

    def test_a_replay_of_the_same_request_returns_the_same_account_with_a_fresh_token(self, world):
        _, _, signer, _, service_ = world
        first = service_.register(NEW, KEY)
        again = service_.register(NEW, KEY)
        assert again.created is False and again.auth.user == first.auth.user
        assert len(signer.signed) == 2, "a fresh token each time; the account is the first one"

    def test_another_person_replaying_the_key_with_another_body_gets_no_token(self, world):
        users, _, signer, _, service_ = world
        first = service_.register(NEW, KEY)
        other = Register("Otra Persona", "otra@uni.edu.co", "Qampus2027!", "202300002", "X Y", 2)
        with pytest.raises(IdempotencyKeyReused):
            service_.register(other, KEY)
        assert len(signer.signed) == 1, "only the first registration was signed"
        assert users.find_by_email("otra@uni.edu.co") is None and users.find(first.auth.user.id) == first.auth.user

    def test_the_same_body_with_another_password_gets_no_token(self, world):
        _, _, signer, _, service_ = world
        service_.register(NEW, KEY)
        with pytest.raises(IdempotencyKeyReused):
            service_.register(Register(**{**NEW.__dict__, "password": "Qampus2027!"}), KEY)
        assert len(signer.signed) == 1, "a replay never signs in without the account's password"

    def test_the_key_taken_by_a_concurrent_request_is_checked_the_same_way(self, world):
        _, _, signer, _, _ = world
        racing = RacingUserStore(list(SEED))
        service_ = IdentityService(racing, InMemoryServiceTokenStore(), signer, FixedClock(), SequenceIds())
        service_.register(NEW, KEY)
        racing.stale = True  # the lookups miss the first row; the claim in create() finds the key taken
        with pytest.raises(IdempotencyKeyReused):
            service_.register(Register(**{**NEW.__dict__, "password": "Qampus2027!"}), KEY)
        again = service_.register(NEW, KEY)
        assert again.created is False and len(signer.signed) == 2

    def test_a_used_email_is_a_business_rule_violation(self, world):
        _, _, _, _, service_ = world
        with pytest.raises(BusinessRuleViolation):
            service_.register(Register("Laura Dos", "LAURA.GOMEZ@uni.edu.co", PASSWORD, "202300003", "X Y", 1), KEY)

    def test_a_used_student_code_is_a_business_rule_violation(self, world):
        _, _, _, _, service_ = world
        with pytest.raises(BusinessRuleViolation) as caught:
            service_.register(Register("Otra Persona", "otra@uni.edu.co", PASSWORD, "202110342", "X Y", 1), KEY)
        assert "student code" in str(caught.value)

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
        auth = service_.login(Login("Laura.Gomez@uni.edu.co ", PASSWORD))
        assert auth.user == LAURA and claims_of(auth.token)["sub"] == str(LAURA.id)
        assert auth.expires_at == clock.now() + timedelta(hours=8)

    @pytest.mark.parametrize(
        "command", [Login("laura.gomez@uni.edu.co", "wrong"), Login("nobody@uni.edu.co", PASSWORD), Login("", "")]
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
        assert tokens.find_by_key(admin.subject, "svc-key-0001").resource == issued.service_token

    def test_another_admin_with_the_same_key_gets_its_own_token_never_the_first_one(self, world):
        _, tokens, _, _, service_ = world
        first = service_.issue_service_token(admin, IssueServiceToken("qone-workflow", 720), "svc-key-0004")
        second = service_.issue_service_token(other_admin, IssueServiceToken("qone-workflow", 720), "svc-key-0004")
        assert second.created is True and second.token is not None
        assert second.service_token.id != first.service_token.id
        assert tokens.find_by_key(other_admin.subject, "svc-key-0004").resource == second.service_token

    def test_the_same_admin_reusing_the_key_for_another_request_is_refused(self, world):
        _, _, signer, _, service_ = world
        service_.issue_service_token(admin, IssueServiceToken("qone-workflow", 720), "svc-key-0005")
        with pytest.raises(IdempotencyKeyReused):
            service_.issue_service_token(admin, IssueServiceToken("qone-worker", 720), "svc-key-0005")
        with pytest.raises(IdempotencyKeyReused):
            service_.issue_service_token(admin, IssueServiceToken("qone-workflow", 24), "svc-key-0005")
        assert len(signer.signed) == 1

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
