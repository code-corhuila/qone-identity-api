"""Integration level (Annex C): the real engine with the schema of qone-identity-db, through
TEST_DATABASE_URL. Skipped, not failed, when the variable is absent."""

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from identity.application.port.outbound.ports import DuplicateEmail, DuplicateStudentCode
from identity.domain.model.idempotency import ANONYMOUS, IdempotencyKey, fingerprint_of
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import Role, User

URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL not set")
NOW = datetime(2026, 10, 12, 15, 0, 0, tzinfo=UTC)
ADMIN_ID = "33333333-3333-4333-8333-333333333331"


def key(value: str, owner: str = ANONYMOUS, request: dict | None = None) -> IdempotencyKey:
    return IdempotencyKey(owner, value, fingerprint_of(request or {"key": value}))


@pytest.fixture(scope="module")
def pool():
    from identity.adapter.outbound.persistence.postgres import connect

    pool = connect(URL, max_size=2)
    yield pool
    pool.close()


@pytest.fixture
def stores(pool):
    from identity.adapter.outbound.persistence.postgres import PostgresServiceTokenStore, PostgresUserStore

    with pool.connection() as conn:
        conn.execute("TRUNCATE identity.idempotency_key, identity.service_token")
        conn.execute("DELETE FROM identity.app_user WHERE email LIKE 'it-%%'")
    return PostgresUserStore(pool), PostgresServiceTokenStore(pool)


def new_user(email: str = "it-nuevo@uni.edu.co", code: str = "202300001") -> User:
    return User.register(uuid4(), "Nuevo Estudiante", email, "Qampus2026!", code, "Ingeniería de Software", 1, NOW)


def test_round_trip_keeps_every_type_and_the_hash(stores):
    users, _ = stores
    user = new_user()
    stored, created = users.create(user, key("it-key-roundtrip-01"))
    assert created and stored.resource == user and stored.fingerprint == key("it-key-roundtrip-01").fingerprint
    found = users.find(user.id)
    assert found == user and found.created_at.tzinfo is not None and found.password_matches("Qampus2026!")
    assert (
        users.find_by_email("it-nuevo@uni.edu.co") == user
        and users.find_by_key(ANONYMOUS, "it-key-roundtrip-01").resource == user
    )


def test_a_used_key_rolls_back_and_returns_the_first_user(stores):
    users, _ = stores
    first = new_user("it-first@uni.edu.co", "202300011")
    users.create(first, key("it-key-replay-0001"))
    second = new_user("it-second@uni.edu.co", "202300012")
    again, created = users.create(second, key("it-key-replay-0001"))
    assert created is False and again.resource == first and users.find(second.id) is None


def test_the_unique_email_is_duplicate_email(stores):
    users, _ = stores
    users.create(new_user("it-dup@uni.edu.co", "202300021"), key("it-key-unique-001"))
    with pytest.raises(DuplicateEmail):
        users.create(new_user("it-dup@uni.edu.co", "202300022"), key("it-key-unique-002"))
    with pytest.raises(DuplicateStudentCode):
        users.create(new_user("it-other@uni.edu.co", "202300021"), key("it-key-unique-003"))


def test_the_page_is_newest_first_with_filters_and_the_seed_people_are_there(stores):
    users, _ = stores
    users.create(new_user("it-page@uni.edu.co", "202300031"), key("it-key-page-00001"))
    items, total = users.page(None, None, 1, 1)
    assert items[0].email == "it-page@uni.edu.co" and total >= 10
    professors, _ = users.page("PROFESSOR", None, 1, 20)
    assert {u.email for u in professors} >= {
        "carlos.ramirez@uni.edu.co",
        "ana.torres@uni.edu.co",
        "jorge.medina@uni.edu.co",
    }
    laura, _ = users.page(None, "laura", 1, 20)
    assert [u.name for u in laura] == ["Laura Gómez"]
    seed = users.find(UUID("11111111-1111-4111-8111-111111111111"))
    assert seed is not None and seed.role is Role.STUDENT and seed.student_code == "202110342"


def test_service_tokens_are_stored_once_per_key(stores):
    _, tokens = stores
    token = ServiceToken.issue(uuid4(), "qone-workflow", 720, "eyJ.value.sig", NOW)
    stored, created = tokens.create(token, key("it-svc-key-00001", ADMIN_ID))
    assert created and stored.resource == token
    again, created_again = tokens.create(
        ServiceToken.issue(uuid4(), "qone-worker", 1, "x.y.z", NOW), key("it-svc-key-00001", ADMIN_ID)
    )
    assert created_again is False and again.resource == token
    assert tokens.find_by_key(ADMIN_ID, "it-svc-key-00001").resource == token
    assert tokens.find_by_key(str(uuid4()), "it-svc-key-00001") is None, "another admin does not see the key"


def test_a_retry_of_the_same_key_returns_the_first_user_even_against_the_unique_email(stores):
    users, _ = stores
    first = new_user("it-retry@uni.edu.co", "202300041")
    users.create(first, key("it-key-retry-0001"))
    retry = new_user("it-retry@uni.edu.co", "202300041")  # same e-mail and code: would trip the indexes
    again, created = users.create(retry, key("it-key-retry-0001"))
    assert created is False and again.resource == first


def test_the_same_key_from_two_owners_is_two_resources_and_each_keeps_its_fingerprint(stores):
    _, tokens = stores
    other_admin = str(uuid4())
    first = ServiceToken.issue(uuid4(), "qone-workflow", 720, "a.b.c", NOW)
    second = ServiceToken.issue(uuid4(), "qone-workflow", 720, "d.e.f", NOW)
    mine = key("it-svc-key-shared", ADMIN_ID, {"service": "qone-workflow", "ttlHours": 720})
    theirs = key("it-svc-key-shared", other_admin, {"service": "qone-workflow", "ttlHours": 720})
    assert tokens.create(first, mine)[1] is True and tokens.create(second, theirs)[1] is True
    assert tokens.find_by_key(ADMIN_ID, "it-svc-key-shared").resource == first
    found = tokens.find_by_key(other_admin, "it-svc-key-shared")
    assert found.resource == second and found.fingerprint == theirs.fingerprint


def test_the_ready_probe_answers_against_the_real_engine(pool):
    from identity.adapter.outbound.persistence.postgres import PostgresProbe

    PostgresProbe(pool, timeout_seconds=2.0).ping()
