"""HTTP level (Annex C): the checks of norm 5.3.12 against this service's resources, with the
server in memory. The token the service issues must be accepted by its own verifier, which is
the same verification every other service performs with JWT_PUBLIC_KEY."""

import jwt
import pytest

from tests.fakes import CARLOS, DEMO_PASSWORD, LAURA, PATRICIA
from tests.http_support import OTHER_PRIVATE_PEM, PUBLIC_PEM, bearer, make_client, mint

BASE = "/api/v1/identity"
KEY = {"Idempotency-Key": "register-6f1d2c3e-9b7a-4e1f-8c2d-0a1b2c3d4e5f"}
NEW = {
    "name": "Nuevo Estudiante",
    "email": "Nuevo.Estudiante@uni.edu.co",
    "password": "Qampus2026!",
    "studentCode": "202300001",
    "program": "Ingeniería de Software",
    "semester": 1,
}


@pytest.fixture
def client():
    return make_client()


def admin():
    return bearer(str(PATRICIA.id), "ADMIN", "Patricia Mora")


def laura():
    return bearer(str(LAURA.id), "STUDENT", "Laura Gómez")


class TestAuthentication:
    def test_health_answers_without_a_token(self, client):
        r = client.get(f"{BASE}/health")
        assert r.status_code == 200 and r.json() == {"status": "ok", "service": "qone-identity-api", "version": "2.0.0"}

    def test_without_a_token_is_401(self, client):
        r = client.get(f"{BASE}/users/me")
        assert r.status_code == 401 and r.json()["error"] == "UNAUTHORIZED"

    @pytest.mark.parametrize("kw", [{"alg": "HS256"}, {"minutes": -5}, {"key": OTHER_PRIVATE_PEM}, {"exp": None}])
    def test_a_bad_token_is_401(self, client, kw):
        token = mint(str(LAURA.id), "STUDENT", **kw)
        assert client.get(f"{BASE}/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_a_valid_token_with_the_wrong_role_is_403(self, client):
        assert client.get(f"{BASE}/users", headers=laura()).status_code == 403


class TestEnvelopeAndCorrelation:
    def test_a_malformed_id_is_400_with_the_envelope(self, client):
        r = client.get(f"{BASE}/users/not-a-uuid", headers=admin())
        body = r.json()
        assert (
            r.status_code == 400
            and body["error"] == "VALIDATION_ERROR"
            and {"error", "message", "traceId"} <= body.keys()
        )
        assert body["details"] == [{"field": "id", "message": "must be a UUID"}]

    def test_the_trace_id_repeats_the_received_correlation_id_and_one_is_made_when_absent(self, client):
        r = client.get(f"{BASE}/users/not-a-uuid", headers={**admin(), "X-Correlation-Id": "e2e-saga-1"})
        assert r.json()["traceId"] == "e2e-saga-1" and r.headers["X-Correlation-Id"] == "e2e-saga-1"
        assert len(client.get(f"{BASE}/health").headers["X-Correlation-Id"]) == 36

    def test_a_missing_resource_and_an_unknown_route_are_404(self, client):
        assert (
            client.get(f"{BASE}/users/00000000-0000-4000-8000-000000000000", headers=admin()).json()["error"]
            == "NOT_FOUND"
        )
        r = client.get(f"{BASE}/nothing", headers=admin())
        assert r.status_code == 404 and r.json()["error"] == "NOT_FOUND"


class TestRegister:
    def test_the_first_send_is_201_with_location_and_a_token_the_service_accepts(self, client):
        r = client.post(f"{BASE}/auth/register", json=NEW, headers=KEY)
        assert r.status_code == 201
        body = r.json()
        assert r.headers["Location"] == f"{BASE}/users/{body['user']['id']}"
        assert body["user"]["email"] == "nuevo.estudiante@uni.edu.co" and body["user"]["role"] == "STUDENT"
        assert "password" not in body["user"] and "passwordHash" not in body["user"]
        claims = jwt.decode(body["token"], PUBLIC_PEM, algorithms=["RS256"])
        assert (
            claims["sub"] == body["user"]["id"]
            and claims["role"] == "STUDENT"
            and claims["exp"] - claims["iat"] == 8 * 3600
        )
        me = client.get(f"{BASE}/users/me", headers={"Authorization": f"Bearer {body['token']}"})
        assert me.status_code == 200 and me.json() == body["user"]

    def test_a_retry_with_the_same_key_is_200_with_the_same_account(self, client):
        first = client.post(f"{BASE}/auth/register", json=NEW, headers=KEY).json()
        again = client.post(f"{BASE}/auth/register", json=NEW, headers=KEY)
        assert again.status_code == 200 and again.json()["user"]["id"] == first["user"]["id"]

    def test_a_used_email_is_422(self, client):
        r = client.post(f"{BASE}/auth/register", json={**NEW, "email": "LAURA.GOMEZ@uni.edu.co"}, headers=KEY)
        assert r.status_code == 422 and r.json()["error"] == "BUSINESS_RULE_VIOLATION"

    def test_an_invalid_body_names_every_field_including_the_key(self, client):
        r = client.post(f"{BASE}/auth/register", json={**NEW, "studentCode": "12-3"})
        assert r.status_code == 400 and [d["field"] for d in r.json()["details"]] == ["Idempotency-Key"]
        r = client.post(
            f"{BASE}/auth/register", json={**NEW, "name": "N", "studentCode": "12-3", "semester": 13}, headers=KEY
        )
        assert [d["field"] for d in r.json()["details"]] == ["name", "studentCode", "semester"]

    def test_malformed_json_and_a_wrong_type_are_400(self, client):
        r = client.post(
            f"{BASE}/auth/register", content="{not json", headers={**KEY, "Content-Type": "application/json"}
        )
        assert r.status_code == 400 and r.json()["error"] == "VALIDATION_ERROR"
        r = client.post(f"{BASE}/auth/register", json={**NEW, "semester": "1"}, headers=KEY)
        assert r.status_code == 400 and [d["field"] for d in r.json()["details"]] == ["semester"]


class TestLogin:
    def test_the_right_password_returns_a_token_and_the_user(self, client):
        r = client.post(f"{BASE}/auth/login", json={"email": "laura.gomez@uni.edu.co", "password": DEMO_PASSWORD})
        assert r.status_code == 200
        body = r.json()
        assert body["user"]["id"] == str(LAURA.id) and body["expiresAt"].endswith("Z")
        assert jwt.decode(body["token"], PUBLIC_PEM, algorithms=["RS256"])["name"] == "Laura Gómez"

    @pytest.mark.parametrize(
        "body",
        [
            {"email": "laura.gomez@uni.edu.co", "password": "wrong"},
            {"email": "nobody@uni.edu.co", "password": DEMO_PASSWORD},
        ],
    )
    def test_a_wrong_password_and_an_unknown_email_look_the_same(self, client, body):
        r = client.post(f"{BASE}/auth/login", json=body)
        assert r.status_code == 401 and r.json() | {"traceId": ""} == {
            "error": "UNAUTHORIZED",
            "message": "invalid e-mail or password",
            "traceId": "",
        }

    def test_a_missing_field_is_400(self, client):
        r = client.post(f"{BASE}/auth/login", json={"email": "laura.gomez@uni.edu.co"})
        assert r.status_code == 400 and [d["field"] for d in r.json()["details"]] == ["password"]


class TestUsers:
    def test_the_list_is_data_and_meta_newest_first_with_filters(self, client):
        r = client.get(f"{BASE}/users", headers=admin())
        body = r.json()
        assert (
            r.status_code == 200
            and set(body) == {"data", "meta"}
            and body["meta"] == {"page": 1, "limit": 20, "total": 4, "totalPages": 1}
        )
        assert [u["name"] for u in client.get(f"{BASE}/users?role=PROFESSOR", headers=admin()).json()["data"]] == [
            "Carlos Ramírez"
        ]
        assert [u["name"] for u in client.get(f"{BASE}/users?q=lau", headers=admin()).json()["data"]] == ["Laura Gómez"]
        assert client.get(f"{BASE}/users?page=2&limit=3", headers=admin()).json()["meta"] == {
            "page": 2,
            "limit": 3,
            "total": 4,
            "totalPages": 2,
        }

    @pytest.mark.parametrize("query", ["limit=101", "limit=0", "page=0", "limit=abc", "role=KING"])
    def test_out_of_range_or_unknown_values_are_400(self, client, query):
        r = client.get(f"{BASE}/users?{query}", headers=admin())
        assert r.status_code == 400 and r.json()["error"] == "VALIDATION_ERROR"

    def test_one_user_for_an_admin_or_a_service_and_me_for_a_person(self, client):
        assert client.get(f"{BASE}/users/{CARLOS.id}", headers=admin()).json()["email"] == "carlos.ramirez@uni.edu.co"
        assert client.get(f"{BASE}/users/{CARLOS.id}", headers=bearer("qone-workflow", "SERVICE")).status_code == 200
        assert client.get(f"{BASE}/users/{CARLOS.id}", headers=laura()).status_code == 403
        assert client.get(f"{BASE}/users/me", headers=laura()).json()["studentCode"] == "202110342"
        assert client.get(f"{BASE}/users/me", headers=bearer("qone-workflow", "SERVICE")).status_code == 403


class TestServiceTokens:
    def test_an_admin_issues_a_service_token_once(self, client):
        r = client.post(
            f"{BASE}/service-tokens",
            json={"service": "qone-workflow"},
            headers={**admin(), "Idempotency-Key": "svc-token-0001"},
        )
        assert r.status_code == 201
        body = r.json()
        claims = jwt.decode(body["token"], PUBLIC_PEM, algorithms=["RS256"])
        assert (
            claims["sub"] == "qone-workflow"
            and claims["role"] == "SERVICE"
            and claims["exp"] - claims["iat"] == 720 * 3600
        )
        again = client.post(
            f"{BASE}/service-tokens",
            json={"service": "qone-workflow"},
            headers={**admin(), "Idempotency-Key": "svc-token-0001"},
        )
        assert again.status_code == 200 and again.json()["token"] is None and again.json()["id"] == body["id"]
        assert (
            client.get(f"{BASE}/users/{CARLOS.id}", headers={"Authorization": f"Bearer {body['token']}"}).status_code
            == 200
        )

    def test_a_bad_service_is_400_and_a_student_is_403(self, client):
        r = client.post(
            f"{BASE}/service-tokens",
            json={"service": "qone-front", "ttlHours": 0},
            headers={**admin(), "Idempotency-Key": "svc-token-0002"},
        )
        assert r.status_code == 400 and [d["field"] for d in r.json()["details"]] == ["service", "ttlHours"]
        assert (
            client.post(
                f"{BASE}/service-tokens",
                json={"service": "qone-worker"},
                headers={**laura(), "Idempotency-Key": "svc-token-0003"},
            ).status_code
            == 403
        )
