"""Contract level: responses validate against the synced copy of qone-identity-api.yaml, and
every path the contract declares is served."""

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from tests.fakes import CARLOS, DEMO_PASSWORD, LAURA, PATRICIA
from tests.http_support import bearer, make_client

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts" / "openapi"
IDENTITY = yaml.safe_load((CONTRACTS / "qone-identity-api.yaml").read_text(encoding="utf-8"))
SHARED = yaml.safe_load((CONTRACTS / "_shared.yaml").read_text(encoding="utf-8"))
BASE = "/api/v1/identity"
NEW = {
    "name": "Nuevo Estudiante",
    "email": "nuevo@uni.edu.co",
    "password": "Qampus2026!",
    "studentCode": "202300001",
    "program": "Ingeniería de Software",
}


def inline(node, doc):
    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            source = SHARED if ref.startswith("./_shared.yaml#") else doc
            target = source
            for part in ref.split("#/")[1].split("/"):
                target = target[part]
            return inline(target, source)
        out = {k: inline(v, doc) for k, v in node.items() if k != "nullable"}
        return {"anyOf": [out, {"type": "null"}]} if node.get("nullable") else out
    if isinstance(node, list):
        return [inline(v, doc) for v in node]
    return node


def assert_valid(body, name: str, doc=IDENTITY):
    schema = inline(doc["components"]["schemas"][name], doc)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(body))
    assert not errors, [e.message for e in errors]


@pytest.fixture
def client():
    return make_client()


def test_every_path_of_the_contract_is_served(client):
    served = set(client.app.openapi()["paths"])
    for path in IDENTITY["paths"]:
        assert "/api/v1" + path.replace("{id}", "{user_id}") in served, f"{path} is in the contract but not served"


def test_health_auth_user_page_and_service_token_match_their_schemas(client):
    assert_valid(client.get(f"{BASE}/health").json(), "Health", SHARED)
    assert_valid(NEW, "RegisterRequest")
    registered = client.post(f"{BASE}/auth/register", json=NEW, headers={"Idempotency-Key": "register-contract-0001"})
    assert registered.status_code == 201
    assert_valid(registered.json(), "AuthResponse")
    assert_valid(
        client.post(f"{BASE}/auth/login", json={"email": LAURA.email, "password": DEMO_PASSWORD}).json(), "AuthResponse"
    )
    assert_valid(client.get(f"{BASE}/users/me", headers=bearer(str(LAURA.id), "STUDENT")).json(), "User")
    assert_valid(client.get(f"{BASE}/users/{CARLOS.id}", headers=bearer(str(PATRICIA.id), "ADMIN")).json(), "User")
    assert_valid(client.get(f"{BASE}/users", headers=bearer(str(PATRICIA.id), "ADMIN")).json(), "UserPage")
    issued = client.post(
        f"{BASE}/service-tokens",
        json={"service": "qone-worker"},
        headers={**bearer(str(PATRICIA.id), "ADMIN"), "Idempotency-Key": "svc-contract-0001"},
    )
    assert_valid(issued.json(), "ServiceToken")
    replay = client.post(
        f"{BASE}/service-tokens",
        json={"service": "qone-worker"},
        headers={**bearer(str(PATRICIA.id), "ADMIN"), "Idempotency-Key": "svc-contract-0001"},
    )
    assert_valid(replay.json(), "ServiceToken") and replay.json()["token"] is None


@pytest.mark.parametrize(
    ("method", "path", "auth", "json", "status", "code"),
    [
        ("GET", "/users?limit=101", ("ADMIN", "33333333-3333-4333-8333-333333333331"), None, 400, "VALIDATION_ERROR"),
        ("GET", "/users/me", None, None, 401, "UNAUTHORIZED"),
        ("POST", "/auth/login", None, {"email": "x@y.co", "password": "nope-nope"}, 401, "UNAUTHORIZED"),
        ("GET", "/users", ("STUDENT", "11111111-1111-4111-8111-111111111111"), None, 403, "FORBIDDEN"),
        (
            "GET",
            "/users/00000000-0000-4000-8000-000000000000",
            ("ADMIN", "33333333-3333-4333-8333-333333333331"),
            None,
            404,
            "NOT_FOUND",
        ),
        ("GET", "/no-such-route", None, None, 404, "NOT_FOUND"),
    ],
)
def test_every_error_matches_the_shared_error_schema(client, method, path, auth, json, status, code):
    headers = bearer(auth[1], auth[0]) if auth else {}
    r = client.request(method, f"{BASE}{path}", headers=headers, json=json)
    assert r.status_code == status and r.json()["error"] == code
    assert_valid(r.json(), "Error", SHARED)
