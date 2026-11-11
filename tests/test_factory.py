"""The composition root (code-corhuila/qone-docs#55): the in-memory runtime exists only in develop,
its demo people are synthetic and carry no ADMIN, the ADMIN comes from BOOTSTRAP_ADMIN_*, and a
bad configuration outside develop stops the service before it opens anything."""

import secrets

import pytest
from apps.api.factory import Settings, build_app
from fastapi.testclient import TestClient

from tests.http_support import PRIVATE_PEM

BASE = "/api/v1/identity"
DEMO = secrets.token_urlsafe(16)
ADMIN_PASSWORD = secrets.token_urlsafe(18)
UNREACHABLE = "postgresql://nobody:nothing@127.0.0.1:1/none"


@pytest.fixture
def env(tmp_path):
    key = tmp_path / "jwt-private.pem"
    key.write_text(PRIVATE_PEM, encoding="utf-8")
    return {
        "JWT_PRIVATE_KEY_FILE": str(key),
        "APP_ENV": "develop",
        "DEMO_PASSWORD": DEMO,
        "BOOTSTRAP_ADMIN_EMAIL": "admin@qampus.test",
        "BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PASSWORD,
    }


def client(env) -> TestClient:
    return TestClient(build_app(Settings(env)), raise_server_exceptions=False)


def login(c: TestClient, email: str, password: str):
    return c.post(f"{BASE}/auth/login", json={"email": email, "password": password})


class TestInMemoryRuntime:
    def test_develop_serves_the_synthetic_people_and_the_bootstrapped_admin(self, env):
        c = client(env)
        student = login(c, "estudiante.01@qampus.test", DEMO)
        assert student.status_code == 200
        assert student.json()["user"]["name"] == "Estudiante Demo 01"
        assert student.json()["user"]["id"] == "11111111-1111-4111-8111-111111111111"
        assert login(c, "profesor.03@qampus.test", DEMO).json()["user"]["role"] == "PROFESSOR"
        admin = login(c, "admin@qampus.test", ADMIN_PASSWORD).json()
        assert admin["user"]["id"] == "33333333-3333-4333-8333-333333333331" and admin["user"]["role"] == "ADMIN"
        listed = c.get(f"{BASE}/users?limit=100", headers={"Authorization": f"Bearer {admin['token']}"}).json()
        assert listed["meta"]["total"] == 9, "eight demo people and the bootstrapped ADMIN"
        assert all(u["email"].endswith("@qampus.test") for u in listed["data"])

    def test_the_demo_password_does_not_open_the_admin(self, env):
        assert login(client(env), "admin@qampus.test", DEMO).status_code == 401

    @pytest.mark.parametrize("app_env", ["", "qa", "main", "production"])
    def test_outside_develop_the_in_memory_runtime_refuses_to_start(self, env, app_env):
        with pytest.raises(SystemExit) as caught:
            client({**env, "APP_ENV": app_env})
        assert "APP_ENV=develop" in str(caught.value)


class TestOutsideDevelop:
    @pytest.mark.parametrize(
        ("overrides", "variable"),
        [
            ({"BOOTSTRAP_ADMIN_EMAIL": ""}, "BOOTSTRAP_ADMIN_EMAIL"),
            ({"BOOTSTRAP_ADMIN_PASSWORD": ""}, "BOOTSTRAP_ADMIN_PASSWORD"),
            ({"BOOTSTRAP_ADMIN_PASSWORD": "short-pass"}, "BOOTSTRAP_ADMIN_PASSWORD"),
            ({"BOOTSTRAP_ADMIN_PASSWORD": DEMO}, "BOOTSTRAP_ADMIN_PASSWORD"),
        ],
    )
    def test_a_bad_bootstrap_stops_the_service_before_it_touches_the_database(self, env, overrides, variable):
        with pytest.raises(SystemExit) as caught:
            build_app(Settings({**env, "APP_ENV": "qa", "IDENTITY_DATABASE_URL": UNREACHABLE, **overrides}))
        assert variable in str(caught.value) and ADMIN_PASSWORD not in str(caught.value)
