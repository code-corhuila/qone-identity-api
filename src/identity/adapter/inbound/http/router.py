"""Routes, validation at the border and response objects of ID-01..ID-07
(07-api/contracts/openapi/qone-identity-api.yaml). No endpoint ever returns a password hash;
the domain entities are never serialized directly (Annex C)."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr

from identity.application.port.inbound.caller import Caller
from identity.application.port.inbound.identity import (
    DEFAULT_LIMIT,
    IdentityUseCases,
    IssueServiceToken,
    Login,
    Register,
)
from identity.application.usecase.identity import KEY_MAX, KEY_MIN
from identity.domain.model.errors import FieldError, ValidationError
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.user import User

PREFIX = "/api/v1/identity"
router = APIRouter(prefix=PREFIX)


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: StrictStr
    email: StrictStr
    password: StrictStr
    studentCode: StrictStr  # noqa: N815 - the contract's camelCase
    program: StrictStr
    semester: StrictInt = 1


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: StrictStr
    password: StrictStr


class ServiceTokenBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    service: StrictStr
    ttlHours: StrictInt = 720  # noqa: N815


def use_cases(request: Request) -> IdentityUseCases:
    return request.app.state.use_cases


def caller(request: Request) -> Caller:
    return request.app.state.verifier.verify(request.headers.get("Authorization"))


UseCases = Annotated[IdentityUseCases, Depends(use_cases)]
Current = Annotated[Caller, Depends(caller)]


@router.get("/health")
def health(request: Request):
    return {"status": "ok", "service": request.app.state.service, "version": request.app.state.version}


@router.post("/auth/register")
def register(body: RegisterBody, service: UseCases, request: Request):
    key = idempotency_key_of(request)
    command = Register(body.name, body.email, body.password, body.studentCode, body.program, body.semester)
    result = service.register(command, key)
    payload = represent_auth(result.auth.user, result.auth.token, result.auth.expires_at)
    if not result.created:
        return JSONResponse(payload, status_code=200)
    return JSONResponse(payload, status_code=201, headers={"Location": f"{PREFIX}/users/{result.auth.user.id}"})


@router.post("/auth/login")
def login(body: LoginBody, service: UseCases):
    auth = service.login(Login(body.email, body.password))
    return represent_auth(auth.user, auth.token, auth.expires_at)


@router.get("/users/me")
def me(who: Current, service: UseCases):
    return represent_user(service.me(who))


@router.get("/users")
def users(
    who: Current,
    service: UseCases,
    page: int = Query(1),
    limit: int = Query(DEFAULT_LIMIT),
    role: str | None = Query(None),
    q: str | None = Query(None),
):
    result = service.users(who, role, q, page, limit)
    return {
        "data": [represent_user(u) for u in result.items],
        "meta": {"page": result.page, "limit": result.limit, "total": result.total, "totalPages": result.total_pages},
    }


@router.get("/users/{user_id}")
def get_user(user_id: str, who: Current, service: UseCases):
    return represent_user(service.get_user(who, parse_uuid(user_id, "id")))


@router.post("/service-tokens")
def service_tokens(body: ServiceTokenBody, who: Current, service: UseCases, request: Request):
    key = idempotency_key_of(request)
    result = service.issue_service_token(who, IssueServiceToken(body.service, body.ttlHours), key)
    return JSONResponse(
        represent_service_token(result.service_token, result.token), status_code=201 if result.created else 200
    )


def idempotency_key_of(request: Request) -> str:
    key = request.headers.get("Idempotency-Key", "")
    if not KEY_MIN <= len(key) <= KEY_MAX:
        raise ValidationError([FieldError("Idempotency-Key", "header required, 8 to 128 characters")])
    return key


def parse_uuid(value: str, field: str) -> UUID:
    try:
        return UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise ValidationError([FieldError(field, "must be a UUID")]) from None


def rfc3339(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def represent_user(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "name": user.name,
        "role": user.role.value,
        "studentCode": user.student_code,
        "program": user.program,
        "semester": user.semester,
        "createdAt": rfc3339(user.created_at),
    }


def represent_auth(user: User, token: str, expires_at: datetime) -> dict:
    return {"token": token, "expiresAt": rfc3339(expires_at), "user": represent_user(user)}


def represent_service_token(record: ServiceToken, token: str | None) -> dict:
    return {
        "id": str(record.id),
        "service": record.service,
        "token": token,
        "expiresAt": rfc3339(record.expires_at),
        "createdAt": rfc3339(record.created_at),
    }
