"""The operations of the identity service (ID-02..ID-07) over the ports. Authorization by role
happens here (07-api/authentication.md access matrix); input bounds carry the contract's field
names so the HTTP adapter only translates."""

from datetime import timedelta
from uuid import UUID

from identity.application.errors import AuthenticationFailed, Forbidden, NotFound
from identity.application.port.inbound.caller import Caller, TokenRole
from identity.application.port.inbound.identity import (
    MAX_LIMIT,
    Authenticated,
    IdentityUseCases,
    IssuedServiceToken,
    IssueServiceToken,
    Login,
    Page,
    Register,
    Registered,
)
from identity.application.port.outbound.ports import (
    Clock,
    DuplicateEmail,
    DuplicateStudentCode,
    IdGenerator,
    ServiceTokenStore,
    TokenSigner,
    UserStore,
)
from identity.domain.model.credentials import hash_password, verify_password
from identity.domain.model.errors import BusinessRuleViolation, FieldError, ValidationError
from identity.domain.model.service_token import ServiceToken
from identity.domain.model.token import USER_TOKEN_LIFETIME, TokenClaims
from identity.domain.model.user import Role, User

KEY_MIN, KEY_MAX = 8, 128
ROLES = {r.value for r in Role}
# A login for an unknown e-mail still verifies against this hash so both failures take the same time.
_DECOY_HASH = hash_password("decoy-password-for-constant-time", salt="0" * 32)


class IdentityService(IdentityUseCases):
    def __init__(
        self,
        users: UserStore,
        service_tokens: ServiceTokenStore,
        signer: TokenSigner,
        clock: Clock,
        ids: IdGenerator,
        token_lifetime: timedelta = USER_TOKEN_LIFETIME,
    ) -> None:
        self._users = users
        self._service_tokens = service_tokens
        self._signer = signer
        self._clock = clock
        self._ids = ids
        self._lifetime = token_lifetime

    def register(self, command: Register, idempotency_key: str) -> Registered:
        _check_key(idempotency_key)
        earlier = self._users.find_by_key(idempotency_key)
        if earlier is not None:
            return Registered(self._authenticate(earlier), created=False)
        user = User.register(
            user_id=self._ids.new_id(),
            name=command.name,
            email=command.email,
            password=command.password,
            student_code=command.student_code,
            program=command.program,
            semester=command.semester,
            now=self._clock.now(),
        )
        if self._users.find_by_email(user.email) is not None:
            raise _email_taken()
        try:
            stored, created = self._users.create(user, idempotency_key)
        except DuplicateEmail:
            raise _email_taken() from None
        except DuplicateStudentCode:
            raise BusinessRuleViolation("an account with this student code already exists") from None
        return Registered(self._authenticate(stored), created)

    def login(self, command: Login) -> Authenticated:
        email = command.email.strip().lower() if isinstance(command.email, str) else ""
        user = self._users.find_by_email(email) if email else None
        if user is None:
            verify_password(command.password or "", _DECOY_HASH)
            raise AuthenticationFailed()
        if not user.password_matches(command.password or ""):
            raise AuthenticationFailed()
        return self._authenticate(user)

    def me(self, caller: Caller) -> User:
        if caller.role is TokenRole.SERVICE:
            raise Forbidden()
        user = self._users.find(_uuid(caller.subject))
        if user is None:
            raise NotFound()
        return user

    def users(self, caller: Caller, role: str | None, q: str | None, page: int, limit: int) -> Page:
        _require(caller, TokenRole.ADMIN)
        details: list[FieldError] = []
        if not isinstance(page, int) or page < 1:
            details.append(FieldError("page", "must be 1 or greater"))
        if not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
            details.append(FieldError("limit", f"must be between 1 and {MAX_LIMIT}"))
        if role is not None and role not in ROLES:
            details.append(FieldError("role", f"must be one of {', '.join(sorted(ROLES))}"))
        if q is not None and not 1 <= len(q.strip()) <= 120:
            details.append(FieldError("q", "must have 1 to 120 characters"))
        if details:
            raise ValidationError(details)
        items, total = self._users.page(role, q.strip().lower() if q else None, page, limit)
        return Page(items=items, page=page, limit=limit, total=total)

    def get_user(self, caller: Caller, user_id: UUID) -> User:
        _require(caller, TokenRole.ADMIN, TokenRole.SERVICE)
        user = self._users.find(user_id)
        if user is None:
            raise NotFound()
        return user

    def issue_service_token(
        self, caller: Caller, command: IssueServiceToken, idempotency_key: str
    ) -> IssuedServiceToken:
        _require(caller, TokenRole.ADMIN)
        _check_key(idempotency_key)
        earlier = self._service_tokens.find_by_key(idempotency_key)
        if earlier is not None:
            return IssuedServiceToken(earlier, token=None, created=False)
        now = self._clock.now()
        # The aggregate validates the service and the lifetime before anything is signed.
        probe = ServiceToken.issue(self._ids.new_id(), command.service, command.ttl_hours, "", now)
        claims = TokenClaims.for_service(command.service, now, probe.expires_at - probe.created_at)
        token = self._signer.sign(claims)
        record = ServiceToken.issue(probe.id, command.service, command.ttl_hours, token, now)
        stored, created = self._service_tokens.create(record, idempotency_key)
        return IssuedServiceToken(stored, token=token if created else None, created=created)

    def _authenticate(self, user: User) -> Authenticated:
        claims = TokenClaims.for_user(user, self._clock.now(), self._lifetime)
        return Authenticated(user=user, token=self._signer.sign(claims), expires_at=claims.expires_at)


def _check_key(idempotency_key: str) -> None:
    if not KEY_MIN <= len(idempotency_key or "") <= KEY_MAX:
        raise ValidationError([FieldError("Idempotency-Key", "header required, 8 to 128 characters")])


def _require(caller: Caller, *roles: TokenRole) -> None:
    if caller.role not in roles:
        raise Forbidden()


def _uuid(subject: str) -> UUID:
    try:
        return UUID(subject)
    except ValueError:
        raise NotFound() from None


def _email_taken() -> BusinessRuleViolation:
    return BusinessRuleViolation("an account with this e-mail already exists")
