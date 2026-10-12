# qone-identity-api

> identity bounded context: service API

Part of the **Qampus (Quorum One)** distributed system — team `quorum-one`, Grupo 1.
Governance and documentation live in [`qone-docs`](https://github.com/code-corhuila/qone-docs).

## Purpose

The service of the **identity** domain (course norm 5.3, Annex C): users, roles, credentials
and the RS256 key pair. It is the only piece that signs tokens; every other piece validates
them offline with the public key (`07-api/authentication.md`). Python 3.12 + FastAPI,
hexagonal (ADR-007): the domain and the use cases import no framework and no driver; a test
enforces it.

- Contract: `07-api/contracts/openapi/qone-identity-api.yaml` (ID-01..ID-07) in `qone-docs`.
- Data: `qone-identity-db` owns the schema `identity`; this service never versions it.
- Piece page: `09-microservices/services/02-identity-api/README.md`. Story: `code-corhuila/qone-docs#35` (HU-AUT-001).

## Layout (Annex C, Python)

```
src/identity/
├── domain/model/            user.py, credentials.py (PBKDF2), service_token.py, token.py (claims), errors.py
├── application/port/        inbound/ (register, login, me, users, service tokens) · outbound/ (store, signer, clock, ids)
├── application/usecase/     the operations of ID-02..ID-07 and the authorization by role
└── adapter/
    ├── inbound/http/        app.py, auth.py (RS256 with the public half of the key), errors.py, router.py
    └── outbound/            persistence/ (memory, postgres), jwt/ (RS256 signer with the private key)
apps/api/__main__.py         composition root: the only module that knows every concrete type and limit
tests/                       domain, use cases, HTTP, contract, architecture, postgres integration
```

## Rules it keeps

- Passwords are PBKDF2-HMAC-SHA256, 200,000 iterations, per-user salt, compared in constant
  time; no endpoint returns a hash.
- Self-registration creates students only; the e-mail is unique and lower-case; a second
  account with the same e-mail is a business rule violation.
- Login failures answer the same neutral 401 for an unknown e-mail and a wrong password.
- User tokens live 8 hours; `SERVICE` exists only in tokens, with the service name as `sub`.
- Every creation is idempotent by `Idempotency-Key` (norm 5.3.8).

## How to run it

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check .
python -m pytest
```

The HTTP server, its configuration (`.env.example`) and the PostgreSQL adapter arrive with the
next pull requests of HU-AUT-001.

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `qone-docs`.
