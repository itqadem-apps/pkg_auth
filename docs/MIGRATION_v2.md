# Migrating from pkg_auth v1.x to v2.0

v2.0 splits the single JWT-sync use case into two, so Mode B (consuming)
services can resolve users **without** writing to an ACL table they
don't own. Before v2.0, `SyncUserFromJwtUseCase` always upserted — a
bug when a Mode B consumer's `ACL_DATABASE_URL` points at a Mode A
peer's database (the `NotNullViolationError` on `users.id` in the
v1.7 → v2.0 issue report).

There is **no deprecation period**: the FastAPI / Django / Strawberry
integration factories now require exactly one of `sync_user_use_case`
or `resolve_user_use_case`. Passing both (or neither) raises
`ValueError`.

## Pick your mode

- **Mode B (consumer)** — the common case. Your service shares the
  ACL database with a source-of-truth peer and does **not** own the
  `users` table. Use `ResolveUserFromJwtUseCase`.
- **Mode A (source-of-truth)** — e.g. `itq_users`. Your service owns
  the `users` table and is responsible for provisioning rows on first
  JWT sight. Keep using `SyncUserFromJwtUseCase`.

## Mode B upgrade (most services)

**Before (v1.x)**:

```python
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)

sync_user = SyncUserFromJwtUseCase(user_repo=user_repo)

get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    sync_user_use_case=sync_user,
    resolve_use_case=resolve,
    organization_repo=org_repo,
)
```

**After (v2.0)**:

```python
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)

resolve_user = ResolveUserFromJwtUseCase(user_repo=user_repo)

get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    resolve_user_use_case=resolve_user,     # was: sync_user_use_case
    resolve_use_case=resolve,
    organization_repo=org_repo,
)
```

A request whose Keycloak `sub` isn't in the local ACL now raises
`UserNotProvisioned` → **HTTP 403**. That's the correct signal: the
source-of-truth service hasn't mirrored this user yet. The consumer
never writes in response.

Same change shape for Django `install_pkg_auth(...)` and Strawberry
`make_context_getter(...)` — swap `sync_user_use_case=` for
`resolve_user_use_case=`. The Strawberry context getter is permissive
(degrades `ctx.auth_context` to `None` on miss) rather than raising.

## Mode A upgrade (source-of-truth services)

No call-site changes — keep passing `sync_user_use_case=`. The use
case itself is unchanged.

## New exception

`pkg_auth.authorization.UserNotProvisioned` (subclass of
`AuthorizationError`). Raised by `ResolveUserFromJwtUseCase` when
`get_by_keycloak_sub` returns `None`. FastAPI and Django integrations
map it to HTTP 403; Strawberry degrades gracefully.

If you catch `AuthorizationError` at a framework boundary (e.g. custom
exception handler), `UserNotProvisioned` is already covered by the
base class.

## Why the split (and why not just patch the adapter)?

v1.7's bundled `SqlAlchemyUserRepository.upsert_from_identity`
emitted `INSERT INTO users (keycloak_sub, email, full_name) ...` —
that misses every Mode A-owned extension column on the Mode A
service's `users` table. Even with `id` defaulted, the insert would
write nulls into Mode A-required columns, corrupting the source-of-
truth's schema invariants. Fixing this in the adapter layer wasn't
enough; the FastAPI / Django / Strawberry factories always composed
with an "upsert-on-every-request" use case. The split pushes the
Mode A vs Mode B choice up to the composition root where it belongs.
