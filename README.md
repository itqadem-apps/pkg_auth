# pkg-auth

Clean-architecture **identity + ACL** for multi-framework Python services. Handles JWT authentication (via Keycloak) and database-backed authorization (users, organizations, roles, permissions, memberships) in a single package with first-class support for **FastAPI**, **Django**, and **Strawberry GraphQL**.

> **v1.0 is a breaking change from v0.x.** The old claim-based authorization model (`AccessContext`, `AccessRights`, `require_permissions`) is replaced by a real ACL database. See [`docs/MIGRATION_v1.md`](docs/MIGRATION_v1.md) for the upgrade guide.

## Install

```bash
# Core (identity only — no DB deps)
pip install pkg-auth

# With ACL + FastAPI (most common for itqadem services)
pip install pkg-auth[acl-sqlalchemy,fastapi]

# With ACL + Django
pip install pkg-auth[acl-django,django]

# With optional Redis cache
pip install pkg-auth[cache-redis]
```

## Quickstart (FastAPI)

```python
from fastapi import Depends, FastAPI
from pkg_auth.authentication import IdentityContext
from pkg_auth.authorization import AuthContext
from pkg_auth.integrations.fastapi import (
    create_authentication,
    make_get_auth_context,
    require_permission,
)

# --- Wire authentication + authorization ---

auth = create_authentication(
    keycloak_base_url="https://auth.example.com",
    realm="itqadem",
    audience="courses-service",
)

# (wire sync_user_use_case, resolve_use_case, organization_repo from your DI)
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    sync_user_use_case=sync_user,
    resolve_use_case=resolve,
    organization_repo=org_repo,
)

app = FastAPI()

# --- Use in routes ---

@app.get("/courses/{id}")
async def get_course(
    id: str,
    bundle: tuple[IdentityContext, AuthContext] = Depends(
        require_permission("course:view", get_auth_context=get_auth_context)
    ),
):
    identity, auth_ctx = bundle
    return {"course_id": id, "role": str(auth_ctx.role_name)}
```

See [`examples/itqadem_courses_app`](examples/itqadem_courses_app) for a complete working example.

## Architecture

```
pkg_auth/
  authentication/             JWT validation → IdentityContext (identity only)
  authorization/              Full ACL (users, orgs, roles, perms, memberships)
    domain/                   Pure entities, ports (Protocol), exceptions
    application/use_cases/    Business logic (13 use cases)
    adapters/
      sqlalchemy/             Canonical schema + Alembic migration + repos
      django_orm/             Mirror models (managed=False) + repos
      cache/                  InMemoryTTLCache / RedisCache + decorator
  integrations/
    fastapi/                  Deps + require_permission + exception handlers
    django/                   Middleware + decorators
    strawberry/               Context getter + permission classes
  admin/                      Keycloak admin client (user provisioning)
```

**Layering rules**: domain has zero external imports; application imports only domain; adapters import their framework; integrations import everything.

## Documentation

- [Authorization model](docs/Authorization.md) — schema, permission catalog, roles, memberships
- [Caching](docs/Caching.md) — InMemoryTTLCache, RedisCache, invalidation contract
- [FastAPI Integration](docs/FastAPI.md)
- [Django Integration](docs/Django.md)
- [Strawberry Integration](docs/Strawberry.md)
- [Keycloak Admin](docs/Keycloak-Admin.md)
- [Migration from v0.x](docs/MIGRATION_v1.md)
