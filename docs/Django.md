# Django Integration

## Setup

### 1. Install

```bash
pip install pkg-auth[acl-django,django]
```

### 2. Add to INSTALLED_APPS

```python
INSTALLED_APPS = [
    ...
    "pkg_auth.authorization.adapters.django_orm",  # managed=False mirror models
    "pkg_auth.integrations.django",                 # middleware + decorators
]
```

### 3. Wire at startup

In your project's `AppConfig.ready()`:

```python
from pkg_auth.integrations.django import install_pkg_auth
from pkg_auth.authorization.adapters.django_orm.repositories import (
    DjangoUserRepository, DjangoOrganizationRepository,
    DjangoMembershipRepository,
)
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import SyncUserFromJwtUseCase
from pkg_auth.authorization.application.use_cases.resolve_auth_context import ResolveAuthContextUseCase

install_pkg_auth(
    keycloak_base_url="https://auth.example.com",
    realm="itqadem",
    audience="my-django-service",
    sync_user_use_case=SyncUserFromJwtUseCase(user_repo=DjangoUserRepository()),
    resolve_use_case=ResolveAuthContextUseCase(
        membership_repo=DjangoMembershipRepository(),
    ),
    organization_repo=DjangoOrganizationRepository(),
)
```

### 4. Add middleware (in order)

```python
MIDDLEWARE = [
    ...
    "pkg_auth.integrations.django.IdentityMiddleware",
    "pkg_auth.integrations.django.AuthContextMiddleware",
    ...
]
```

`IdentityMiddleware` must come before `AuthContextMiddleware`.

## Protecting views

```python
from pkg_auth.integrations.django import require_permission

@require_permission("course:edit")
async def edit_course(request, course_id):
    auth_ctx = request.auth_context
    return JsonResponse({"role": str(auth_ctx.role_name)})
```

Works for both sync and async views. Returns 401 if unauthenticated, 400 if `X-Organization-Id` header is missing, 403 if the perm is missing.

## Django ORM models

The `managed = False` mirror models at `pkg_auth.authorization.adapters.django_orm.models` let you query the ACL tables with Django's ORM:

```python
from pkg_auth.authorization.adapters.django_orm.models import User, Organization, Membership

# Find all orgs a user belongs to
async for org in Organization.objects.filter(memberships__user__keycloak_sub="kc-uuid-1"):
    print(org.name)
```

The schema is owned by Alembic (from the SQLAlchemy adapter). Django's `makemigrations` will not generate migrations for these models.
