# FastAPI Integration

Quickstart using dependency-injection helpers. Token extraction prefers `Authorization: Bearer <token>` and falls back to the `access_token` cookie.

## `app/auth.py`

```python
from pkg_auth.integrations.fastapi import create_fastapi_auth

from app.config import settings

fastapi_auth = create_fastapi_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
)

# Optional dependency aliases
get_current_user = fastapi_auth.get_current_user
get_optional_user = fastapi_auth.get_optional_user
require_permissions = fastapi_auth.require_permissions
require_realm_roles = fastapi_auth.require_realm_roles
require_client_roles = fastapi_auth.require_client_roles
```

## `app/routes.py`

```python
from fastapi import APIRouter, Depends
from pkg_auth import AccessContext
from app.auth import (
  get_current_user,
  get_optional_user,
  require_permissions,
)

router = APIRouter()

@router.get("/me")
async def me(current_user: AccessContext = Depends(get_current_user)):
    return {"email": current_user.email}

@router.get("/articles")
async def list_articles(
    current_user: AccessContext = Depends(require_permissions("articles:read")),
):
    ...

@router.get("/public")
async def public(current_user: AccessContext | None = Depends(get_optional_user)):
    # current_user may be None
    ...
```

## Decorator style (optional)

Same semantics, injected `current_user` argument added to your handler.

### `app/auth.py`

```python
from pkg_auth.integrations.common.auth_factory import create_auth_dependencies_from_keycloak
from pkg_auth.integrations.fastapi import FastAPIDecorators
from app.config import settings

auth_core = create_auth_dependencies_from_keycloak(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
)

authz = FastAPIDecorators(auth=auth_core)  # cookie_name can be customized
```

### `app/routes.py`

```python
from fastapi import APIRouter, Request
from pkg_auth import AccessContext
from app.auth import authz

router = APIRouter()

@router.get("/me")
@authz.authenticated
async def me(request: Request, current_user: AccessContext):
    return {"email": current_user.email}

@router.get("/articles")
@authz.require_permissions("articles:read")
async def list_articles(request: Request, current_user: AccessContext):
    ...

@router.get("/public")
@authz.optional_auth
async def public(request: Request, current_user: AccessContext | None = None):
    ...
```
