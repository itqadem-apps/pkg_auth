# FastAPI Integration

## Setup

```python
from pkg_auth.integrations.fastapi import (
    create_authentication,
    make_get_auth_context,
    require_permission,
    install_exception_handlers,
)

# 1. Identity (Keycloak JWT)
auth = create_authentication(
    keycloak_base_url="https://auth.example.com",
    realm="itqadem",
    audience="courses-service",
)

# 2. Authorization context (composes identity + ACL lookup)
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    sync_user_use_case=sync_user,
    resolve_use_case=resolve,
    organization_repo=org_repo,
    header_name="X-Organization-Id",  # default
)

# 3. Exception handlers (optional — makes domain errors map to HTTP)
install_exception_handlers(app)
```

## Protecting routes

### Via `require_permission`

```python
@router.get("/courses/{id}")
async def get_course(
    id: str,
    bundle: tuple[IdentityContext, AuthContext] = Depends(
        require_permission("course:view", get_auth_context=get_auth_context)
    ),
):
    identity, auth_ctx = bundle
    ...
```

### Via route-level dependencies

```python
@router.delete(
    "/courses/{id}",
    dependencies=[Depends(require_permission("course:delete", get_auth_context=get_auth_context))],
)
async def delete_course(id: str):
    ...
```

## Error mapping

| Condition | Status |
|---|---|
| No/invalid token | 401 |
| Missing `X-Organization-Id` | 400 |
| User not a member | 403 |
| Permission missing | 403 |
| Unknown org | 404 |

## Reference example

See [`examples/itqadem_courses_app`](../examples/itqadem_courses_app) for the full wiring.
