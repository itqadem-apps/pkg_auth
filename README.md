# pkg-auth

[![Build Status](https://img.shields.io/actions/workflow/status/OWNER/REPO/ci.yml?branch=main&style=for-the-badge)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pkg-auth?style=for-the-badge)](https://pypi.org/project/pkg-auth/)
[![codecov](https://img.shields.io/codecov/c/github/OWNER/REPO?style=for-the-badge)](https://codecov.io/gh/OWNER/REPO)

Clean-architecture auth core for multiple Python frameworks. This package provides a framework-agnostic auth facade plus first‑class integrations for FastAPI and Strawberry GraphQL.

## Documentation

For detailed documentation, please visit the [GitHub Wiki](https://github.com/OWNER/REPO/wiki).

- [Installation](https://github.com/OWNER/REPO/wiki/Installation)
- [User Guide](https://github.com/OWNER/REPO/wiki/User-Guide)
- [FastAPI Integration](https://github.com/OWNER/REPO/wiki/FastAPI-Integration)
- [Strawberry GraphQL Integration](https://github.com/OWNER/REPO/wiki/Strawberry-GraphQL-Integration)

## Quickstart

```python
from pkg_auth.integrations.fastapi import create_fastapi_auth

# Configure with your Keycloak instance
fastapi_auth = create_fastapi_auth(
    keycloak_base_url="http://localhost:8080",
    realm="my-realm",
    client_id="my-client",
)

# Use in your FastAPI routes
from fastapi import APIRouter, Depends
from pkg_auth import AccessContext

router = APIRouter()

@router.get("/me")
async def me(current_user: AccessContext = Depends(fastapi_auth.get_current_user)):
    return {"email": current_user.email}
```
