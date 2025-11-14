pkg-auth

Clean-architecture auth core for multiple Python frameworks. This package provides a framework-agnostic auth facade plus first‑class integrations for FastAPI and Strawberry GraphQL.

Install from GitHub (no PyPI):

pip install "pkg-auth @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"

Extras (FastAPI / Strawberry):

pip install "pkg-auth[fastapi] @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"
pip install "pkg-auth[strawberry] @ git+https://github.com/OWNER/REPO.git@pkg_auth-vX.Y.Z"

Replace OWNER/REPO and X.Y.Z with your repository and the package tag (e.g. pkg_auth-v0.2.0).

Monorepo note: if the package lives in a subdirectory, append
`#subdirectory=path/to/pkg` to the URL.


FastAPI
--------

Quickstart using dependency-injection helpers. Token extraction prefers `Authorization: Bearer <token>` and falls back to the `access_token` cookie.

app/auth.py

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


app/routes.py

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


Decorator style (optional). Same semantics, injected `current_user` argument added to your handler.

app/auth.py

from pkg_auth.integrations.common.auth_factory import create_auth_dependencies_from_keycloak
from pkg_auth.integrations.fastapi import FastAPIDecorators
from app.config import settings

auth_core = create_auth_dependencies_from_keycloak(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
)

authz = FastAPIDecorators(auth=auth_core)  # cookie_name can be customized


app/routes.py

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


Strawberry GraphQL
------------------

Context getter and permission classes for Strawberry. Token extraction prefers `Authorization: Bearer <token>` and falls back to the `access_token` cookie.

app/graphql.py

import strawberry
from strawberry.fastapi import GraphQLRouter
from pkg_auth.integrations.strawberry import (
    create_strawberry_auth,
    StrawberryAuthContext,
)
from app.config import settings

strawberry_auth = create_strawberry_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    # cookie_name="access_token",  # optional override
)

@strawberry.type
class Query:
    @strawberry.field
    def hello(self, info) -> str:
        ctx: StrawberryAuthContext = info.context
        return f"Hello, {ctx.user.email}" if ctx.user else "Hello, anonymous"

schema = strawberry.Schema(query=Query)

graphql_router = GraphQLRouter(
    schema,
    context_getter=strawberry_auth.make_context_getter(optional=True),
)


Attach permissions to fields:

import strawberry
from strawberry.types import Info
from pkg_auth.integrations.strawberry import StrawberryAuthContext
from app.graphql import strawberry_auth

RequireAuthenticated = strawberry_auth.require_authenticated()
RequireArticlesRead = strawberry_auth.require_permissions(["articles:read"])

@strawberry.type
class Article:
    id: str
    title: str

@strawberry.type
class Query:
    @strawberry.field(permission_classes=[RequireAuthenticated, RequireArticlesRead])
    def articles(self, info: Info) -> list[Article]:
        ctx: StrawberryAuthContext = info.context
        # ctx.user is guaranteed and has "articles:read"
        ...


Notes
-----

- Token source: `Authorization: Bearer <token>` header, then `access_token` cookie.
- Keycloak helper: both integrations use the shared factory `create_auth_dependencies_from_keycloak(...)` under the hood.
- Extras: install with `[fastapi]` or `[strawberry]` to pull optional deps.
