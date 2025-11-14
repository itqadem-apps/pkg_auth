```python
# app/graphql.py

import strawberry
from strawberry.fastapi import GraphQLRouter
from pkg_auth.integrations.strawberry import (
    create_strawberry_auth,
    StrawberryAuthContext,
)
from app.config import settings

# 1) Build auth facade from Keycloak config
strawberry_auth = create_strawberry_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    # cookie_name="access_token",  # optional override
)

# 2) Schema
@strawberry.type
class Query:
    @strawberry.field
    def hello(self, info) -> str:
        ctx: StrawberryAuthContext = info.context
        if ctx.user:
            return f"Hello, {ctx.user.email}"
        return "Hello, anonymous"


schema = strawberry.Schema(query=Query)

# 3) Router with context_getter
graphql_router = GraphQLRouter(
    schema,
    context_getter=strawberry_auth.make_context_getter(optional=True),
)

```


```python
# app/graphql_schema.py

import strawberry
from strawberry.types import Info
from pkg_auth.integrations.strawberry import StrawberryAuthContext
from app.graphql import strawberry_auth  # from previous snippet

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
        # ctx.user is guaranteed not None and has "articles:read" permission
        ...

```