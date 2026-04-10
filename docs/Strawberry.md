# Strawberry GraphQL Integration

## Setup

```python
from pkg_auth.integrations.strawberry import (
    make_context_getter, IsAuthenticated, RequirePermission,
)

context_getter = make_context_getter(
    authenticate_use_case=authenticate_uc,
    sync_user_use_case=sync_user_uc,
    resolve_use_case=resolve_uc,
    organization_repo=org_repo,
)

schema = strawberry.Schema(query=Query)
graphql_app = GraphQLRouter(schema, context_getter=context_getter)
```

## Permission classes

```python
@strawberry.type
class Query:
    @strawberry.field(permission_classes=[IsAuthenticated])
    async def me(self, info: Info) -> str:
        return info.context.identity.subject_str

    @strawberry.field(permission_classes=[RequirePermission("course:view")])
    async def course(self, id: strawberry.ID, info: Info) -> Course:
        ...
```

## Context object

Every resolver receives a `StrawberryContext` via `info.context`:

```python
@dataclass
class StrawberryContext:
    request: Request
    identity: IdentityContext | None
    auth_context: AuthContext | None
    extra: dict[str, object]
```

- `identity` is `None` when no valid JWT is present.
- `auth_context` is `None` when `X-Organization-Id` header is missing or the user isn't a member.
- The context getter is permissive (no exceptions raised) — permission classes decide what to reject.
