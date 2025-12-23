# Django Integration

This package is framework-agnostic at its core. The Django integration is a thin adapter that:

- Extracts tokens from Django `HttpRequest` (Authorization header or cookie)
- Authenticates tokens into an `AccessContext`
- Provides decorators for authentication + authorization
- (Optional) middleware to attach `request.access_context`

## Installation

```bash
pip install "pkg-auth[django]"
```

## Configuration

Add these to your Django settings (via env or settings module):

- `KEYCLOAK_BASE_URL` (example: `https://auth.example.com`)
- `KEYCLOAK_REALM` (example: `my-realm`)
- `KEYCLOAK_CLIENT_ID` (example: `my-service-client`)
- Optional: `KEYCLOAK_AUDIENCE` (defaults to `KEYCLOAK_CLIENT_ID`)
- Optional: `PKG_AUTH_COOKIE_NAME` (defaults to `access_token`)

## Usage (decorators)

Create a shared auth instance:

```python
from django.conf import settings
from pkg_auth.integrations.django import create_django_auth

authz = create_django_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    audience=getattr(settings, "KEYCLOAK_AUDIENCE", None),
)
```

Use it to guard views:

```python
from django.http import JsonResponse

@authz.require_auth()
def me(request):
    ctx = request.access_context
    return JsonResponse({"email": str(ctx.identity.email) if ctx.identity.email else None})

@authz.require_permissions("users:read")
def users(request):
    return JsonResponse({"ok": True})
```

## Usage (optional middleware)

If you want `request.access_context` to be set automatically (authenticated when possible, otherwise `None`),
add the middleware:

```python
MIDDLEWARE = [
    # ...
    "pkg_auth.integrations.django.PkgAuthMiddleware",
]
```

Then in your views you can check:

```python
def health(request):
    if request.access_context is None:
        return JsonResponse({"user": None})
    return JsonResponse({"user": request.access_context.identity.preferred_username})
```

## Strawberry GraphQL in Django

Install Strawberry Django in your service:

```bash
pip install "strawberry-graphql[django]"
```

Create a shared `StrawberryAuth` instance:

```python
from django.conf import settings
from pkg_auth.integrations.strawberry import create_strawberry_auth

strawberry_auth = create_strawberry_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    audience=getattr(settings, "KEYCLOAK_AUDIENCE", None),
)
```

Wire it into Strawberry Django views by overriding `get_context`:

```python
import strawberry
from strawberry.django.views import GraphQLView

schema = strawberry.Schema(query=Query)
context_getter = strawberry_auth.make_django_context_getter(optional=True)

class AuthedGraphQLView(GraphQLView):
    def get_context(self, request, response):
        return context_getter(request, response)
```

Then use pkg_auth permissions in your schema:

```python
from strawberry.types import Info

RequireAuth = strawberry_auth.require_authenticated()
RequireUsersRead = strawberry_auth.require_permissions(["users:read"])

@strawberry.type
class Query:
    @strawberry.field(permission_classes=[RequireAuth])
    def me(self, info: Info) -> str:
        return info.context.user.identity.preferred_username

    @strawberry.field(permission_classes=[RequireUsersRead])
    def users(self, info: Info) -> list[str]:
        return ["..."]
```
