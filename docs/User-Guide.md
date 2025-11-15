# User Guide

This guide provides an overview of how to use `pkg-auth` to secure your applications.

## Key Concepts

- **Access Token**: A JSON Web Token (JWT) that contains information about the authenticated user and their permissions.
- **Access Context**: A Pydantic model that represents the claims in the access token.
- **Permissions**: A set of strings that define what actions a user is allowed to perform.
- **Realm Roles**: A set of strings that define the user's roles within a Keycloak realm.
- **Client Roles**: A set of strings that define the user's roles within a Keycloak client.

## Getting Started

To get started with `pkg-auth`, you'll need to configure it with your Keycloak instance. This is done using the `create_auth_dependencies_from_keycloak` function, which returns an `AuthDependencies` object.

```python
from pkg_auth.integrations.common.auth_factory import create_auth_dependencies_from_keycloak

auth_deps = create_auth_dependencies_from_keycloak(
    keycloak_base_url="http://localhost:8080",
    realm="my-realm",
    client_id="my-client",
)
```

The `create_auth_dependencies_from_keycloak` function takes the following arguments:

- `keycloak_base_url`: The base URL of your Keycloak instance.
- `realm`: The name of the Keycloak realm to use.
- `client_id`: The ID of the Keycloak client to use.
- `audience`: The audience of the JWT. If not provided, the `client_id` is used.

## The `AuthDependencies` Object

The `AuthDependencies` object provides a framework-agnostic facade for handling authentication and authorization. It has the following methods:

- `authenticate(token: str) -> AccessContext`: Decodes and validates a JWT, returning an `AccessContext` object.
- `authorize(context: AccessContext, requirements: Iterable[AccessRequirement]) -> AccessContext`: Checks if an `AccessContext` meets a set of access requirements.

It also provides the following helper methods for creating `AccessRequirement` objects:

- `require_permissions(any_of: Sequence[str] = (), all_of: Sequence[str] = ()) -> AccessRequirement`
- `require_realm_roles(any_of: Sequence[str] = (), all_of: Sequence[str] = ()) -> AccessRequirement`
- `require_client_roles(any_of: Sequence[str] = (), all_of: Sequence[str] = ()) -> AccessRequirement`

## Example Usage

Here's an example of how to use the `AuthDependencies` object to secure a route:

```python
from fastapi import APIRouter, Depends, HTTPException
from pkg_auth import AccessContext
from pkg_auth.integrations.common.auth_factory import create_auth_dependencies_from_keycloak

auth_deps = create_auth_dependencies_from_keycloak(
    keycloak_base_url="http://localhost:8080",
    realm="my-realm",
    client_id="my-client",
)

router = APIRouter()

def get_current_user(token: str) -> AccessContext:
    try:
        return auth_deps.authenticate(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@router.get("/me")
async def me(current_user: AccessContext = Depends(get_current_user)):
    return {"email": current_user.email}

@router.get("/articles")
async def list_articles(current_user: AccessContext = Depends(get_current_user)):
    auth_deps.authorize(
        current_user,
        [auth_deps.require_permissions(all_of=["articles:read"])]
    )
    # ...
```
