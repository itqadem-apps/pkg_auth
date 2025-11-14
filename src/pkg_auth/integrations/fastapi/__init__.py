from __future__ import annotations

from .decorators import FastAPIDecorators
from .deps import FastAPIAuthorization
from ..common.auth_factory import create_auth_dependencies_from_keycloak, AuthDependencies


def create_fastapi_auth(
    *,
    keycloak_base_url: str,
    realm: str,
    client_id: str,
    audience: str | None = None,
) -> FastAPIAuthorization:
    """
    High-level helper for FastAPI apps:

    - Creates AuthDependencies from Keycloak config
    - Wraps them in FastAPIAuthorization, exposing dependencies like:

        fastapi_auth.get_current_user
        fastapi_auth.get_optional_user
        fastapi_auth.require_permissions(...)
        fastapi_auth.require_realm_roles(...)
        fastapi_auth.require_client_roles(...)
    """
    auth: AuthDependencies = create_auth_dependencies_from_keycloak(
        keycloak_base_url=keycloak_base_url,
        realm=realm,
        client_id=client_id,
        audience=audience,
    )
    return FastAPIAuthorization(auth=auth)


__all__ = ["FastAPIAuthorization", "FastAPIDecorators", "create_fastapi_auth"]
