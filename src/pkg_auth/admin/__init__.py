"""
pkg_auth.admin.keycloak

Async Keycloak admin utilities:

- KCAdminSettings: configuration for Keycloak admin connection.
- KeycloakAdminClient: minimal async admin client (httpx-based).
- provision_keycloak_client: high-level async helper to:
    * ensure API client exists (bearer-only)
    * ensure client roles match your permission list
    * ensure audience + roles mappers on frontend clients
- settings_from_env / ensure_keycloak_client_from_env:
    convenience wrappers for env-driven CLI / initContainers.
"""

from __future__ import annotations

from .client import KeycloakAdminClient
from .env import settings_from_env, ensure_keycloak_client_from_env
from .helpers import (
    _ensure_api_client,
    _ensure_roles,
    _ensure_frontend_mappers,
    _remove_frontend_mappers,
)
from .provision_client import provision_keycloak_client
from .settings import KCAdminSettings

__all__ = [
    "KCAdminSettings",
    "KeycloakAdminClient",
    "settings_from_env",
    "ensure_keycloak_client_from_env",
    "provision_keycloak_client"
]
