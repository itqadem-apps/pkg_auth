from __future__ import annotations

from typing import Optional, Iterable, Any

from .client import KeycloakAdminClient
from .helpers import _ensure_api_client, _ensure_roles, _ensure_frontend_mappers, _remove_frontend_mappers
from .settings import KCAdminSettings


async def provision_keycloak_client(
        *,
        settings: KCAdminSettings,
        client_id: Optional[str] = None,
        permissions: Optional[Iterable[str]] = None,
        frontend_client_ids: Optional[Iterable[str]] = None,
        remove_frontend_client_ids: Optional[Iterable[str]] = None,
        strict_roles: bool = False,
        strict_audience: bool = False,
) -> dict[str, Any]:
    """
    High-level async helper to provision a Keycloak API client.

    Steps:
      1) Ensure the API client exists (bearer-only).
      2) Ensure client roles correspond to the provided permissions.
      3) Ensure audience + roles mappers on frontend clients.
      4) Optionally remove mappers for some frontend clients (strict mode).

    This is the refactored version of your old `provision(...)` function.

    Returns a summary dictionary with:
      - client
      - roles
      - audience
      - client_roles_mapper
      - removed
    """
    api_client_id = (client_id or settings.default_api_client_id).strip()
    desired_permissions = list(permissions or [])

    fe_ids = list(frontend_client_ids or settings.frontend_client_ids)
    remove_fe_ids = list(remove_frontend_client_ids or [])

    kc = KeycloakAdminClient(settings=settings)
    try:
        # 1) Ensure API client exists
        client_repr, internal_api_id = await _ensure_api_client(
            kc,
            api_client_id=api_client_id,
        )

        # 2) Ensure roles
        roles_summary = await _ensure_roles(
            kc,
            internal_id=internal_api_id,
            permissions=desired_permissions,
            strict_roles=strict_roles,
        )

        # 3) Ensure audience + roles mappers for frontend clients
        audience_actions, roles_mapper_actions = await _ensure_frontend_mappers(
            kc,
            api_client_id=api_client_id,
            internal_api_id=internal_api_id,
            frontend_client_ids=fe_ids,
            strict_audience=strict_audience,
        )

        # 4) Optionally remove mappers for remove_frontend_client_ids
        removed = []
        if strict_audience and remove_fe_ids:
            removed = await _remove_frontend_mappers(
                kc,
                api_client_id=api_client_id,
                remove_frontend_client_ids=remove_fe_ids,
            )

        return {
            "client": client_repr,
            "roles": roles_summary,
            "audience": audience_actions,
            "client_roles_mapper": roles_mapper_actions,
            "removed": removed,
        }
    finally:
        await kc.close()
