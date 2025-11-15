from __future__ import annotations

from typing import Any

from .client import KeycloakAdminClient


async def _ensure_api_client(
    kc: KeycloakAdminClient,
    *,
    api_client_id: str,
) -> tuple[dict[str, Any], str]:
    client_repr = {
        "clientId": api_client_id,
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "enabled": True,
    }
    ensured = await kc.ensure_client(client_repr)

    server_obj = await kc.get_client_by_client_id(api_client_id)
    if not server_obj:
        raise RuntimeError("Client ensure failed unexpectedly: cannot read back the client")

    return ensured, server_obj["id"]  # (trimmed, internal_id)


async def _ensure_roles(
    kc: KeycloakAdminClient,
    *,
    internal_id: str,
    permissions: list[str],
    strict_roles: bool,
) -> dict[str, int]:
    if strict_roles:
        return await kc.ensure_client_roles_strict(internal_id, permissions)
    return await kc.ensure_client_roles(internal_id, permissions)


async def _ensure_frontend_mappers(
    kc: KeycloakAdminClient,
    *,
    api_client_id: str,
    internal_api_id: str,
    frontend_client_ids: list[str],
    strict_audience: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    audience_actions: list[dict[str, Any]] = []
    roles_mapper_actions: list[dict[str, Any]] = []

    for fe_client_id in frontend_client_ids:
        fe = await kc.get_client_by_client_id(fe_client_id)
        if not fe:
            msg = f"frontend client not found in realm {kc.s.keycloak_realm}"
            audience_actions.append(
                {"frontend_client": fe_client_id, "created": False, "updated": False, "error": msg}
            )
            roles_mapper_actions.append(
                {"frontend_client": fe_client_id, "created": False, "updated": False, "error": msg}
            )
            continue

        res_aud = await kc.ensure_audience_mapper(
            fe["id"],
            api_client_id,
            update_if_different=strict_audience,
        )
        audience_actions.append({"frontend_client": fe_client_id, **res_aud})

        res_roles = await kc.ensure_client_roles_mapper(
            fe["id"],
            api_client_id,
            update_if_different=strict_audience,
        )
        roles_mapper_actions.append({"frontend_client": fe_client_id, **res_roles})

    return audience_actions, roles_mapper_actions


async def _remove_frontend_mappers(
    kc: KeycloakAdminClient,
    *,
    api_client_id: str,
    remove_frontend_client_ids: list[str],
) -> list[dict[str, Any]]:
    removed: list[dict[str, Any]] = []
    for fe_client_id in remove_frontend_client_ids:
        fe = await kc.get_client_by_client_id(fe_client_id)
        if not fe:
            removed.append(
                {
                    "frontend_client": fe_client_id,
                    "audience_removed": False,
                    "roles_mapper_removed": False,
                    "error": f"frontend client not found in realm {kc.s.keycloak_realm}",
                }
            )
            continue
        did_aud = await kc.remove_audience_mapper(fe["id"], api_client_id)
        did_roles = await kc.remove_client_roles_mapper(fe["id"], api_client_id)
        removed.append(
            {
                "frontend_client": fe_client_id,
                "audience_removed": did_aud,
                "roles_mapper_removed": did_roles,
            }
        )
    return removed
