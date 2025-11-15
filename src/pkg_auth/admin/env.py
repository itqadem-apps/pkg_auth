from __future__ import annotations

import asyncio
import os
from typing import Optional, Any

from .settings import KCAdminSettings
from . import provision_keycloak_client


def settings_from_env() -> KCAdminSettings:
    def _bool(key: str, default: bool = True) -> bool:
        raw = os.getenv(key)
        if raw is None:
            return default
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _split_csv(key: str) -> list[str]:
        raw = os.getenv(key)
        if not raw:
            return []
        return [x.strip() for x in raw.split(",") if x and x.strip()]

    base_url = os.getenv("KEYCLOAK_BASE_URL")
    realm = os.getenv("KEYCLOAK_REALM")
    admin_user = os.getenv("KEYCLOAK_ADMIN_USER")
    admin_pass = os.getenv("KEYCLOAK_ADMIN_PASS")
    if not all([base_url, realm, admin_user, admin_pass]):
        missing = [
            n
            for n, v in [
                ("KEYCLOAK_BASE_URL", base_url),
                ("KEYCLOAK_REALM", realm),
                ("KEYCLOAK_ADMIN_USER", admin_user),
                ("KEYCLOAK_ADMIN_PASS", admin_pass),
            ]
            if not v
        ]
        raise RuntimeError(f"Missing Keycloak admin settings: {', '.join(missing)}")

    return KCAdminSettings(
        keycloak_base_url=base_url,
        keycloak_realm=realm,
        keycloak_admin_user=admin_user,
        keycloak_admin_pass=admin_pass,
        verify_ssl=_bool("VERIFY_SSL", True),
        app_name=os.getenv("APP_NAME"),
        service_name=os.getenv("SERVICE_NAME"),
        frontend_client_ids=_split_csv("KEYCLOAK_FRONTEND_CLIENT_IDS"),
    )


def ensure_keycloak_client_from_env(
    *,
    strict_roles: bool = False,
    strict_audience: bool = False,
    client_id: Optional[str] = None,
    permissions: Optional[list[str]] = None,
    frontend_client_ids: Optional[list[str]] = None,
    remove_frontend_client_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Convenience sync wrapper using env-configured settings."""
    settings = settings_from_env()
    return asyncio.run(
        provision_keycloak_client(
            settings=settings,
            client_id=client_id,
            permissions=permissions,
            frontend_client_ids=frontend_client_ids,
            remove_frontend_client_ids=remove_frontend_client_ids,
            strict_roles=strict_roles,
            strict_audience=strict_audience,
        )
    )
