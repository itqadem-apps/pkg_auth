from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass(slots=True)
class KCAdminSettings:
    """
    Keycloak admin connection + wiring settings.

    Host code decides how to construct this (env, config file, etc.).
    """
    keycloak_base_url: str
    keycloak_admin_user: str
    keycloak_admin_pass: str
    keycloak_realm: str
    verify_ssl: bool = True

    # Service naming / wiring
    app_name: Optional[str] = None
    service_name: Optional[str] = None
    frontend_client_ids: List[str] = field(default_factory=list)

    @property
    def base_url_slash(self) -> str:
        b = self.keycloak_base_url.strip()
        return b if b.endswith("/") else b + "/"

    @property
    def default_api_client_id(self) -> str:
        name = (self.app_name or self.service_name or "service").strip()
        return f"{name}-api"
