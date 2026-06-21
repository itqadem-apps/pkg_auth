"""Create a role with a set of permissions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ...domain.entities import Role
from ...domain.exceptions import UnknownOrganization
from ...domain.ports import (
    OrganizationRepository,
    PermissionCatalogRepository,
    RoleRepository,
)
from ...domain.value_objects import OrgId, PermissionKey, RoleName
from ._helpers import validate_permission_keys_for_role


@dataclass(slots=True)
class CreateRoleUseCase:
    """Create a new role under an organization (or as a global template).

    Validates:
        - the organization exists (when ``org_id`` is not ``None``)
        - every referenced permission key is registered in the catalog
        - permission visibility matches the role's org (when
          ``platform_org_id`` is configured): a platform-org role may not use
          ``tenant_only`` perms; a normal-org role may not use
          ``platform_only`` perms.
    """

    organization_repo: OrganizationRepository
    role_repo: RoleRepository
    catalog_repo: PermissionCatalogRepository
    platform_org_id: OrgId | None = None

    async def execute(
        self,
        *,
        org_id: OrgId | None,
        name: RoleName,
        description: str | None,
        permission_keys: Sequence[PermissionKey],
    ) -> Role:
        if org_id is not None:
            if await self.organization_repo.get(org_id) is None:
                raise UnknownOrganization(f"organization {org_id} not found")

        await validate_permission_keys_for_role(
            self.catalog_repo,
            permission_keys,
            is_platform_org=self._is_platform_org(org_id),
        )

        return await self.role_repo.create(
            org_id=org_id,
            name=name,
            description=description,
            permission_keys=permission_keys,
        )

    def _is_platform_org(self, org_id: OrgId | None) -> bool | None:
        """``True``/``False`` when visibility should be enforced, else ``None``.

        Returns ``None`` for global templates (org_id is None) or when no
        platform org is configured, so only existence is checked.
        """
        if org_id is None or self.platform_org_id is None:
            return None
        return org_id == self.platform_org_id
