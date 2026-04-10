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
from ._helpers import validate_permission_keys_exist


@dataclass(slots=True)
class CreateRoleUseCase:
    """Create a new role under an organization (or as a global template).

    Validates:
        - the organization exists (when ``org_id`` is not ``None``)
        - every referenced permission key is registered in the catalog
    """

    organization_repo: OrganizationRepository
    role_repo: RoleRepository
    catalog_repo: PermissionCatalogRepository

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

        await validate_permission_keys_exist(self.catalog_repo, permission_keys)

        return await self.role_repo.create(
            org_id=org_id,
            name=name,
            description=description,
            permission_keys=permission_keys,
        )
