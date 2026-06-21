"""Update a role's name, description, or permission set."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ...domain.entities import Role
from ...domain.exceptions import UnknownRole
from ...domain.ports import PermissionCatalogRepository, RoleRepository
from ...domain.value_objects import OrgId, PermissionKey, RoleId, RoleName
from ._helpers import validate_permission_keys_for_role


@dataclass(slots=True)
class UpdateRoleUseCase:
    """Update an existing role.

    Pass ``None`` for any field to leave it unchanged. When
    ``permission_keys`` is provided, every referenced key must already
    exist in the permission catalog.

    Note on cache invalidation: services that wrap their
    ``MembershipRepository`` with ``CachedMembershipRepository`` should
    invalidate the cache prefix after this call returns. The package
    documents the convention but does not auto-invalidate.
    """

    role_repo: RoleRepository
    catalog_repo: PermissionCatalogRepository
    platform_org_id: OrgId | None = None

    async def execute(
        self,
        role_id: RoleId,
        *,
        name: RoleName | None = None,
        description: str | None = None,
        permission_keys: Sequence[PermissionKey] | None = None,
    ) -> Role:
        existing = await self.role_repo.get(role_id)
        if existing is None:
            raise UnknownRole(f"role {role_id} not found")

        if permission_keys is not None:
            await validate_permission_keys_for_role(
                self.catalog_repo,
                permission_keys,
                is_platform_org=self._is_platform_org(existing.organization_id),
            )

        return await self.role_repo.update(
            role_id,
            name=name,
            description=description,
            permission_keys=permission_keys,
        )

    def _is_platform_org(self, org_id: OrgId | None) -> bool | None:
        if org_id is None or self.platform_org_id is None:
            return None
        return org_id == self.platform_org_id
