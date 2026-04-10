"""Django ORM implementation of RoleRepository."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from ....domain.entities import Role as DomainRole
from ....domain.value_objects import (
    OrgId,
    PermissionKey,
    RoleId,
    RoleName,
)
from ..models import Permission as PermissionModel, Role as RoleModel


async def _role_to_domain(row: RoleModel) -> DomainRole:
    perm_keys = [k async for k in row.permissions.all().values_list("key", flat=True)]
    return DomainRole(
        id=RoleId(row.id),
        organization_id=OrgId(row.organization_id) if row.organization_id else None,
        name=RoleName(row.name),
        description=row.description,
        permission_keys=frozenset(perm_keys),
    )


@dataclass(slots=True)
class DjangoRoleRepository:
    async def get(self, role_id: RoleId) -> DomainRole | None:
        try:
            row = await RoleModel.objects.aget(id=int(role_id))
        except RoleModel.DoesNotExist:
            return None
        return await _role_to_domain(row)

    async def get_by_name(
        self, org_id: OrgId | None, name: RoleName
    ) -> DomainRole | None:
        qs = RoleModel.objects.filter(name=str(name))
        qs = (
            qs.filter(organization__isnull=True)
            if org_id is None
            else qs.filter(organization_id=int(org_id))
        )
        try:
            row = await qs.aget()
        except RoleModel.DoesNotExist:
            return None
        return await _role_to_domain(row)

    async def create(
        self,
        *,
        org_id: OrgId | None,
        name: RoleName,
        description: str | None,
        permission_keys: Sequence[PermissionKey],
    ) -> DomainRole:
        now = datetime.now(timezone.utc)
        row = await RoleModel.objects.acreate(
            organization_id=int(org_id) if org_id is not None else None,
            name=str(name),
            description=description,
            created_at=now,
            updated_at=now,
        )
        if permission_keys:
            key_strs = [str(k) for k in permission_keys]
            perm_ids = [
                pid
                async for pid in PermissionModel.objects.filter(
                    key__in=key_strs
                ).values_list("id", flat=True)
            ]
            await row.permissions.aset(perm_ids)
        return await _role_to_domain(row)

    async def update(
        self,
        role_id: RoleId,
        *,
        name: RoleName | None,
        description: str | None,
        permission_keys: Sequence[PermissionKey] | None,
    ) -> DomainRole:
        row = await RoleModel.objects.aget(id=int(role_id))
        update_fields: list[str] = []
        if name is not None:
            row.name = str(name)
            update_fields.append("name")
        if description is not None:
            row.description = description
            update_fields.append("description")
        if update_fields:
            row.updated_at = datetime.now(timezone.utc)
            update_fields.append("updated_at")
            await row.asave(update_fields=update_fields)

        if permission_keys is not None:
            key_strs = [str(k) for k in permission_keys]
            perm_ids = [
                pid
                async for pid in PermissionModel.objects.filter(
                    key__in=key_strs
                ).values_list("id", flat=True)
            ]
            await row.permissions.aset(perm_ids)

        return await _role_to_domain(row)

    async def delete(self, role_id: RoleId) -> None:
        await RoleModel.objects.filter(id=int(role_id)).adelete()
