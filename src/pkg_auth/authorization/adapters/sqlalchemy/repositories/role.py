"""SQLAlchemy implementation of RoleRepository."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from ....domain.entities import Role
from ....domain.value_objects import (
    OrgId,
    PermissionKey,
    RoleId,
    RoleName,
)
from ..models import PermissionORM, RoleORM


def _to_role(row: RoleORM) -> Role:
    return Role(
        id=RoleId(row.id),
        organization_id=(
            OrgId(row.organization_id) if row.organization_id is not None else None
        ),
        name=RoleName(row.name),
        description=row.description,
        permission_keys=frozenset(p.key for p in row.permissions),
    )


@dataclass(slots=True)
class SqlAlchemyRoleRepository:
    session_factory: async_sessionmaker[AsyncSession]

    async def get(self, role_id: RoleId) -> Role | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(RoleORM)
                    .options(selectinload(RoleORM.permissions))
                    .where(RoleORM.id == int(role_id))
                )
            ).scalar_one_or_none()
            return _to_role(row) if row is not None else None

    async def get_by_name(
        self, org_id: OrgId | None, name: RoleName
    ) -> Role | None:
        async with self.session_factory() as session:
            cond = (
                RoleORM.organization_id.is_(None)
                if org_id is None
                else RoleORM.organization_id == int(org_id)
            )
            row = (
                await session.execute(
                    select(RoleORM)
                    .options(selectinload(RoleORM.permissions))
                    .where(cond, RoleORM.name == str(name))
                )
            ).scalar_one_or_none()
            return _to_role(row) if row is not None else None

    async def create(
        self,
        *,
        org_id: OrgId | None,
        name: RoleName,
        description: str | None,
        permission_keys: Sequence[PermissionKey],
    ) -> Role:
        async with self.session_factory() as session:
            perm_rows: list[PermissionORM] = []
            if permission_keys:
                key_strs = [str(k) for k in permission_keys]
                perm_rows = list(
                    (
                        await session.execute(
                            select(PermissionORM).where(
                                PermissionORM.key.in_(key_strs)
                            )
                        )
                    )
                    .scalars()
                    .all()
                )

            row = RoleORM(
                organization_id=int(org_id) if org_id is not None else None,
                name=str(name),
                description=description,
            )
            row.permissions = perm_rows
            session.add(row)
            await session.commit()
            # Re-load with eager perms so _to_role can read row.permissions
            row = (
                await session.execute(
                    select(RoleORM)
                    .options(selectinload(RoleORM.permissions))
                    .where(RoleORM.id == row.id)
                )
            ).scalar_one()
            return _to_role(row)

    async def update(
        self,
        role_id: RoleId,
        *,
        name: RoleName | None,
        description: str | None,
        permission_keys: Sequence[PermissionKey] | None,
    ) -> Role:
        async with self.session_factory() as session:
            values: dict[str, object] = {}
            if name is not None:
                values["name"] = str(name)
            if description is not None:
                values["description"] = description
            if values:
                await session.execute(
                    update(RoleORM)
                    .where(RoleORM.id == int(role_id))
                    .values(**values)
                )

            if permission_keys is not None:
                row = (
                    await session.execute(
                        select(RoleORM)
                        .options(selectinload(RoleORM.permissions))
                        .where(RoleORM.id == int(role_id))
                    )
                ).scalar_one()
                key_strs = [str(k) for k in permission_keys]
                if key_strs:
                    new_perms = list(
                        (
                            await session.execute(
                                select(PermissionORM).where(
                                    PermissionORM.key.in_(key_strs)
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                else:
                    new_perms = []
                row.permissions = new_perms

            await session.commit()
            row = (
                await session.execute(
                    select(RoleORM)
                    .options(selectinload(RoleORM.permissions))
                    .where(RoleORM.id == int(role_id))
                )
            ).scalar_one()
            return _to_role(row)

    async def delete(self, role_id: RoleId) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(RoleORM).where(RoleORM.id == int(role_id))
            )
            await session.commit()
