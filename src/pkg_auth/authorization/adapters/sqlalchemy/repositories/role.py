"""SQLAlchemy implementation of RoleRepository (UUID PKs, injectable model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

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
from ..models import PermissionORM as DefaultPermissionORM
from ..models import RoleORM as DefaultRoleORM


def _to_role(row: Any) -> Role:
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
    model: type = field(default=DefaultRoleORM)
    permission_model: type = field(default=DefaultPermissionORM)

    async def get(self, role_id: RoleId) -> Role | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(self.model)
                    .options(selectinload(self.model.permissions))
                    .where(self.model.id == role_id.value)
                )
            ).scalar_one_or_none()
            return _to_role(row) if row is not None else None

    async def get_by_name(
        self, org_id: OrgId | None, name: RoleName
    ) -> Role | None:
        async with self.session_factory() as session:
            cond = (
                self.model.organization_id.is_(None)
                if org_id is None
                else self.model.organization_id == org_id.value
            )
            row = (
                await session.execute(
                    select(self.model)
                    .options(selectinload(self.model.permissions))
                    .where(cond, self.model.name == str(name))
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
            perm_rows: list[Any] = []
            if permission_keys:
                key_strs = [str(k) for k in permission_keys]
                perm_rows = list(
                    (
                        await session.execute(
                            select(self.permission_model).where(
                                self.permission_model.key.in_(key_strs)
                            )
                        )
                    )
                    .scalars()
                    .all()
                )

            row = self.model(
                organization_id=org_id.value if org_id is not None else None,
                name=str(name),
                description=description,
            )
            row.permissions = perm_rows
            session.add(row)
            await session.commit()
            row = (
                await session.execute(
                    select(self.model)
                    .options(selectinload(self.model.permissions))
                    .where(self.model.id == row.id)
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
                    update(self.model)
                    .where(self.model.id == role_id.value)
                    .values(**values)
                )

            if permission_keys is not None:
                row = (
                    await session.execute(
                        select(self.model)
                        .options(selectinload(self.model.permissions))
                        .where(self.model.id == role_id.value)
                    )
                ).scalar_one()
                key_strs = [str(k) for k in permission_keys]
                if key_strs:
                    new_perms = list(
                        (
                            await session.execute(
                                select(self.permission_model).where(
                                    self.permission_model.key.in_(key_strs)
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
                    select(self.model)
                    .options(selectinload(self.model.permissions))
                    .where(self.model.id == role_id.value)
                )
            ).scalar_one()
            return _to_role(row)

    async def delete(self, role_id: RoleId) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(self.model).where(self.model.id == role_id.value)
            )
            await session.commit()
