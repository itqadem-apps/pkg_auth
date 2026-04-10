"""SQLAlchemy implementation of PermissionCatalogRepository."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ....domain.entities import Permission
from ....domain.value_objects import PermissionId, PermissionKey
from ..models import PermissionORM


def _to_permission(row: PermissionORM) -> Permission:
    return Permission(
        id=PermissionId(row.id),
        key=PermissionKey(row.key),
        service_name=row.service_name,
        description=row.description,
    )


@dataclass(slots=True)
class SqlAlchemyPermissionCatalogRepository:
    session_factory: async_sessionmaker[AsyncSession]

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[tuple[PermissionKey, str | None]],
    ) -> None:
        if not entries:
            return
        rows = [
            {
                "key": str(key),
                "service_name": service_name,
                "description": description,
            }
            for key, description in entries
        ]
        stmt = pg_insert(PermissionORM).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["key"],
            set_={
                "service_name": stmt.excluded.service_name,
                "description": stmt.excluded.description,
            },
        )
        async with self.session_factory() as session:
            await session.execute(stmt)
            await session.commit()

    async def list_all(self) -> list[Permission]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(select(PermissionORM).order_by(PermissionORM.id))
            ).scalars().all()
            return [_to_permission(r) for r in rows]

    async def list_for_service(self, service_name: str) -> list[Permission]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(
                    select(PermissionORM)
                    .where(PermissionORM.service_name == service_name)
                    .order_by(PermissionORM.id)
                )
            ).scalars().all()
            return [_to_permission(r) for r in rows]
