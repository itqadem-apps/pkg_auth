"""SQLAlchemy implementation of PermissionCatalogRepository (UUID PKs, injectable model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ....application.use_cases.register_permission_catalog import CatalogEntry
from ....domain.entities import Permission
from ....domain.ports import PermissionScope
from ....domain.value_objects import PermissionId, PermissionKey
from ..models import PermissionORM as DefaultPermissionORM


def _to_permission(row: Any) -> Permission:
    return Permission(
        id=PermissionId(row.id),
        key=PermissionKey(row.key),
        service_name=row.service_name,
        description=row.description,
        is_platform=bool(row.is_platform),
    )


def _scope_clause(model: type, scope: PermissionScope):
    if scope == "org":
        return model.is_platform.is_(False)
    if scope == "platform":
        return model.is_platform.is_(True)
    return None


@dataclass(slots=True)
class SqlAlchemyPermissionCatalogRepository:
    session_factory: async_sessionmaker[AsyncSession]
    model: type = field(default=DefaultPermissionORM)

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntry],
    ) -> None:
        if not entries:
            return
        rows = [
            {
                "key": str(entry.key),
                "service_name": service_name,
                "description": entry.description,
                "is_platform": entry.is_platform,
            }
            for entry in entries
        ]
        stmt = pg_insert(self.model).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["key"],
            set_={
                "service_name": stmt.excluded.service_name,
                "description": stmt.excluded.description,
                "is_platform": stmt.excluded.is_platform,
            },
        )
        async with self.session_factory() as session:
            await session.execute(stmt)
            await session.commit()

    async def list_all(
        self, *, scope: PermissionScope = "all"
    ) -> list[Permission]:
        async with self.session_factory() as session:
            stmt = select(self.model).order_by(self.model.id)
            clause = _scope_clause(self.model, scope)
            if clause is not None:
                stmt = stmt.where(clause)
            rows = (await session.execute(stmt)).scalars().all()
            return [_to_permission(r) for r in rows]

    async def list_for_service(
        self, service_name: str, *, scope: PermissionScope = "all"
    ) -> list[Permission]:
        async with self.session_factory() as session:
            stmt = (
                select(self.model)
                .where(self.model.service_name == service_name)
                .order_by(self.model.id)
            )
            clause = _scope_clause(self.model, scope)
            if clause is not None:
                stmt = stmt.where(clause)
            rows = (await session.execute(stmt)).scalars().all()
            return [_to_permission(r) for r in rows]

    async def prune_absent(
        self,
        *,
        service_name: str,
        keep_keys: Iterable[PermissionKey],
    ) -> int:
        keys = [str(k) for k in keep_keys]
        stmt = delete(self.model).where(self.model.service_name == service_name)
        if keys:
            stmt = stmt.where(self.model.key.notin_(keys))
        async with self.session_factory() as session:
            result = await session.execute(stmt)
            await session.commit()
            return int(result.rowcount or 0)
