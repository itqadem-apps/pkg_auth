"""SQLAlchemy implementation of PermissionCatalogRepository (UUID PKs, injectable model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy import func, select, update
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
                "deleted_at": None,
            },
        )
        async with self.session_factory() as session:
            await session.execute(stmt)
            await session.commit()

    async def apply_snapshot(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntry],
    ) -> None:
        """Upsert ``entries`` and soft-delete any other keys for ``service_name``.

        The NATS subscriber calls this on every catalog message. Keys
        absent from the snapshot are stamped with ``deleted_at``;
        re-appearing keys have ``deleted_at`` cleared by
        :meth:`register_many`'s ``ON CONFLICT`` clause.
        """
        async with self.session_factory() as session:
            if entries:
                rows = [
                    {
                        "key": str(entry.key),
                        "service_name": service_name,
                        "description": entry.description,
                        "is_platform": entry.is_platform,
                    }
                    for entry in entries
                ]
                upsert_stmt = pg_insert(self.model).values(rows)
                upsert_stmt = upsert_stmt.on_conflict_do_update(
                    index_elements=["key"],
                    set_={
                        "service_name": upsert_stmt.excluded.service_name,
                        "description": upsert_stmt.excluded.description,
                        "is_platform": upsert_stmt.excluded.is_platform,
                        "deleted_at": None,
                    },
                )
                await session.execute(upsert_stmt)

            present_keys = [str(entry.key) for entry in entries]
            soft_delete_stmt = (
                update(self.model)
                .where(self.model.service_name == service_name)
                .where(self.model.deleted_at.is_(None))
                .where(self.model.key.notin_(present_keys))
                .values(deleted_at=func.now())
            )
            await session.execute(soft_delete_stmt)
            await session.commit()

    async def list_all(
        self, *, scope: PermissionScope = "all"
    ) -> list[Permission]:
        async with self.session_factory() as session:
            stmt = (
                select(self.model)
                .where(self.model.deleted_at.is_(None))
                .order_by(self.model.id)
            )
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
                .where(self.model.deleted_at.is_(None))
                .order_by(self.model.id)
            )
            clause = _scope_clause(self.model, scope)
            if clause is not None:
                stmt = stmt.where(clause)
            rows = (await session.execute(stmt)).scalars().all()
            return [_to_permission(r) for r in rows]
