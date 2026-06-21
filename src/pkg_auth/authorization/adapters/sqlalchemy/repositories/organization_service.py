"""SQLAlchemy implementation of OrganizationServiceRepository."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ....domain.entities import OrganizationService
from ....domain.value_objects import OrgId, ServiceName
from ..models import OrganizationServiceORM as DefaultOrganizationServiceORM


def _to_entitlement(row: Any) -> OrganizationService:
    return OrganizationService(
        organization_id=OrgId(row.organization_id),
        service_name=ServiceName(row.service_name),
        enabled=bool(row.enabled),
        source=row.source,
        granted_at=row.granted_at,
    )


@dataclass(slots=True)
class SqlAlchemyOrganizationServiceRepository:
    session_factory: async_sessionmaker[AsyncSession]
    model: type = field(default=DefaultOrganizationServiceORM)

    async def list_enabled_service_names(self, org_id: OrgId) -> set[str]:
        async with self.session_factory() as session:
            stmt = select(self.model.service_name).where(
                self.model.organization_id == org_id.value,
                self.model.enabled.is_(True),
            )
            rows = (await session.execute(stmt)).scalars().all()
            return set(rows)

    async def get(
        self, org_id: OrgId, service_name: ServiceName
    ) -> OrganizationService | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(self.model).where(
                        self.model.organization_id == org_id.value,
                        self.model.service_name == str(service_name),
                    )
                )
            ).scalar_one_or_none()
            return _to_entitlement(row) if row is not None else None

    async def enable(
        self, org_id: OrgId, service_name: ServiceName, *, source: str
    ) -> OrganizationService:
        await self._upsert(org_id, [str(service_name)], source=source)
        result = await self.get(org_id, service_name)
        assert result is not None  # just upserted
        return result

    async def disable(
        self, org_id: OrgId, service_name: ServiceName
    ) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(self.model).where(
                    self.model.organization_id == org_id.value,
                    self.model.service_name == str(service_name),
                )
            )
            await session.commit()

    async def bulk_enable(
        self,
        org_id: OrgId,
        service_names: Sequence[ServiceName],
        *,
        source: str,
    ) -> None:
        if not service_names:
            return
        await self._upsert(
            org_id, [str(n) for n in service_names], source=source
        )

    async def _upsert(
        self, org_id: OrgId, names: list[str], *, source: str
    ) -> None:
        rows = [
            {
                "organization_id": org_id.value,
                "service_name": name,
                "enabled": True,
                "source": source,
            }
            for name in names
        ]
        stmt = pg_insert(self.model).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["organization_id", "service_name"],
            set_={"enabled": True, "source": stmt.excluded.source},
        )
        async with self.session_factory() as session:
            await session.execute(stmt)
            await session.commit()
