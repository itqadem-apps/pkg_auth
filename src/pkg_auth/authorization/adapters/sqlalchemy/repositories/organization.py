"""SQLAlchemy implementation of OrganizationRepository."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ....domain.entities import Organization
from ....domain.value_objects import OrgId, UserId
from ..models import MembershipORM, OrganizationORM


def _to_org(row: OrganizationORM) -> Organization:
    return Organization(
        id=OrgId(row.id),
        slug=row.slug,
        name=row.name,
        created_at=row.created_at,
    )


@dataclass(slots=True)
class SqlAlchemyOrganizationRepository:
    session_factory: async_sessionmaker[AsyncSession]

    async def get(self, org_id: OrgId) -> Organization | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(OrganizationORM).where(
                        OrganizationORM.id == int(org_id)
                    )
                )
            ).scalar_one_or_none()
            return _to_org(row) if row is not None else None

    async def get_by_slug(self, slug: str) -> Organization | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(OrganizationORM).where(OrganizationORM.slug == slug)
                )
            ).scalar_one_or_none()
            return _to_org(row) if row is not None else None

    async def create(self, *, slug: str, name: str) -> Organization:
        async with self.session_factory() as session:
            row = OrganizationORM(slug=slug, name=name)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return _to_org(row)

    async def update(
        self, org_id: OrgId, *, name: str | None
    ) -> Organization:
        async with self.session_factory() as session:
            values: dict[str, object] = {}
            if name is not None:
                values["name"] = name
            if values:
                await session.execute(
                    update(OrganizationORM)
                    .where(OrganizationORM.id == int(org_id))
                    .values(**values)
                )
                await session.commit()
            row = (
                await session.execute(
                    select(OrganizationORM).where(
                        OrganizationORM.id == int(org_id)
                    )
                )
            ).scalar_one()
            return _to_org(row)

    async def delete(self, org_id: OrgId) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(OrganizationORM).where(
                    OrganizationORM.id == int(org_id)
                )
            )
            await session.commit()

    async def list_for_user(self, user_id: UserId) -> list[Organization]:
        async with self.session_factory() as session:
            stmt = (
                select(OrganizationORM)
                .join(
                    MembershipORM,
                    MembershipORM.organization_id == OrganizationORM.id,
                )
                .where(MembershipORM.user_id == int(user_id))
                .order_by(OrganizationORM.id)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_to_org(r) for r in rows]
