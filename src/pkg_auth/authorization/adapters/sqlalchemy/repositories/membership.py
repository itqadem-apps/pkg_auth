"""SQLAlchemy implementation of MembershipRepository.

The hot path here is :meth:`load_auth_context` — called on every
protected request via the FastAPI / Django / Strawberry deps.
Implementation is a single round-trip joining ``memberships`` →
``roles`` → ``role_permissions`` → ``permissions``.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from ....domain.entities import AuthContext, Membership
from ....domain.value_objects import (
    OrgId,
    RoleId,
    RoleName,
    UserId,
)
from ..models import MembershipORM, RoleORM


def _to_membership(row: MembershipORM, role_name: str) -> Membership:
    return Membership(
        id=row.id,
        user_id=UserId(row.user_id),
        organization_id=OrgId(row.organization_id),
        role_id=RoleId(row.role_id),
        role_name=RoleName(role_name),
        status=row.status,
        joined_at=row.joined_at,
    )


@dataclass(slots=True)
class SqlAlchemyMembershipRepository:
    session_factory: async_sessionmaker[AsyncSession]

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> Membership | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(MembershipORM)
                    .options(selectinload(MembershipORM.role))
                    .where(
                        MembershipORM.user_id == int(user_id),
                        MembershipORM.organization_id == int(org_id),
                    )
                )
            ).scalar_one_or_none()
            return _to_membership(row, row.role.name) if row is not None else None

    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> Membership:
        stmt = (
            pg_insert(MembershipORM)
            .values(
                user_id=int(user_id),
                organization_id=int(org_id),
                role_id=int(role_id),
                status=status,
            )
            .on_conflict_do_update(
                index_elements=["user_id", "organization_id"],
                set_={"role_id": int(role_id), "status": status},
            )
            .returning(MembershipORM)
        )
        async with self.session_factory() as session:
            result = await session.execute(stmt)
            await session.commit()
            row = result.scalar_one()
            # Need to load the role for role_name
            role = (
                await session.execute(
                    select(RoleORM).where(RoleORM.id == row.role_id)
                )
            ).scalar_one()
            return _to_membership(row, role.name)

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(MembershipORM).where(
                    MembershipORM.user_id == int(user_id),
                    MembershipORM.organization_id == int(org_id),
                )
            )
            await session.commit()

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        """Hot path: single query joining membership → role → permissions.

        Returns ``None`` if there is no active membership.
        """
        async with self.session_factory() as session:
            stmt = (
                select(MembershipORM)
                .options(
                    selectinload(MembershipORM.role).selectinload(
                        RoleORM.permissions
                    )
                )
                .where(
                    MembershipORM.user_id == int(user_id),
                    MembershipORM.organization_id == int(org_id),
                    MembershipORM.status == "active",
                )
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None
            return AuthContext(
                user_id=UserId(row.user_id),
                organization_id=OrgId(row.organization_id),
                role_name=RoleName(row.role.name),
                perms=frozenset(p.key for p in row.role.permissions),
            )

    async def list_for_user(self, user_id: UserId) -> list[Membership]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(
                    select(MembershipORM)
                    .options(selectinload(MembershipORM.role))
                    .where(MembershipORM.user_id == int(user_id))
                )
            ).scalars().all()
            return [_to_membership(r, r.role.name) for r in rows]
