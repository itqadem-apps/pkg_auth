"""SQLAlchemy implementation of UserRepository (UUID PKs, injectable model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ....domain.entities import User
from ....domain.value_objects import UserId
from ..models import UserORM as DefaultUserORM


def _to_user(row: Any) -> User:
    return User(
        id=UserId(row.id),
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        full_name=row.full_name,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


@dataclass(slots=True)
class SqlAlchemyUserRepository:
    session_factory: async_sessionmaker[AsyncSession]
    model: type = field(default=DefaultUserORM)

    async def get_by_id(self, user_id: UserId) -> User | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(self.model).where(self.model.id == user_id.value)
                )
            ).scalar_one_or_none()
            return _to_user(row) if row is not None else None

    async def get_by_keycloak_sub(self, sub: str) -> User | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(self.model).where(self.model.keycloak_sub == sub)
                )
            ).scalar_one_or_none()
            return _to_user(row) if row is not None else None

    async def upsert_from_identity(
        self,
        *,
        sub: str,
        email: str,
        full_name: str | None,
    ) -> User:
        stmt = (
            pg_insert(self.model)
            .values(keycloak_sub=sub, email=email, full_name=full_name)
            .on_conflict_do_update(
                index_elements=["keycloak_sub"],
                set_={
                    "email": email,
                    "full_name": full_name,
                    "last_seen_at": func.now(),
                },
            )
            .returning(self.model)
        )
        async with self.session_factory() as session:
            result = await session.execute(stmt)
            await session.commit()
            row = result.scalar_one()
            return _to_user(row)
