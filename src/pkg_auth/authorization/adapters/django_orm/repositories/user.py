"""Django ORM implementation of UserRepository."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from django.db import IntegrityError

from ....domain.entities import User as DomainUser
from ....domain.value_objects import UserId
from ..models import User as DefaultUserModel


def _to_domain(row) -> DomainUser:
    return DomainUser(
        id=UserId(row.id),
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        full_name=row.full_name,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )


@dataclass(slots=True)
class DjangoUserRepository:
    """Django ORM implementation of UserRepository.

    The ``model`` field accepts any concrete Django model class that
    inherits from :class:`pkg_auth.authorization.adapters.django_orm.UserMixin`.
    Defaults to the package's managed=False mirror model.
    """

    model: type = field(default=DefaultUserModel)

    async def get_by_id(self, user_id: UserId) -> DomainUser | None:
        try:
            row = await self.model.objects.aget(id=user_id.value)
        except self.model.DoesNotExist:
            return None
        return _to_domain(row)

    async def get_by_keycloak_sub(self, sub: str) -> DomainUser | None:
        try:
            row = await self.model.objects.aget(keycloak_sub=sub)
        except self.model.DoesNotExist:
            return None
        return _to_domain(row)

    async def upsert_from_identity(
        self,
        *,
        sub: str,
        email: str,
        full_name: str | None,
    ) -> DomainUser:
        now = datetime.now(timezone.utc)
        try:
            row = await self.model.objects.aget(keycloak_sub=sub)
            row.email = email
            row.full_name = full_name
            row.last_seen_at = now
            await row.asave(update_fields=["email", "full_name", "last_seen_at"])
        except self.model.DoesNotExist:
            try:
                row = await self.model.objects.acreate(
                    keycloak_sub=sub,
                    email=email,
                    full_name=full_name,
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
            except IntegrityError:
                row = await self.model.objects.aget(keycloak_sub=sub)
        return _to_domain(row)
