"""Django ORM implementation of PermissionCatalogRepository."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from ....domain.entities import Permission as DomainPermission
from ....domain.value_objects import PermissionId, PermissionKey
from ..models import Permission as PermissionModel


def _to_domain(row: PermissionModel) -> DomainPermission:
    return DomainPermission(
        id=PermissionId(row.id),
        key=PermissionKey(row.key),
        service_name=row.service_name,
        description=row.description,
    )


@dataclass(slots=True)
class DjangoPermissionCatalogRepository:
    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[tuple[PermissionKey, str | None]],
    ) -> None:
        now = datetime.now(timezone.utc)
        for key, description in entries:
            await PermissionModel.objects.aupdate_or_create(
                key=str(key),
                defaults={
                    "service_name": service_name,
                    "description": description,
                    "registered_at": now,
                },
            )

    async def list_all(self) -> list[DomainPermission]:
        return [_to_domain(r) async for r in PermissionModel.objects.order_by("id")]

    async def list_for_service(self, service_name: str) -> list[DomainPermission]:
        rows = PermissionModel.objects.filter(service_name=service_name).order_by("id")
        return [_to_domain(r) async for r in rows]
