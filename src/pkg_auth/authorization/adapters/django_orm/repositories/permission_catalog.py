"""Django ORM implementation of PermissionCatalogRepository (v1.4 — is_platform + scope)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence

from ....application.use_cases.register_permission_catalog import CatalogEntry
from ....domain.entities import Permission as DomainPermission
from ....domain.ports import PermissionScope
from ....domain.value_objects import PermissionId, PermissionKey
from ..models import Permission as DefaultPermissionModel


def _to_domain(row) -> DomainPermission:
    return DomainPermission(
        id=PermissionId(row.id),
        key=PermissionKey(row.key),
        service_name=row.service_name,
        description=row.description,
        is_platform=bool(row.is_platform),
    )


def _scope_filter(qs, scope: PermissionScope):
    if scope == "org":
        return qs.filter(is_platform=False)
    if scope == "platform":
        return qs.filter(is_platform=True)
    return qs


@dataclass(slots=True)
class DjangoPermissionCatalogRepository:
    model: type = field(default=DefaultPermissionModel)

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntry],
    ) -> None:
        now = datetime.now(timezone.utc)
        for entry in entries:
            await self.model.objects.aupdate_or_create(
                key=str(entry.key),
                defaults={
                    "service_name": service_name,
                    "description": entry.description,
                    "is_platform": entry.is_platform,
                    "registered_at": now,
                },
            )

    async def list_all(
        self, *, scope: PermissionScope = "all"
    ) -> list[DomainPermission]:
        qs = _scope_filter(self.model.objects.order_by("id"), scope)
        return [_to_domain(r) async for r in qs]

    async def list_for_service(
        self, service_name: str, *, scope: PermissionScope = "all"
    ) -> list[DomainPermission]:
        qs = _scope_filter(
            self.model.objects.filter(service_name=service_name).order_by("id"),
            scope,
        )
        return [_to_domain(r) async for r in qs]

    async def prune_absent(
        self,
        *,
        service_name: str,
        keep_keys: Iterable[PermissionKey],
    ) -> int:
        keys = [str(k) for k in keep_keys]
        qs = self.model.objects.filter(service_name=service_name)
        if keys:
            qs = qs.exclude(key__in=keys)
        deleted, _ = await qs.adelete()
        return int(deleted)
