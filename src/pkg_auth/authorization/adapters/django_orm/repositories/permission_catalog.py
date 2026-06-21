"""Django ORM implementation of PermissionCatalogRepository (visibility + scope)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence

from ....application.use_cases.register_permission_catalog import CatalogEntry
from ....domain.entities import Permission as DomainPermission
from ....domain.ports import PermissionScope
from ....domain.value_objects import (
    LocalizedText,
    PermissionId,
    PermissionKey,
    PermissionVisibility,
)
from ..models import Permission as DefaultPermissionModel


def _to_domain(row) -> DomainPermission:
    return DomainPermission(
        id=PermissionId(row.id),
        key=PermissionKey(row.key),
        service_name=row.service_name,
        description=LocalizedText(row.description or {}),
        visibility=PermissionVisibility(row.visibility),
    )


def _scope_filter(qs, scope: PermissionScope):
    if scope in ("org", "tenant"):
        return qs.filter(
            visibility__in=(
                PermissionVisibility.SHARED.value,
                PermissionVisibility.TENANT_ONLY.value,
            )
        )
    if scope == "platform":
        return qs.filter(
            visibility__in=(
                PermissionVisibility.PLATFORM_ONLY.value,
                PermissionVisibility.SHARED.value,
            )
        )
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
                    "description": entry.description.as_dict() or None,
                    "visibility": entry.visibility.value,
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

    async def get_service_map(self) -> dict[str, str]:
        return {
            row.key: row.service_name
            async for row in self.model.objects.only("key", "service_name")
        }

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
