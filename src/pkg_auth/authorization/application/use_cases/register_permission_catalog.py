"""Register a service's permission catalog at startup."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Union

from ...domain.ports import (
    PermissionCatalogPublisher,
    PermissionCatalogRepository,
)
from ...domain.value_objects import PermissionKey


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One row a service registers into the central permission catalog.

    ``is_platform`` distinguishes permissions that operate inside a single
    organization (default) from permissions that only make sense at
    platform/system level across organizations (e.g. ``organizations:create``,
    ``organizations:approve``). The central role-editor UI uses the flag to
    filter permissions out of org-scoped role builders.
    """

    key: PermissionKey
    description: str | None
    is_platform: bool = False


CatalogEntryInput = Union[
    CatalogEntry,
    tuple[PermissionKey, str | None],
    tuple[PermissionKey, str | None, bool],
]


def _normalize_entry(entry: CatalogEntryInput) -> CatalogEntry:
    if isinstance(entry, CatalogEntry):
        return entry
    if isinstance(entry, tuple):
        if len(entry) == 2:
            key, description = entry
            return CatalogEntry(key=key, description=description)
        if len(entry) == 3:
            key, description, is_platform = entry
            return CatalogEntry(
                key=key, description=description, is_platform=bool(is_platform)
            )
        raise ValueError(f"Invalid catalog entry tuple length: {len(entry)}")
    raise TypeError(f"Unsupported catalog entry type: {type(entry).__name__}")


@dataclass(slots=True)
class RegisterPermissionCatalogUseCase:
    """Idempotently register the permission keys a service knows about.

    Each consuming service calls this on boot with its static perm
    list. The sink upserts by ``key`` so calling it on every restart
    is safe and converges. Re-registering the same key with a
    different ``is_platform`` value flips the flag.

    ``catalog_sink`` accepts either a :class:`PermissionCatalogRepository`
    (direct SQLAlchemy write — used by the Mode A source-of-truth) or a
    :class:`PermissionCatalogPublisher` (NATS publish — used by Mode B
    consumers whose DB credential cannot write to the SoT's ACL tables).
    Both ports expose the same ``register_many`` shape, so the use case
    is agnostic to which one is wired in.
    """

    catalog_sink: PermissionCatalogRepository | PermissionCatalogPublisher

    async def execute(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntryInput],
    ) -> None:
        normalized = [_normalize_entry(e) for e in entries]
        await self.catalog_sink.register_many(
            service_name=service_name,
            entries=normalized,
        )
