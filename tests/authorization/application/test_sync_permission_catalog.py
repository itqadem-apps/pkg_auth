"""SyncPermissionCatalogUseCase tests."""
from __future__ import annotations

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.application.use_cases.sync_permission_catalog import (
    SyncPermissionCatalogUseCase,
    SyncResult,
)

from .fakes import FakePermissionCatalogRepository


async def _seed(repo: FakePermissionCatalogRepository, service: str, keys: list[str]) -> None:
    await repo.register_many(
        service_name=service,
        entries=[CatalogEntry(PermissionKey(k), None) for k in keys],
    )


async def test_sync_upserts_then_prunes_absent_for_service() -> None:
    repo = FakePermissionCatalogRepository()
    await _seed(repo, "courses", ["courses:view", "courses:edit", "courses:legacy"])

    uc = SyncPermissionCatalogUseCase(catalog_repo=repo)
    result = await uc.execute(
        service_name="courses",
        entries=[
            CatalogEntry(PermissionKey("courses:view"), "View"),
            CatalogEntry(PermissionKey("courses:edit"), "Edit"),
            CatalogEntry(PermissionKey("courses:publish"), "Publish"),
        ],
    )

    assert result == SyncResult(upserted=3, pruned=1, dry_run=False)
    keys = sorted(str(p.key) for p in await repo.list_for_service("courses"))
    assert keys == ["courses:edit", "courses:publish", "courses:view"]


async def test_sync_is_scoped_by_service_name() -> None:
    repo = FakePermissionCatalogRepository()
    await _seed(repo, "courses", ["courses:view"])
    await _seed(repo, "videos", ["videos:read", "videos:legacy"])

    uc = SyncPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("courses:view"), None)],
    )

    videos = sorted(str(p.key) for p in await repo.list_for_service("videos"))
    assert videos == ["videos:legacy", "videos:read"]


async def test_sync_with_empty_entries_prunes_every_row_for_service() -> None:
    repo = FakePermissionCatalogRepository()
    await _seed(repo, "courses", ["courses:view", "courses:edit"])
    await _seed(repo, "videos", ["videos:read"])

    uc = SyncPermissionCatalogUseCase(catalog_repo=repo)
    result = await uc.execute(service_name="courses", entries=[])

    assert result.upserted == 0
    assert result.pruned == 2
    assert await repo.list_for_service("courses") == []
    assert [str(p.key) for p in await repo.list_for_service("videos")] == ["videos:read"]


async def test_dry_run_reports_counts_without_writing() -> None:
    repo = FakePermissionCatalogRepository()
    await _seed(repo, "courses", ["courses:view", "courses:legacy"])

    uc = SyncPermissionCatalogUseCase(catalog_repo=repo)
    result = await uc.execute(
        service_name="courses",
        entries=[
            CatalogEntry(PermissionKey("courses:view"), None),
            CatalogEntry(PermissionKey("courses:new"), None),
        ],
        dry_run=True,
    )

    assert result == SyncResult(upserted=2, pruned=1, dry_run=True)
    # No writes: DB still has the pre-existing rows
    keys = sorted(str(p.key) for p in await repo.list_for_service("courses"))
    assert keys == ["courses:legacy", "courses:view"]


async def test_sync_upserts_flips_is_platform_flag() -> None:
    repo = FakePermissionCatalogRepository()
    await repo.register_many(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("courses:view"), "old", is_platform=False)],
    )

    uc = SyncPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("courses:view"), "new", is_platform=True)],
    )

    perms = await repo.list_for_service("courses")
    assert len(perms) == 1
    assert perms[0].is_platform is True
    assert perms[0].description == "new"
