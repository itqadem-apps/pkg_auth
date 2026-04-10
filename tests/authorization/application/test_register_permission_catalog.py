"""RegisterPermissionCatalogUseCase tests."""
from pkg_auth.authorization import PermissionKey
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)

from .fakes import FakePermissionCatalogRepository


async def test_register_persists_entries():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[
            (PermissionKey("course:edit"), "Edit course content"),
            (PermissionKey("course:view"), "View course content"),
        ],
    )
    all_perms = await repo.list_all()
    keys = sorted(str(p.key) for p in all_perms)
    assert keys == ["course:edit", "course:view"]


async def test_register_is_idempotent():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    entries = [(PermissionKey("course:edit"), "Edit course")]
    await uc.execute(service_name="courses", entries=entries)
    await uc.execute(service_name="courses", entries=entries)
    await uc.execute(service_name="courses", entries=entries)
    perms = await repo.list_all()
    assert len(perms) == 1


async def test_register_updates_description_on_repeat():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("course:edit"), "Old description")],
    )
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("course:edit"), "New description")],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].description == "New description"


async def test_list_for_service_filters_by_service_name():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("course:edit"), None)],
    )
    await uc.execute(
        service_name="media",
        entries=[(PermissionKey("media:upload"), None)],
    )
    courses_perms = await repo.list_for_service("courses")
    assert [str(p.key) for p in courses_perms] == ["course:edit"]
