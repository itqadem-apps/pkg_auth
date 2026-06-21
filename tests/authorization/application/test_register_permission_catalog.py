"""RegisterPermissionCatalogUseCase tests (CatalogEntry + visibility + scope)."""
import pytest

from pkg_auth.authorization import (
    CatalogEntry,
    PermissionKey,
    PermissionVisibility,
)
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)

from .fakes import FakePermissionCatalogRepository, FakeServiceRepository

PLATFORM = PermissionVisibility.PLATFORM_ONLY
SHARED = PermissionVisibility.SHARED
TENANT = PermissionVisibility.TENANT_ONLY


# --------------------------------------------------------------------------- #
# Registration shapes
# --------------------------------------------------------------------------- #


async def test_register_persists_entries_via_catalog_entry():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[
            CatalogEntry(PermissionKey("course:edit"), "Edit course content"),
            CatalogEntry(PermissionKey("course:view"), "View course content"),
        ],
    )
    keys = sorted(str(p.key) for p in await repo.list_all())
    assert keys == ["course:edit", "course:view"]


async def test_register_accepts_two_tuple_defaults_to_shared():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("course:edit"), "Edit course content")],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].visibility is SHARED
    assert perms[0].description.get("en") == "Edit course content"


async def test_register_accepts_three_tuple_with_explicit_visibility():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("organizations:create"), "Create org", PLATFORM)],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].visibility is PLATFORM


async def test_register_accepts_localized_description_dict():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[
            CatalogEntry(
                PermissionKey("course:edit"),
                {"en": "Edit course", "ar": "تعديل الدورة"},
            )
        ],
    )
    perm = (await repo.list_all())[0]
    assert perm.description.get("en") == "Edit course"
    assert perm.description.get("ar") == "تعديل الدورة"


async def test_register_rejects_unsupported_entry_shape():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    with pytest.raises(TypeError):
        await uc.execute(service_name="courses", entries=["not-a-tuple"])  # type: ignore[list-item]


async def test_register_rejects_wrong_arity_tuple():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    with pytest.raises(ValueError):
        await uc.execute(
            service_name="courses",
            entries=[(PermissionKey("course:edit"),)],  # type: ignore[list-item]
        )


async def test_register_ensures_service_row_when_service_repo_wired():
    catalog = FakePermissionCatalogRepository()
    services = FakeServiceRepository()
    uc = RegisterPermissionCatalogUseCase(
        catalog_repo=catalog, service_repo=services
    )
    await uc.execute(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("course:edit"), "Edit")],
    )
    names = [str(s.name) for s in await services.list_all()]
    assert names == ["courses"]


# --------------------------------------------------------------------------- #
# Idempotency + flag flipping
# --------------------------------------------------------------------------- #


async def test_register_is_idempotent():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    entries = [CatalogEntry(PermissionKey("course:edit"), "Edit course")]
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
        entries=[CatalogEntry(PermissionKey("course:edit"), "Old description")],
    )
    await uc.execute(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("course:edit"), "New description")],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].description.get("en") == "New description"


async def test_register_flips_visibility_on_repeat():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="users",
        entries=[CatalogEntry(PermissionKey("organizations:create"), None)],
    )
    assert (await repo.list_all())[0].visibility is SHARED

    await uc.execute(
        service_name="users",
        entries=[
            CatalogEntry(
                PermissionKey("organizations:create"), None, PLATFORM
            ),
        ],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].visibility is PLATFORM


# --------------------------------------------------------------------------- #
# Scope filtering on list methods
# --------------------------------------------------------------------------- #


async def _seed_mixed_catalog(repo: FakePermissionCatalogRepository) -> None:
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="users",
        entries=[
            CatalogEntry(PermissionKey("users:create"), "Create user"),
            CatalogEntry(PermissionKey("users:read"), "Read user"),
            CatalogEntry(
                PermissionKey("organizations:create"), "Create org", PLATFORM
            ),
            CatalogEntry(
                PermissionKey("organizations:approve"), "Approve org", PLATFORM
            ),
            CatalogEntry(
                PermissionKey("users:wellbeing-survey"),
                "Tenant-only survey",
                TENANT,
            ),
        ],
    )


async def test_list_all_default_scope_returns_everything():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all())
    assert keys == [
        "organizations:approve",
        "organizations:create",
        "users:create",
        "users:read",
        "users:wellbeing-survey",
    ]


async def test_scope_tenant_excludes_platform_only_keeps_tenant_and_shared():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all(scope="tenant"))
    assert keys == ["users:create", "users:read", "users:wellbeing-survey"]


async def test_scope_org_is_alias_for_tenant():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    assert [str(p.key) for p in await repo.list_all(scope="org")] == [
        str(p.key) for p in await repo.list_all(scope="tenant")
    ]


async def test_scope_platform_excludes_tenant_only_keeps_platform_and_shared():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all(scope="platform"))
    assert keys == [
        "organizations:approve",
        "organizations:create",
        "users:create",
        "users:read",
    ]
