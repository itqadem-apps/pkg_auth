"""RegisterPermissionCatalogUseCase tests (v1.4 — CatalogEntry + scope)."""
import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)

from .fakes import FakePermissionCatalogRepository


# --------------------------------------------------------------------------- #
# Backwards-compatible registration shapes
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


async def test_register_accepts_legacy_two_tuple_with_default_is_platform_false():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("course:edit"), "Edit course content")],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].is_platform is False


async def test_register_accepts_legacy_three_tuple_with_explicit_is_platform():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="courses",
        entries=[(PermissionKey("organizations:create"), "Create org", True)],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].is_platform is True


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
    assert perms[0].description == "New description"


async def test_register_flips_is_platform_on_repeat():
    repo = FakePermissionCatalogRepository()
    uc = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await uc.execute(
        service_name="users",
        entries=[CatalogEntry(PermissionKey("organizations:create"), None)],
    )
    assert (await repo.list_all())[0].is_platform is False

    await uc.execute(
        service_name="users",
        entries=[
            CatalogEntry(PermissionKey("organizations:create"), None, is_platform=True),
        ],
    )
    perms = await repo.list_all()
    assert len(perms) == 1
    assert perms[0].is_platform is True


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
                PermissionKey("organizations:create"),
                "Create org",
                is_platform=True,
            ),
            CatalogEntry(
                PermissionKey("organizations:approve"),
                "Approve org",
                is_platform=True,
            ),
        ],
    )
    await uc.execute(
        service_name="courses",
        entries=[
            CatalogEntry(PermissionKey("courses:edit"), "Edit course"),
            CatalogEntry(
                PermissionKey("courses:moderate-globally"),
                "Cross-org course moderation",
                is_platform=True,
            ),
        ],
    )


async def test_list_all_default_scope_returns_everything():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all())
    assert keys == [
        "courses:edit",
        "courses:moderate-globally",
        "organizations:approve",
        "organizations:create",
        "users:create",
        "users:read",
    ]


async def test_list_all_scope_org_excludes_platform_perms():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all(scope="org"))
    assert keys == ["courses:edit", "users:create", "users:read"]


async def test_list_all_scope_platform_returns_only_platform_perms():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_all(scope="platform"))
    assert keys == [
        "courses:moderate-globally",
        "organizations:approve",
        "organizations:create",
    ]


async def test_list_for_service_default_scope_returns_everything_for_service():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(str(p.key) for p in await repo.list_for_service("users"))
    assert keys == ["organizations:approve", "organizations:create", "users:create", "users:read"]


async def test_list_for_service_scope_org():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(
        str(p.key) for p in await repo.list_for_service("users", scope="org")
    )
    assert keys == ["users:create", "users:read"]


async def test_list_for_service_scope_platform():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    keys = sorted(
        str(p.key) for p in await repo.list_for_service("users", scope="platform")
    )
    assert keys == ["organizations:approve", "organizations:create"]


async def test_list_for_service_isolates_other_services():
    repo = FakePermissionCatalogRepository()
    await _seed_mixed_catalog(repo)
    courses = await repo.list_for_service("courses")
    assert {str(p.key) for p in courses} == {
        "courses:edit",
        "courses:moderate-globally",
    }
