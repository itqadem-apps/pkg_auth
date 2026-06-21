"""Integration tests for the service-guard schema against real Postgres.

Run with: ``pytest -m integration`` (requires Docker for testcontainers).

Covers:
    - the bundled migration chain forward, incl. the is_platform→visibility
      and TEXT→JSONB description backfills (0003 / 0004);
    - round-trips of the new services / organization_services repos and
      the catalog repo's visibility filtering + get_service_map.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.integration

sqlalchemy = pytest.importorskip("sqlalchemy")
pytest.importorskip("asyncpg")
pytest.importorskip("alembic")
testcontainers_pg = pytest.importorskip("testcontainers.postgres")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)

from pkg_auth.authorization import (  # noqa: E402
    CatalogEntry,
    OrgId,
    PermissionKey,
    PermissionVisibility,
    ServiceName,
    ServiceSpec,
)
from pkg_auth.authorization.adapters.sqlalchemy import MIGRATIONS_DIR  # noqa: E402
from pkg_auth.authorization.adapters.sqlalchemy.repositories.organization_service import (  # noqa: E402
    SqlAlchemyOrganizationServiceRepository,
)
from pkg_auth.authorization.adapters.sqlalchemy.repositories.permission_catalog import (  # noqa: E402
    SqlAlchemyPermissionCatalogRepository,
)
from pkg_auth.authorization.adapters.sqlalchemy.repositories.service import (  # noqa: E402
    SqlAlchemyServiceRepository,
)

_ENV_PY = '''
from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
'''


def _alembic_config(tmp_path, sync_url: str) -> Config:
    script_dir = tmp_path / "alembic"
    (script_dir / "versions").mkdir(parents=True)
    (script_dir / "env.py").write_text(_ENV_PY)
    (script_dir / "script.py.mako").write_text(
        "# ${message}\nrevision = ${repr(up_revision)}\n"
        "down_revision = ${repr(down_revision)}\n"
        "def upgrade():\n    pass\ndef downgrade():\n    pass\n"
    )
    cfg = Config()
    cfg.set_main_option("script_location", str(script_dir))
    cfg.set_main_option(
        "version_locations", f"{MIGRATIONS_DIR} {script_dir / 'versions'}"
    )
    cfg.set_main_option("sqlalchemy.url", sync_url)
    return cfg


@pytest.fixture(scope="module")
def pg():
    with testcontainers_pg.PostgresContainer("postgres:16") as container:
        yield container


def _urls(container):
    raw = container.get_connection_url()  # psycopg2-style
    sync_url = raw.replace("postgresql+psycopg2", "postgresql+psycopg2")
    async_url = raw.replace("+psycopg2", "+asyncpg").replace(
        "postgresql://", "postgresql+asyncpg://"
    )
    return sync_url, async_url


async def test_migration_chain_and_backfill(pg, tmp_path, monkeypatch):
    monkeypatch.setenv("ACL_DEFAULT_LOCALE", "en")
    sync_url, async_url = _urls(pg)
    cfg = _alembic_config(tmp_path, sync_url)

    # Upgrade to the pre-visibility revision, seed an old-shape row.
    command.upgrade(cfg, "pkg_auth_acl_0002")
    engine = create_async_engine(async_url)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO permissions (id, key, service_name, description, "
                "is_platform) VALUES (gen_random_uuid(), 'organizations:create', "
                "'users', 'Create org', true)"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, key, service_name, description, "
                "is_platform) VALUES (gen_random_uuid(), 'course:edit', "
                "'courses', 'Edit course', false)"
            )
        )
    await engine.dispose()

    # Upgrade through 0003/0004/0005.
    command.upgrade(cfg, "pkg_auth_acl_0005")

    engine = create_async_engine(async_url)
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT key, visibility, description FROM permissions "
                    "ORDER BY key"
                )
            )
        ).all()
    await engine.dispose()

    by_key = {r[0]: (r[1], r[2]) for r in rows}
    assert by_key["organizations:create"][0] == "platform_only"
    assert by_key["course:edit"][0] == "shared"
    assert by_key["course:edit"][1] == {"en": "Edit course"}


async def test_repo_roundtrip(pg, tmp_path):
    sync_url, async_url = _urls(pg)
    # Schema already created by the previous test's module-scoped container;
    # ensure head regardless of ordering.
    command.upgrade(_alembic_config(tmp_path, sync_url), "pkg_auth_acl_0005")

    engine = create_async_engine(async_url)
    sf = async_sessionmaker(engine, expire_on_commit=False)

    # Need an organization row for the FK.
    org_id = OrgId(uuid4())
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO organizations (id, slug, name) "
                "VALUES (:id, :slug, 'Acme')"
            ),
            {"id": org_id.value, "slug": f"acme-{org_id.value}"},
        )

    services = SqlAlchemyServiceRepository(session_factory=sf)
    org_services = SqlAlchemyOrganizationServiceRepository(session_factory=sf)
    catalog = SqlAlchemyPermissionCatalogRepository(session_factory=sf)

    await services.upsert_many(
        [
            ServiceSpec.make("courses", {"en": "Courses"}, saas_available=True),
            ServiceSpec.make("users", {"en": "Users"}, auto_provision=True),
        ]
    )
    assert (await services.get(ServiceName("courses"))).saas_available is True

    await catalog.register_many(
        service_name="courses",
        entries=[
            CatalogEntry(
                PermissionKey("course:edit"),
                {"en": "Edit", "ar": "تعديل"},
                PermissionVisibility.TENANT_ONLY,
            )
        ],
    )
    svc_map = await catalog.get_service_map()
    assert svc_map["course:edit"] == "courses"
    tenant = await catalog.list_all(scope="tenant")
    assert any(str(p.key) == "course:edit" for p in tenant)
    platform = await catalog.list_all(scope="platform")
    assert all(str(p.key) != "course:edit" for p in platform)

    await org_services.bulk_enable(
        org_id, [ServiceName("courses")], source="auto"
    )
    assert await org_services.list_enabled_service_names(org_id) == {"courses"}
    await org_services.disable(org_id, ServiceName("courses"))
    assert await org_services.list_enabled_service_names(org_id) == set()

    await engine.dispose()
