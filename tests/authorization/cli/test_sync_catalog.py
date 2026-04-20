"""pkg-auth-sync-catalog CLI smoke tests.

The SQLAlchemy adapter uses ``pg_insert.on_conflict_do_update`` which is
Postgres-only, so CLI logic is exercised here against a fake repo via the
``repo=`` injection point. An adapter-level integration test against a
real Postgres (testcontainers) belongs behind the ``integration`` marker.
"""
from __future__ import annotations

import asyncio
import sys

import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.cli.sync_catalog import (
    build_arg_parser,
    load_catalog,
    main,
    run,
)

from tests.authorization.application.fakes import FakePermissionCatalogRepository


# --------------------------------------------------------------------------- #
# build_arg_parser
# --------------------------------------------------------------------------- #


def test_parser_requires_service_and_catalog() -> None:
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_reads_db_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_DATABASE_URL", "postgresql+asyncpg://x/y")
    # build_arg_parser reads the env var at call time
    parser = build_arg_parser()
    args = parser.parse_args(["--service", "courses", "--catalog", "m:C"])
    assert args.db_url == "postgresql+asyncpg://x/y"
    assert args.dry_run is False


# --------------------------------------------------------------------------- #
# load_catalog
# --------------------------------------------------------------------------- #


SAMPLE_CATALOG = [
    CatalogEntry(PermissionKey("courses:view"), "View"),
    CatalogEntry(PermissionKey("courses:edit"), "Edit"),
]


def test_load_catalog_resolves_module_attr() -> None:
    entries = load_catalog(f"{__name__}:SAMPLE_CATALOG")
    assert [str(e.key) for e in entries] == ["courses:view", "courses:edit"]


def test_load_catalog_rejects_bad_format() -> None:
    with pytest.raises(ValueError):
        load_catalog("no_colon")


def test_load_catalog_raises_when_attr_missing() -> None:
    with pytest.raises(ValueError):
        load_catalog(f"{__name__}:DOES_NOT_EXIST")


# --------------------------------------------------------------------------- #
# run() with injected fake repo
# --------------------------------------------------------------------------- #


async def test_run_syncs_via_injected_repo() -> None:
    repo = FakePermissionCatalogRepository()
    await repo.register_many(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("courses:legacy"), None)],
    )

    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--service", "courses",
            "--catalog", f"{__name__}:SAMPLE_CATALOG",
        ]
    )
    result = await run(args, repo=repo)

    assert result.upserted == 2
    assert result.pruned == 1
    assert result.dry_run is False
    keys = sorted(str(p.key) for p in await repo.list_for_service("courses"))
    assert keys == ["courses:edit", "courses:view"]


async def test_run_dry_run_does_not_write(capsys: pytest.CaptureFixture[str]) -> None:
    repo = FakePermissionCatalogRepository()
    await repo.register_many(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("courses:legacy"), None)],
    )

    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--service", "courses",
            "--catalog", f"{__name__}:SAMPLE_CATALOG",
            "--dry-run",
        ]
    )
    result = await run(args, repo=repo)

    assert result.dry_run is True
    assert result.upserted == 2
    assert result.pruned == 1
    keys = [str(p.key) for p in await repo.list_for_service("courses")]
    assert keys == ["courses:legacy"]
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "courses:view" in out or "courses:edit" in out


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #


def test_main_exit_non_zero_when_no_db_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACL_DATABASE_URL", raising=False)
    argv = ["--service", "courses", "--catalog", f"{__name__}:SAMPLE_CATALOG"]
    with pytest.raises(SystemExit) as exc:
        main(argv)
    # either argparse's non-zero or the --db-url check inside run()
    assert exc.value.code not in (0, None)


def test_main_prints_result_on_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = FakePermissionCatalogRepository()

    # Monkeypatch asyncio.run inside the CLI module to inject the fake repo.
    from pkg_auth.authorization.cli import sync_catalog as cli_mod

    real_run = cli_mod.run

    async def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        return await real_run(args, repo=repo)

    monkeypatch.setattr(cli_mod, "run", fake_run)

    main(
        [
            "--service", "courses",
            "--catalog", f"{__name__}:SAMPLE_CATALOG",
        ]
    )
    out = capsys.readouterr().out
    assert "sync: service=courses" in out
    assert "upserted=2" in out
    assert "pruned=0" in out
