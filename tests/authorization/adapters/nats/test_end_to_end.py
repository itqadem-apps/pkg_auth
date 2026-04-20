"""End-to-end: publisher encodes a snapshot, subscriber decodes + applies it.

Uses a mocked JetStream context on the publisher side and a
hand-delivered message on the subscriber side, so no real NATS is
needed. Covers the contract across the wire: keys removed from the
catalog between boots are soft-deleted by the subscriber.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.adapters.nats import (
    NatsPermissionCatalogPublisher,
    PermissionCatalogSubscriber,
)

from ...application.fakes import FakePermissionCatalogRepository


def _entries(*keys: str) -> list[CatalogEntry]:
    return [
        CatalogEntry(key=PermissionKey(k), description=k, is_platform=False)
        for k in keys
    ]


def _mk_msg(data: bytes) -> AsyncMock:
    msg = AsyncMock()
    msg.data = data
    msg.subject = "acl.permissions.catalog.courses"
    return msg


async def _publish_then_apply(
    publisher: NatsPermissionCatalogPublisher,
    subscriber: PermissionCatalogSubscriber,
    *,
    service_name: str,
    entries: list[CatalogEntry],
) -> None:
    publisher._js = AsyncMock()
    await publisher.register_many(service_name=service_name, entries=entries)
    payload = publisher._js.publish.await_args.kwargs["payload"]
    await subscriber._handle(_mk_msg(payload))


async def test_first_publish_upserts_all_keys():
    repo = FakePermissionCatalogRepository()
    publisher = NatsPermissionCatalogPublisher(nats_url="nats://ignored")
    subscriber = PermissionCatalogSubscriber(
        nats_url="nats://ignored", catalog_repo=repo
    )

    await _publish_then_apply(
        publisher,
        subscriber,
        service_name="courses",
        entries=_entries("course:view", "course:edit", "course:publish"),
    )

    keys = sorted(str(p.key) for p in await repo.list_for_service("courses"))
    assert keys == ["course:edit", "course:publish", "course:view"]


async def test_second_publish_without_a_key_soft_deletes_it():
    repo = FakePermissionCatalogRepository()
    publisher = NatsPermissionCatalogPublisher(nats_url="nats://ignored")
    subscriber = PermissionCatalogSubscriber(
        nats_url="nats://ignored", catalog_repo=repo
    )

    await _publish_then_apply(
        publisher, subscriber,
        service_name="courses",
        entries=_entries("course:view", "course:edit", "course:publish"),
    )
    await _publish_then_apply(
        publisher, subscriber,
        service_name="courses",
        entries=_entries("course:view", "course:edit"),
    )

    keys = sorted(str(p.key) for p in await repo.list_for_service("courses"))
    assert keys == ["course:edit", "course:view"]


async def test_snapshot_is_per_service_and_does_not_affect_other_services():
    repo = FakePermissionCatalogRepository()
    publisher = NatsPermissionCatalogPublisher(nats_url="nats://ignored")
    subscriber = PermissionCatalogSubscriber(
        nats_url="nats://ignored", catalog_repo=repo
    )

    await _publish_then_apply(
        publisher, subscriber,
        service_name="courses",
        entries=_entries("course:view"),
    )
    await _publish_then_apply(
        publisher, subscriber,
        service_name="articles",
        entries=_entries("article:read"),
    )

    # Now courses drops its only key. articles must be untouched.
    await _publish_then_apply(
        publisher, subscriber,
        service_name="courses",
        entries=[],
    )

    assert [str(p.key) for p in await repo.list_for_service("courses")] == []
    assert [str(p.key) for p in await repo.list_for_service("articles")] == [
        "article:read"
    ]
