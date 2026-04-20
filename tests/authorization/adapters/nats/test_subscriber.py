"""Subscriber message handling: ack on success, nak on DB error, term on poison."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.adapters.nats import (
    SCHEMA_VERSION,
    PermissionCatalogSubscriber,
    encode_message,
)


class _FakeRepo:
    def __init__(self):
        self.calls: list[tuple[str, tuple[CatalogEntry, ...]]] = []
        self.raises: Exception | None = None

    async def apply_snapshot(self, *, service_name, entries):
        if self.raises is not None:
            raise self.raises
        self.calls.append((service_name, tuple(entries)))


def _mk_msg(data: bytes) -> AsyncMock:
    msg = AsyncMock()
    msg.data = data
    msg.subject = "acl.permissions.catalog.courses"
    return msg


@pytest.fixture
def subscriber():
    repo = _FakeRepo()
    sub = PermissionCatalogSubscriber(
        nats_url="nats://ignored:4222", catalog_repo=repo
    )
    return sub, repo


async def test_valid_message_applies_snapshot_and_acks(subscriber):
    sub, repo = subscriber
    payload = encode_message(
        service_name="courses",
        entries=[
            CatalogEntry(
                key=PermissionKey("course:view"),
                description="View",
                is_platform=False,
            )
        ],
    )
    msg = _mk_msg(payload)

    await sub._handle(msg)

    assert len(repo.calls) == 1
    service, entries = repo.calls[0]
    assert service == "courses"
    assert [str(e.key) for e in entries] == ["course:view"]
    msg.ack.assert_awaited_once()
    msg.term.assert_not_called()
    msg.nak.assert_not_called()


async def test_poison_message_is_termed_not_redelivered(subscriber):
    sub, repo = subscriber
    bad = json.dumps(
        {"schema_version": 999, "service_name": "x", "entries": []}
    ).encode()
    msg = _mk_msg(bad)

    await sub._handle(msg)

    assert repo.calls == []
    msg.term.assert_awaited_once()
    msg.ack.assert_not_called()
    msg.nak.assert_not_called()


async def test_repo_error_naks_for_redelivery(subscriber):
    sub, repo = subscriber
    repo.raises = RuntimeError("db down")
    payload = encode_message(
        service_name="courses",
        entries=[
            CatalogEntry(
                key=PermissionKey("course:view"),
                description="d",
                is_platform=False,
            )
        ],
    )
    msg = _mk_msg(payload)

    await sub._handle(msg)

    msg.nak.assert_awaited_once()
    msg.ack.assert_not_called()
    msg.term.assert_not_called()


async def test_empty_entries_snapshot_still_applied(subscriber):
    """A service that removes its last permission key should still sync
    (the subscriber soft-deletes absent keys regardless of entry count)."""
    sub, repo = subscriber
    payload = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "service_name": "courses",
            "published_at": "2026-04-20T00:00:00+00:00",
            "entries": [],
        }
    ).encode()
    msg = _mk_msg(payload)

    await sub._handle(msg)

    assert len(repo.calls) == 1
    service, entries = repo.calls[0]
    assert service == "courses"
    assert entries == ()
    msg.ack.assert_awaited_once()
