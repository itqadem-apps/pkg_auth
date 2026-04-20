"""NATS publisher encodes the envelope and calls js.publish."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.adapters.nats import (
    NatsPermissionCatalogPublisher,
    decode_message,
    subject_for,
)


@pytest.fixture
def publisher():
    p = NatsPermissionCatalogPublisher(nats_url="nats://ignored:4222")
    p._js = AsyncMock()  # skip real connect
    return p


async def test_publishes_to_service_specific_subject(publisher):
    await publisher.register_many(
        service_name="courses",
        entries=[
            CatalogEntry(
                key=PermissionKey("course:view"),
                description="View courses",
                is_platform=False,
            )
        ],
    )
    publisher._js.publish.assert_awaited_once()
    kwargs = publisher._js.publish.await_args.kwargs
    assert kwargs["subject"] == subject_for("courses")


async def test_publish_payload_round_trips_through_decode(publisher):
    entries = [
        CatalogEntry(
            key=PermissionKey("course:view"),
            description="View",
            is_platform=False,
        ),
        CatalogEntry(
            key=PermissionKey("organizations:create"),
            description=None,
            is_platform=True,
        ),
    ]
    await publisher.register_many(service_name="courses", entries=entries)

    payload = publisher._js.publish.await_args.kwargs["payload"]
    decoded = decode_message(payload)
    assert decoded.service_name == "courses"
    assert [e.key for e in decoded.entries] == [
        "course:view",
        "organizations:create",
    ]
    assert [e.is_platform for e in decoded.entries] == [False, True]


async def test_publish_propagates_nats_errors(publisher):
    publisher._js.publish.side_effect = TimeoutError("nats down")
    with pytest.raises(TimeoutError):
        await publisher.register_many(
            service_name="courses",
            entries=[
                CatalogEntry(
                    key=PermissionKey("course:view"),
                    description="d",
                    is_platform=False,
                )
            ],
        )


async def test_publish_uses_configured_timeout():
    publisher = NatsPermissionCatalogPublisher(
        nats_url="nats://ignored:4222",
        publish_timeout_seconds=2.5,
    )
    publisher._js = AsyncMock()
    await publisher.register_many(
        service_name="courses",
        entries=[
            CatalogEntry(
                key=PermissionKey("course:view"),
                description="d",
                is_platform=False,
            )
        ],
    )
    assert publisher._js.publish.await_args.kwargs["timeout"] == 2.5
