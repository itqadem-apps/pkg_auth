"""Wire-format serialization for catalog NATS messages."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from pkg_auth.authorization import CatalogEntry, PermissionKey
from pkg_auth.authorization.adapters.nats import (
    SCHEMA_VERSION,
    InvalidCatalogMessage,
    decode_message,
    encode_message,
    subject_for,
)


def _entry(key: str, desc: str | None = "d", platform: bool = False) -> CatalogEntry:
    return CatalogEntry(
        key=PermissionKey(key), description=desc, is_platform=platform
    )


def test_subject_for_service_uses_expected_prefix():
    assert subject_for("courses") == "acl.permissions.catalog.courses"


def test_encode_decode_round_trip_preserves_fields():
    entries = [
        _entry("course:view", "View courses", platform=False),
        _entry("organizations:create", None, platform=True),
    ]
    published_at = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)

    payload = encode_message(
        service_name="courses", entries=entries, published_at=published_at
    )
    message = decode_message(payload)

    assert message.schema_version == SCHEMA_VERSION
    assert message.service_name == "courses"
    assert message.published_at == published_at
    assert len(message.entries) == 2
    assert message.entries[0].key == "course:view"
    assert message.entries[0].description == "View courses"
    assert message.entries[0].is_platform is False
    assert message.entries[1].key == "organizations:create"
    assert message.entries[1].description is None
    assert message.entries[1].is_platform is True


def test_decode_rejects_unknown_schema_version():
    bad = json.dumps(
        {
            "schema_version": 999,
            "service_name": "courses",
            "published_at": "2026-04-20T00:00:00+00:00",
            "entries": [],
        }
    ).encode()
    with pytest.raises(InvalidCatalogMessage, match="schema_version"):
        decode_message(bad)


def test_decode_rejects_missing_service_name():
    bad = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "published_at": "2026-04-20T00:00:00+00:00",
            "entries": [],
        }
    ).encode()
    with pytest.raises(InvalidCatalogMessage, match="service_name"):
        decode_message(bad)


def test_decode_rejects_malformed_json():
    with pytest.raises(InvalidCatalogMessage, match="JSON"):
        decode_message(b"not json")


def test_decode_rejects_bad_entry_shape():
    bad = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "service_name": "courses",
            "published_at": "2026-04-20T00:00:00+00:00",
            "entries": [{"key": "", "description": "x", "is_platform": False}],
        }
    ).encode()
    with pytest.raises(InvalidCatalogMessage, match=r"entries\[0\].key"):
        decode_message(bad)


def test_to_catalog_entries_returns_permission_key_typed_values():
    payload = encode_message(
        service_name="courses", entries=[_entry("course:view")]
    )
    message = decode_message(payload)
    [entry] = message.to_catalog_entries()
    assert isinstance(entry, CatalogEntry)
    assert isinstance(entry.key, PermissionKey)
    assert str(entry.key) == "course:view"
