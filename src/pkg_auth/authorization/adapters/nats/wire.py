"""Wire format for permission-catalog NATS messages.

Dataclass-based (no pydantic dep) so the serialization surface is
trivially unit-testable and the envelope stays stable across pkg_auth
releases. Breaking changes bump ``SCHEMA_VERSION`` and the subscriber
``term()``s older versions it no longer understands.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from ...application.use_cases.register_permission_catalog import CatalogEntry
from ...domain.value_objects import PermissionKey

SCHEMA_VERSION = 1

CATALOG_SUBJECT_PREFIX = "acl.permissions.catalog"
CATALOG_SUBJECT_WILDCARD = f"{CATALOG_SUBJECT_PREFIX}.>"


def subject_for(service_name: str) -> str:
    """Return the NATS subject a given service publishes its catalog on."""
    return f"{CATALOG_SUBJECT_PREFIX}.{service_name}"


class InvalidCatalogMessage(ValueError):
    """Raised when a NATS payload cannot be decoded into a CatalogMessage.

    Covers malformed JSON, missing required fields, unknown schema
    versions, and type mismatches. The subscriber treats this as a
    poison message and ``term()``s it — the sender is buggy and
    redelivery would not help.
    """


@dataclass(frozen=True, slots=True)
class CatalogMessageEntry:
    key: str
    description: str | None
    is_platform: bool


@dataclass(frozen=True, slots=True)
class CatalogMessage:
    """Full catalog snapshot published by one service on boot."""

    schema_version: int
    service_name: str
    published_at: datetime
    entries: tuple[CatalogMessageEntry, ...]

    def to_catalog_entries(self) -> list[CatalogEntry]:
        return [
            CatalogEntry(
                key=PermissionKey(e.key),
                description=e.description,
                is_platform=e.is_platform,
            )
            for e in self.entries
        ]


def encode_message(
    *,
    service_name: str,
    entries: Sequence[CatalogEntry],
    published_at: datetime | None = None,
) -> bytes:
    """Serialize a catalog snapshot to the NATS payload bytes."""
    ts = published_at or datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "service_name": service_name,
        "published_at": ts.isoformat(),
        "entries": [
            {
                "key": str(entry.key),
                "description": entry.description,
                "is_platform": bool(entry.is_platform),
            }
            for entry in entries
        ],
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_message(data: bytes) -> CatalogMessage:
    """Parse a NATS payload into a CatalogMessage or raise InvalidCatalogMessage."""
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCatalogMessage(f"payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise InvalidCatalogMessage("payload must be a JSON object")

    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise InvalidCatalogMessage(
            f"unsupported schema_version {schema_version!r}; expected {SCHEMA_VERSION}"
        )

    service_name = payload.get("service_name")
    if not isinstance(service_name, str) or not service_name:
        raise InvalidCatalogMessage("service_name must be a non-empty string")

    published_at_raw = payload.get("published_at")
    if not isinstance(published_at_raw, str):
        raise InvalidCatalogMessage("published_at must be an ISO-8601 string")
    try:
        published_at = datetime.fromisoformat(published_at_raw)
    except ValueError as exc:
        raise InvalidCatalogMessage(f"published_at is not ISO-8601: {exc}") from exc

    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise InvalidCatalogMessage("entries must be a list")

    entries: list[CatalogMessageEntry] = []
    for i, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise InvalidCatalogMessage(f"entries[{i}] must be an object")
        key = raw.get("key")
        if not isinstance(key, str) or not key:
            raise InvalidCatalogMessage(f"entries[{i}].key must be a non-empty string")
        description = raw.get("description")
        if description is not None and not isinstance(description, str):
            raise InvalidCatalogMessage(
                f"entries[{i}].description must be a string or null"
            )
        is_platform = raw.get("is_platform", False)
        if not isinstance(is_platform, bool):
            raise InvalidCatalogMessage(
                f"entries[{i}].is_platform must be a boolean"
            )
        entries.append(
            CatalogMessageEntry(
                key=key, description=description, is_platform=is_platform
            )
        )

    return CatalogMessage(
        schema_version=schema_version,
        service_name=service_name,
        published_at=published_at,
        entries=tuple(entries),
    )
