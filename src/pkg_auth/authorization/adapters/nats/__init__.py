"""NATS adapters for permission-catalog sync.

Mode B (consumer) services bind :class:`NatsPermissionCatalogPublisher`
into :class:`RegisterPermissionCatalogUseCase` in place of a repository,
so boot-time registration goes out over NATS instead of a cross-database
SQL write. Mode A (the source-of-truth) runs
:class:`PermissionCatalogSubscriber` in its lifespan; the subscriber
receives each consumer's snapshot and applies it to the local ACL DB
via :meth:`SqlAlchemyPermissionCatalogRepository.apply_snapshot`.

See ``docs/NATS-Catalog-Sync.md`` for the wire format and deployment
topology.
"""
from __future__ import annotations

from .publisher import NatsPermissionCatalogPublisher
from .subscriber import PermissionCatalogSubscriber
from .wire import (
    CATALOG_SUBJECT_PREFIX,
    CATALOG_SUBJECT_WILDCARD,
    SCHEMA_VERSION,
    CatalogMessage,
    CatalogMessageEntry,
    InvalidCatalogMessage,
    decode_message,
    encode_message,
    subject_for,
)

__all__ = [
    "NatsPermissionCatalogPublisher",
    "PermissionCatalogSubscriber",
    "CATALOG_SUBJECT_PREFIX",
    "CATALOG_SUBJECT_WILDCARD",
    "SCHEMA_VERSION",
    "CatalogMessage",
    "CatalogMessageEntry",
    "InvalidCatalogMessage",
    "decode_message",
    "encode_message",
    "subject_for",
]
