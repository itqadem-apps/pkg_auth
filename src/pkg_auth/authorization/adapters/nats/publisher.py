"""NATS JetStream publisher for permission-catalog snapshots.

Implements :class:`PermissionCatalogPublisher`. Mode B services bind
this into :class:`RegisterPermissionCatalogUseCase` so the lifespan
one-liner ``await register_catalog_use_case.execute(...)`` publishes
the catalog over NATS instead of writing to a DB they don't own.

The publisher uses ``js.publish()`` (not core NATS publish) so the
call only returns after JetStream has durably acked the message. If
NATS is unreachable or the ack times out, the coroutine raises and
the consumer service's boot fails — the right behavior, since running
with a silently-dropped catalog would drift the SoT's role-editor UI
out of sync with reality.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import nats
from nats.aio.client import Client as NatsClient
from nats.js import JetStreamContext

from ...application.use_cases.register_permission_catalog import CatalogEntry
from .wire import encode_message, subject_for


@dataclass(slots=True)
class NatsPermissionCatalogPublisher:
    """Publish catalog snapshots to ``acl.permissions.catalog.<service>``.

    Lazily opens a NATS connection on first publish and reuses it for
    the process lifetime. :meth:`close` disconnects; FastAPI apps can
    wire it into the lifespan shutdown but it's optional — dropping
    the connection at process exit is fine.
    """

    nats_url: str
    publish_timeout_seconds: float = 5.0
    connect_timeout_seconds: float = 5.0
    _nc: NatsClient | None = field(default=None, init=False, repr=False)
    _js: JetStreamContext | None = field(default=None, init=False, repr=False)

    async def _ensure_connected(self) -> JetStreamContext:
        if self._js is not None:
            return self._js
        self._nc = await nats.connect(
            self.nats_url,
            connect_timeout=self.connect_timeout_seconds,
        )
        self._js = self._nc.jetstream()
        return self._js

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntry],
    ) -> None:
        js = await self._ensure_connected()
        payload = encode_message(service_name=service_name, entries=entries)
        await js.publish(
            subject=subject_for(service_name),
            payload=payload,
            timeout=self.publish_timeout_seconds,
        )

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.drain()
            self._nc = None
            self._js = None
