"""NATS JetStream subscriber that applies catalog snapshots to the ACL DB.

Runs inside the Mode A (source-of-truth) service. Listens on
``acl.permissions.catalog.>`` with a durable pull consumer so
messages published while the subscriber is offline are delivered
on reconnect.

Message handling:

- Valid message → ``apply_snapshot`` UPSERTs the snapshot and
  soft-deletes absent keys for that ``service_name``, then ``ack()``.
- Decoding / schema error → ``term()``: redelivery wouldn't help;
  the publisher is buggy. Logged at error.
- Repository / DB error → ``nak()``: transient, let JetStream redeliver.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Protocol, Sequence

import nats
from nats.aio.client import Client as NatsClient
from nats.aio.msg import Msg
from nats.js import JetStreamContext
from nats.js.api import (
    ConsumerConfig,
    DeliverPolicy,
    RetentionPolicy,
    StreamConfig,
)
from nats.js.errors import BadRequestError

from ...application.use_cases.register_permission_catalog import CatalogEntry
from .wire import (
    CATALOG_SUBJECT_WILDCARD,
    InvalidCatalogMessage,
    decode_message,
)

logger = logging.getLogger(__name__)


class _SnapshotRepo(Protocol):
    async def apply_snapshot(
        self,
        *,
        service_name: str,
        entries: Sequence[CatalogEntry],
    ) -> None: ...


DEFAULT_STREAM_NAME = "acl-permissions-catalog"
DEFAULT_DURABLE_NAME = "acl-permissions-catalog-subscriber"


@dataclass(slots=True)
class PermissionCatalogSubscriber:
    """Durable JetStream consumer that applies catalog snapshots.

    The subscriber owns its own NATS connection; call :meth:`start` in
    the FastAPI lifespan before ``yield`` and :meth:`stop` after.
    """

    nats_url: str
    catalog_repo: _SnapshotRepo
    stream_name: str = DEFAULT_STREAM_NAME
    durable_name: str = DEFAULT_DURABLE_NAME
    subject: str = CATALOG_SUBJECT_WILDCARD
    fetch_batch: int = 16
    fetch_timeout_seconds: float = 5.0
    connect_timeout_seconds: float = 5.0
    nak_delay_seconds: float = 5.0
    _nc: NatsClient | None = field(default=None, init=False, repr=False)
    _js: JetStreamContext | None = field(default=None, init=False, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _stopping: asyncio.Event = field(
        default_factory=asyncio.Event, init=False, repr=False
    )

    async def start(self) -> None:
        if self._task is not None:
            return
        self._nc = await nats.connect(
            self.nats_url,
            connect_timeout=self.connect_timeout_seconds,
        )
        self._js = self._nc.jetstream()
        await self._ensure_stream(self._js)
        self._stopping.clear()
        self._task = asyncio.create_task(
            self._run(), name="pkg_auth-catalog-subscriber"
        )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._nc is not None:
            await self._nc.drain()
            self._nc = None
            self._js = None

    async def _ensure_stream(self, js: JetStreamContext) -> None:
        config = StreamConfig(
            name=self.stream_name,
            subjects=[self.subject],
            retention=RetentionPolicy.LIMITS,
            max_age=24 * 60 * 60,
        )
        try:
            await js.add_stream(config=config)
        except BadRequestError:
            await js.update_stream(config=config)

    async def _run(self) -> None:
        assert self._js is not None
        psub = await self._js.pull_subscribe(
            subject=self.subject,
            durable=self.durable_name,
            config=ConsumerConfig(
                durable_name=self.durable_name,
                deliver_policy=DeliverPolicy.ALL,
                ack_wait=30,
            ),
        )
        while not self._stopping.is_set():
            try:
                msgs = await psub.fetch(
                    batch=self.fetch_batch,
                    timeout=self.fetch_timeout_seconds,
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("catalog subscriber fetch error")
                await asyncio.sleep(1.0)
                continue
            for msg in msgs:
                await self._handle(msg)

    async def _handle(self, msg: Msg) -> None:
        try:
            message = decode_message(msg.data)
        except InvalidCatalogMessage as exc:
            logger.error(
                "poison catalog message on %s: %s", msg.subject, exc
            )
            await msg.term()
            return
        try:
            await self.catalog_repo.apply_snapshot(
                service_name=message.service_name,
                entries=message.to_catalog_entries(),
            )
        except Exception:
            logger.exception(
                "failed to apply catalog snapshot for %s; nak",
                message.service_name,
            )
            await msg.nak(delay=self.nak_delay_seconds)
            return
        await msg.ack()
        logger.info(
            "applied catalog snapshot for service=%s entries=%d",
            message.service_name,
            len(message.entries),
        )
