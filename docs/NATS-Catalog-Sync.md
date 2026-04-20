# NATS permission-catalog sync

Mode B (consumer) services cannot write to the SoT's database, so their boot-time permission-catalog registration is inverted: the consumer **publishes** its catalog over NATS, and itq_users (Mode A) **subscribes** and applies the snapshot to its own ACL tables using its own privileged DB credential. Consumer DB credentials stay `SELECT`-only.

## Topology

```
┌─────────────────┐       ┌─────────────────────────┐       ┌────────────────┐
│  courses (B)    │       │  NATS JetStream stream  │       │  itq_users (A) │
│  RegisterUseCase├──────▶│  acl-permissions-catalog├──────▶│  Subscriber    │
│  (Publisher)    │       │  subject:               │       │  → apply_      │
└─────────────────┘       │   acl.permissions.      │       │    snapshot()  │
                          │   catalog.>             │       └────────┬───────┘
                                                                     │
                                                                     ▼
                                                             ┌────────────────┐
                                                             │ users.permis-  │
                                                             │  sions (ACL)   │
                                                             └────────────────┘
```

## Wire format

Subject: `acl.permissions.catalog.<service_name>` (one subject per service).

Payload (UTF-8 JSON):

```json
{
  "schema_version": 1,
  "service_name": "courses",
  "published_at": "2026-04-20T12:34:56+00:00",
  "entries": [
    {"key": "course:view", "description": "View courses", "is_platform": false},
    {"key": "course:edit", "description": "Edit courses", "is_platform": false}
  ]
}
```

Each message is a **full snapshot**. Any catalog key previously registered under the same `service_name` but absent from the latest snapshot is soft-deleted (`deleted_at = now()`). Soft-delete keeps referential integrity with `role_permissions`.

Breaking changes bump `schema_version`; the subscriber `term()`s older payloads it no longer understands (poison messages, never redelivered).

## JetStream configuration

The subscriber creates the stream on startup if it's missing:

| Setting | Value |
|---|---|
| Stream name | `acl-permissions-catalog` |
| Subjects | `acl.permissions.catalog.>` |
| Retention | `LIMITS` |
| `max_age` | 24 hours |
| Durable consumer | `acl-permissions-catalog-subscriber` |
| `deliver_policy` | `ALL` |
| `ack_wait` | 30s |

Rationale: messages are small, idempotent, and republished on every boot, so 24h retention plus a durable consumer gives plenty of headroom for a brief itq_users outage without needing long-term storage.

## Wiring in a Mode B service

```python
from pkg_auth.authorization.adapters.nats import NatsPermissionCatalogPublisher
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)

catalog_publisher = NatsPermissionCatalogPublisher(
    nats_url=os.environ["NATS_URL"],
)
register_catalog_use_case = RegisterPermissionCatalogUseCase(
    catalog_sink=catalog_publisher,
)
```

FastAPI lifespan:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await register_catalog_use_case.execute(
        service_name=SERVICE_NAME,
        entries=CATALOG,
    )
    try:
        yield
    finally:
        await catalog_publisher.close()
```

If NATS is unreachable or the publish ack times out, the lifespan raises and the service refuses to start. This is intentional: running with a silently-dropped catalog would drift the SoT's role-editor UI out of sync with reality.

## Wiring the subscriber in itq_users

```python
from pkg_auth.authorization.adapters.nats import PermissionCatalogSubscriber
from pkg_auth.authorization.adapters.sqlalchemy import (
    SqlAlchemyPermissionCatalogRepository,
)

catalog_repo = SqlAlchemyPermissionCatalogRepository(session_factory=...)
subscriber = PermissionCatalogSubscriber(
    nats_url=os.environ["NATS_URL"],
    catalog_repo=catalog_repo,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await subscriber.start()
    try:
        yield
    finally:
        await subscriber.stop()
```

itq_users itself does not publish — it registers its own catalog by constructing a `RegisterPermissionCatalogUseCase(catalog_sink=catalog_repo)` (direct DB write), since it owns the tables.

## Error handling

| Condition | Action |
|---|---|
| Decoding fails (bad JSON, wrong schema_version, bad field) | `msg.term()` — poison, never redelivered |
| `apply_snapshot` raises (DB error) | `msg.nak(delay=5s)` — transient, redelivered |
| Publish times out on Mode B boot | Lifespan raises — service refuses to start |
| NATS connection drops mid-consume | JetStream redelivers unacked messages on reconnect |
