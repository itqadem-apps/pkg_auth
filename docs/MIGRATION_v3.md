# Migrating from pkg_auth v2.x to v3.0

v3.0 moves permission-catalog writes off Mode B consumers and onto NATS. Consumer services that used to UPSERT into the SoT's `permissions` table on boot now **publish** their catalog to NATS instead, and itq_users subscribes and performs the writes.

Motivation: Vault-minted DB credentials for Mode B services are now `SELECT`-only and scoped to each service's own database, so the previous cross-database write path is gone by design. See [`NATS-Catalog-Sync.md`](NATS-Catalog-Sync.md) for the full architecture.

## Breaking changes

### 1. `RegisterPermissionCatalogUseCase` field rename

`catalog_repo=` → `catalog_sink=`. The new field is typed as `PermissionCatalogRepository | PermissionCatalogPublisher` so the same use case accepts either adapter.

**Before (v2.x):**

```python
register_catalog_use_case = RegisterPermissionCatalogUseCase(
    catalog_repo=SqlAlchemyPermissionCatalogRepository(...),
)
```

**After (v3.0) — Mode B:**

```python
from pkg_auth.authorization.adapters.nats import NatsPermissionCatalogPublisher

catalog_publisher = NatsPermissionCatalogPublisher(nats_url=os.environ["NATS_URL"])
register_catalog_use_case = RegisterPermissionCatalogUseCase(
    catalog_sink=catalog_publisher,
)
```

**After (v3.0) — Mode A (itq_users):**

```python
register_catalog_use_case = RegisterPermissionCatalogUseCase(
    catalog_sink=SqlAlchemyPermissionCatalogRepository(...),  # direct DB write
)
```

### 2. `nats-py` is now a hard dependency

`nats-py>=2.6` is a runtime dependency of pkg_auth. No extras flag needed. Tests mock the client directly.

### 3. New `deleted_at` column on `permissions`

Alembic revision `pkg_auth_acl_0003` adds a nullable `deleted_at timestamp with time zone`. The subscriber stamps this column on catalog keys absent from a service's latest snapshot. `list_all()` / `list_for_service()` filter out rows where `deleted_at IS NOT NULL`.

Run migrations on the SoT:

```bash
alembic upgrade head
```

### 4. itq_users must run the subscriber

Add to itq_users' FastAPI lifespan:

```python
from pkg_auth.authorization.adapters.nats import PermissionCatalogSubscriber

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

Without this, consumer boot-time catalog updates accumulate in the JetStream queue and do not reach the DB.

## Non-breaking

- `PermissionCatalogRepository` Protocol is unchanged.
- `list_all()` / `list_for_service()` signatures are unchanged; they now implicitly filter out soft-deleted rows, which is the intended semantic.
- `CatalogEntry` and legacy tuple inputs to `execute()` are unchanged.
