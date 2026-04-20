# Authorization Model

`pkg_auth.authorization` provides per-(user, organization) RBAC backed by a Postgres database the package owns.

## Database topology

The ACL tables live **inside the `itq_users` service's database** (Mode A — source of truth), which owns and migrates the schema. Consumer services (Mode B) read from the same tables via their own `SELECT`-only credential. Authorization checks hit this database on every protected request (with an optional in-process or Redis cache in front).

**Catalog writes go over NATS, not SQL.** Mode B services cannot write to the SoT's database, so `RegisterPermissionCatalogUseCase` is wired with a `NatsPermissionCatalogPublisher` on Mode B. itq_users runs a `PermissionCatalogSubscriber` that receives each snapshot and upserts into its own database. See [`NATS-Catalog-Sync.md`](NATS-Catalog-Sync.md) for the wire format and deployment setup.

## Schema (`acl.*`)

The schema lives in a Postgres schema called `acl` and contains:

| Table | Purpose |
|---|---|
| `users` | Lazily upserted from JWT on first sight. FK anchor for memberships. |
| `organizations` | Top-level grouping. Identified by `slug` (string) or `id` (bigint). |
| `permissions` | Global permission catalog. Populated by services on boot. |
| `roles` | Per-org (or global template). Links to permissions via `role_permissions`. |
| `role_permissions` | Many-to-many join between roles and permissions. |
| `memberships` | One row per (user, org). Links user to a role in that org. `UNIQUE(user_id, organization_id)` enforces single-role per (user, org) in v1. |
| `membership_invitations` | Pending invitations for non-member users. |
| `auth_audit_log` | Append-only log of ACL mutations. |

### Applying migrations

The schema is owned by Alembic migrations shipped inside the package:

```python
from pkg_auth.authorization.adapters.sqlalchemy import MIGRATIONS_DIR
```

In your users service's `alembic/env.py`:

```python
config.set_main_option(
    "version_locations",
    f"{config.get_main_option('version_locations')} {MIGRATIONS_DIR}",
)
```

Then: `alembic upgrade pkg_auth_acl@head`

Other services don't run migrations — they connect to the same database the users service migrated.

## Core concepts

### AuthContext

The hot-path authorization primitive. Built once per request by `ResolveAuthContextUseCase` and injected into handlers:

```python
@dataclass(frozen=True, slots=True)
class AuthContext:
    user_id: UserId
    organization_id: OrgId
    role_name: RoleName
    perms: frozenset[str]

    def has(self, perm: str) -> bool: ...
    def require(self, perm: str) -> None: ...  # raises MissingPermission
```

### Permission keys

Permission keys use the `resource:action` format (e.g. `"course:edit"`, `"billing:invoice:refund"`). Each service declares its own keys in code and registers them on boot via `RegisterPermissionCatalogUseCase`. The catalog serves the users service's admin UI for building roles.

### Extending the schema

The users service can extend `users`, `organizations`, and `memberships` with extra fields. Two patterns are supported:

1. **Extension tables** (recommended): create service-owned tables with `REFERENCES acl.users(id)`. Zero coupling to pkg_auth releases.
2. **Direct ALTER** (escape hatch): add columns to `acl.users` with a `usrsvc_` prefix to avoid future collisions.

See the plan file for full details on both patterns.
