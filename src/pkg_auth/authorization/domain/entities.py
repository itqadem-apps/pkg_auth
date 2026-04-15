"""Authorization domain entities.

All entities are frozen dataclasses with slots. They are loaded from the
central ACL database by the SQLAlchemy / Django ORM repositories and
treated as immutable snapshots. The entities are schema-agnostic — the
concrete ``db_table`` / ``__tablename__`` values live in the adapter
layer, and source-of-truth services that extend the ACL tables (Mode A)
pick their own schema and table names via the mixin pattern.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from .exceptions import MissingPermission
from .value_objects import (
    OrgId,
    PermissionId,
    PermissionKey,
    RoleId,
    RoleName,
    UserId,
)


@dataclass(frozen=True, slots=True)
class User:
    """A row from the ``users`` table.

    The package owns the users table; rows are upserted lazily on the
    first JWT seen by ``SyncUserFromJwtUseCase``. ``keycloak_sub`` is
    the unique link to the IdP identity.
    """

    id: UserId
    keycloak_sub: str
    email: str
    full_name: str | None
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass(frozen=True, slots=True)
class Organization:
    """A row from the ``organizations`` table."""

    id: OrgId
    slug: str
    name: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class Permission:
    """A row from the ``permissions`` table (the global permission catalog).

    Each downstream service registers its own permission keys on boot
    via ``RegisterPermissionCatalogUseCase``. ``is_platform`` marks
    permissions that only apply at the platform/system level (e.g.
    ``organizations:create``) so the central role editor can filter
    them out of org-scoped role builders.
    """

    id: PermissionId
    key: PermissionKey
    service_name: str
    description: str | None
    is_platform: bool = False


@dataclass(frozen=True, slots=True)
class Role:
    """A row from the ``roles`` table.

    ``organization_id`` is ``None`` for global role templates that can
    be reused across organizations. ``permission_keys`` is the
    denormalized set of permission strings the role grants — fast for
    in-memory ``.has(perm)`` checks at the call site.
    """

    id: RoleId
    organization_id: OrgId | None
    name: RoleName
    description: str | None
    permission_keys: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Membership:
    """A row from the ``memberships`` table.

    ``role_name`` is denormalized from the joined role for cheap
    construction of an :class:`AuthContext` without re-querying. A user
    can hold multiple memberships in the same organization — one row per
    role — and the schema enforces uniqueness on
    ``(user_id, organization_id, role_id)``.
    """

    id: UUID
    user_id: UserId
    organization_id: OrgId
    role_id: RoleId
    role_name: RoleName
    status: str
    joined_at: datetime


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Hot-path authorization context for a (user, organization) request.

    Built once per request by ``ResolveAuthContextUseCase`` and passed
    through to handlers. A user can have **multiple roles** in an org;
    ``perms`` is the **union** of all active roles' permissions.

    Frozen because handler code must not mutate the perms set after the
    dependency layer has built it.

    pkg_auth deliberately does NOT carry a ``is_platform`` flag here.
    Platform-admin detection is a *service-level* policy: consuming
    services cache their platform org's id at startup and call
    :func:`pkg_auth.authorization.is_platform_context` to compare against
    ``self.organization_id``. See the package docs for the pattern.
    """

    user_id: UserId
    organization_id: OrgId
    role_names: frozenset[str]
    perms: frozenset[str]

    def has(self, perm: str) -> bool:
        """Return ``True`` if any of the user's roles grant ``perm``."""
        return perm in self.perms

    def require(self, perm: str) -> None:
        """Raise :class:`MissingPermission` if ``perm`` is not granted.

        Equivalent to ``if not ctx.has(perm): raise MissingPermission(...)``
        but exported as a method for ergonomic ``ctx.require("course:edit")``
        call sites.
        """
        if perm not in self.perms:
            raise MissingPermission(
                f"permission {perm!r} required on org {self.organization_id} "
                f"(roles {sorted(self.role_names)})"
            )

    def has_role(self, role: str) -> bool:
        """Return ``True`` if the user has the named role in this org."""
        return role in self.role_names
