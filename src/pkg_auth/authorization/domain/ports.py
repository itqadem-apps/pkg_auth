"""Authorization domain ports (Protocol-based repositories).

These Protocols are the contract between the application layer and the
adapter layer. Adapters live under ``pkg_auth.authorization.adapters``
(SQLAlchemy, Django ORM, cache decorator). The application layer imports
only from this module; it must not import any concrete adapter.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Protocol, Sequence

from .entities import (
    AuthContext,
    Membership,
    Organization,
    Permission,
    Role,
    User,
)
from .value_objects import (
    OrgId,
    PermissionKey,
    RoleId,
    RoleName,
    UserId,
)

if TYPE_CHECKING:
    from ..application.use_cases.register_permission_catalog import (
        CatalogEntry,
    )

PermissionScope = Literal["org", "platform", "all"]


class UserRepository(Protocol):
    """Read/write access to the ``users`` table.

    The package lazily upserts users on first JWT sight via
    :meth:`upsert_from_identity`; explicit creation is not exposed.
    """

    async def get_by_id(self, user_id: UserId) -> User | None: ...
    async def get_by_keycloak_sub(self, sub: str) -> User | None: ...
    async def upsert_from_identity(
        self,
        *,
        sub: str,
        email: str,
        full_name: str | None,
    ) -> User: ...


class OrganizationRepository(Protocol):
    """Read/write access to the ``organizations`` table."""

    async def get(self, org_id: OrgId) -> Organization | None: ...
    async def get_by_slug(self, slug: str) -> Organization | None: ...
    async def create(self, *, slug: str, name: str) -> Organization: ...
    async def update(
        self, org_id: OrgId, *, name: str | None
    ) -> Organization: ...
    async def delete(self, org_id: OrgId) -> None: ...
    async def list_for_user(self, user_id: UserId) -> list[Organization]: ...


class RoleRepository(Protocol):
    """Read/write access to the ``roles`` table (and the ``role_permissions`` join)."""

    async def get(self, role_id: RoleId) -> Role | None: ...
    async def get_by_name(
        self, org_id: OrgId | None, name: RoleName
    ) -> Role | None: ...
    async def create(
        self,
        *,
        org_id: OrgId | None,
        name: RoleName,
        description: str | None,
        permission_keys: Sequence[PermissionKey],
    ) -> Role: ...
    async def update(
        self,
        role_id: RoleId,
        *,
        name: RoleName | None,
        description: str | None,
        permission_keys: Sequence[PermissionKey] | None,
    ) -> Role: ...
    async def delete(self, role_id: RoleId) -> None: ...


class MembershipRepository(Protocol):
    """Read/write access to the ``memberships`` table.

    The hot path is :meth:`load_auth_context`, which the FastAPI / Django /
    Strawberry deps call on every protected request. SQLAlchemy / Django
    implementations should do this in one query (joined with the role and
    its permissions) so the call site never round-trips for individual
    perms.
    """

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> Membership | None: ...
    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> Membership: ...
    async def delete(self, user_id: UserId, org_id: OrgId) -> None: ...
    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None: ...
    async def list_for_user(self, user_id: UserId) -> list[Membership]: ...


class PermissionCatalogRepository(Protocol):
    """Read/write access to the ``permissions`` table (the global perm catalog).

    The ``scope`` argument on the list methods filters by the
    ``is_platform`` flag on each catalog row:

    - ``"org"``      → only permissions usable inside an organization
    - ``"platform"`` → only platform/system-level permissions
    - ``"all"``      → no filter (default)
    """

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence["CatalogEntry"],
    ) -> None: ...
    async def list_all(
        self, *, scope: PermissionScope = "all"
    ) -> list[Permission]: ...
    async def list_for_service(
        self, service_name: str, *, scope: PermissionScope = "all"
    ) -> list[Permission]: ...
