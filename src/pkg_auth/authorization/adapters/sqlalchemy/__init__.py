"""SQLAlchemy adapter for the ACL tables.

Importing this module requires SQLAlchemy and asyncpg to be installed:

    pip install pkg-auth[acl-sqlalchemy]

The module exposes ``MIGRATIONS_DIR`` so the source-of-truth service
can register the bundled version files via Alembic's
``version_locations`` mechanism as a starting point — Mode A services
typically evolve the schema further via their own migrations from
that point on. See ``docs/Authorization.md`` for the wiring pattern.
"""
from __future__ import annotations

try:
    import sqlalchemy  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.authorization.adapters.sqlalchemy requires SQLAlchemy. "
        "Install with: pip install pkg-auth[acl-sqlalchemy]"
    ) from exc

from pathlib import Path

from .base import AclBase, create_acl_base
from .mixins import (
    MembershipMixin,
    OrganizationMixin,
    OrganizationServiceMixin,
    PermissionMixin,
    RoleMixin,
    ServiceMixin,
    UserMixin,
)
from .models import (
    AuthAuditLogORM,
    MembershipInvitationORM,
    MembershipORM,
    OrganizationORM,
    OrganizationServiceORM,
    PermissionORM,
    RoleORM,
    RolePermissionORM,
    ServiceORM,
    UserORM,
)
from .repositories.membership import SqlAlchemyMembershipRepository
from .repositories.organization import SqlAlchemyOrganizationRepository
from .repositories.organization_service import (
    SqlAlchemyOrganizationServiceRepository,
)
from .repositories.permission_catalog import SqlAlchemyPermissionCatalogRepository
from .repositories.role import SqlAlchemyRoleRepository
from .repositories.service import SqlAlchemyServiceRepository
from .repositories.user import SqlAlchemyUserRepository

MIGRATIONS_DIR: str = str(Path(__file__).parent / "migrations" / "versions")

__all__ = [
    "AclBase",
    "create_acl_base",
    "MIGRATIONS_DIR",
    # Mixins (for services that extend)
    "UserMixin",
    "OrganizationMixin",
    "PermissionMixin",
    "RoleMixin",
    "MembershipMixin",
    "ServiceMixin",
    "OrganizationServiceMixin",
    # ORM models
    "UserORM",
    "OrganizationORM",
    "PermissionORM",
    "RoleORM",
    "RolePermissionORM",
    "MembershipORM",
    "MembershipInvitationORM",
    "AuthAuditLogORM",
    "ServiceORM",
    "OrganizationServiceORM",
    # Repositories
    "SqlAlchemyUserRepository",
    "SqlAlchemyOrganizationRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyPermissionCatalogRepository",
    "SqlAlchemyServiceRepository",
    "SqlAlchemyOrganizationServiceRepository",
]
