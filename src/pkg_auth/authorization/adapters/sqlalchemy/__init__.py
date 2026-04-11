"""SQLAlchemy adapter for the ACL schema (canonical schema owner via Alembic).

Importing this module requires SQLAlchemy and asyncpg to be installed:

    pip install pkg-auth[acl-sqlalchemy]

The module exposes ``MIGRATIONS_DIR`` so consuming services (notably the
users service) can register the version files via Alembic's
``version_locations`` mechanism. See ``docs/Authorization.md`` for the
wiring pattern.
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
    PermissionMixin,
    RoleMixin,
    UserMixin,
)
from .models import (
    AuthAuditLogORM,
    MembershipInvitationORM,
    MembershipORM,
    OrganizationORM,
    PermissionORM,
    RoleORM,
    RolePermissionORM,
    UserORM,
)
from .repositories.membership import SqlAlchemyMembershipRepository
from .repositories.organization import SqlAlchemyOrganizationRepository
from .repositories.permission_catalog import SqlAlchemyPermissionCatalogRepository
from .repositories.role import SqlAlchemyRoleRepository
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
    # ORM models
    "UserORM",
    "OrganizationORM",
    "PermissionORM",
    "RoleORM",
    "RolePermissionORM",
    "MembershipORM",
    "MembershipInvitationORM",
    "AuthAuditLogORM",
    # Repositories
    "SqlAlchemyUserRepository",
    "SqlAlchemyOrganizationRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyPermissionCatalogRepository",
]
