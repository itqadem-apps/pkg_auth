"""Authorization module: full ACL on top of pkg_auth.authentication.

Public API:

    Entities:        User, Organization, Permission, Role, Membership, AuthContext
    Value objects:   UserId, OrgId, RoleId, PermissionId, RoleName, PermissionKey
    Ports:           UserRepository, OrganizationRepository, RoleRepository,
                     MembershipRepository, PermissionCatalogRepository
    Exceptions:      AuthorizationError, NotAMember, MissingPermission,
                     UnknownOrganization, UnknownUser, UnknownRole,
                     UserNotProvisioned

The application layer (use cases) is added in M3; SQLAlchemy / Django ORM
adapters in M4 / M6; cache layer in M5; framework integrations in M7-M9.
"""
from __future__ import annotations

from .application.use_cases.register_permission_catalog import CatalogEntry
from .domain.entities import (
    AuthContext,
    Membership,
    Organization,
    Permission,
    Role,
    User,
)
from .platform import is_platform_context
from .domain.exceptions import (
    AuthorizationError,
    MissingPermission,
    NotAMember,
    UnknownOrganization,
    UnknownPermission,
    UnknownRole,
    UnknownUser,
    UserNotProvisioned,
)
from .domain.ports import (
    MembershipRepository,
    OrganizationRepository,
    PermissionCatalogRepository,
    PermissionScope,
    RoleRepository,
    UserRepository,
)
from .domain.value_objects import (
    OrgId,
    PermissionId,
    PermissionKey,
    RoleId,
    RoleName,
    UserId,
)

__all__ = [
    # Entities
    "User",
    "Organization",
    "Permission",
    "Role",
    "Membership",
    "AuthContext",
    # Value objects
    "UserId",
    "OrgId",
    "RoleId",
    "PermissionId",
    "RoleName",
    "PermissionKey",
    # Ports (Protocols)
    "UserRepository",
    "OrganizationRepository",
    "RoleRepository",
    "MembershipRepository",
    "PermissionCatalogRepository",
    # Application DTOs
    "CatalogEntry",
    "PermissionScope",
    # Platform helpers
    "is_platform_context",
    # Exceptions
    "AuthorizationError",
    "NotAMember",
    "MissingPermission",
    "UnknownOrganization",
    "UnknownUser",
    "UnknownRole",
    "UnknownPermission",
    "UserNotProvisioned",
]
