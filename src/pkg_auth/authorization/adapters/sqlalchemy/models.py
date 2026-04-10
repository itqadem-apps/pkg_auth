"""SQLAlchemy 2.x ORM models for the ACL schema.

The schema lives in ``acl.*``. The same logical schema is also mirrored
by the Django ORM adapter under ``adapters/django_orm/`` with
``managed = False``; both ORMs query the same physical tables that the
Alembic migration owns.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import AclBase


class UserORM(AclBase):
    """Row in ``acl.users``. Synced lazily from JWT claims on first sight."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    keycloak_sub: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class OrganizationORM(AclBase):
    """Row in ``acl.organizations``."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    roles: Mapped[list["RoleORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class PermissionORM(AclBase):
    """Row in ``acl.permissions`` (the global permission catalog).

    Each downstream service registers its own permission keys on boot
    via :class:`RegisterPermissionCatalogUseCase`.
    """

    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    service_name: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class RoleORM(AclBase):
    """Row in ``acl.roles``.

    ``organization_id`` is nullable: ``NULL`` denotes a global role
    template that can be reused across organizations.
    """

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("acl.organizations.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    organization: Mapped[OrganizationORM | None] = relationship(
        back_populates="roles"
    )
    permissions: Mapped[list[PermissionORM]] = relationship(
        secondary="acl.role_permissions"
    )
    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="role"
    )


class RolePermissionORM(AclBase):
    """Many-to-many join between ``roles`` and ``permissions``."""

    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("acl.roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("acl.permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )


class MembershipORM(AclBase):
    """Row in ``acl.memberships``.

    A user belongs to an organization with exactly one role (v1 single-
    role constraint enforced via the UNIQUE on ``(user_id, organization_id)``).
    """

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "organization_id", name="uq_memberships_user_org"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("acl.users.id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("acl.organizations.id", ondelete="CASCADE"),
        index=True,
    )
    role_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("acl.roles.id", ondelete="RESTRICT"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), server_default="active")
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped[UserORM] = relationship(back_populates="memberships")
    organization: Mapped[OrganizationORM] = relationship(back_populates="memberships")
    role: Mapped[RoleORM] = relationship(back_populates="memberships")


class MembershipInvitationORM(AclBase):
    """Pending invitations for non-existent or non-member users."""

    __tablename__ = "membership_invitations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("acl.organizations.id", ondelete="CASCADE")
    )
    email: Mapped[str] = mapped_column(String(255), index=True)
    role_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("acl.roles.id", ondelete="RESTRICT")
    )
    token: Mapped[str] = mapped_column(String(64), unique=True)
    invited_by_user_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("acl.users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuthAuditLogORM(AclBase):
    """Append-only audit log for authorization-related actions.

    Services-specific audit context belongs in service-owned tables;
    this one only records ACL-level mutations (role changes, membership
    grants, etc.).
    """

    __tablename__ = "auth_audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("acl.users.id", ondelete="SET NULL"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
    request_id: Mapped[str | None] = mapped_column(String(64))
