"""Default concrete ORM models for the ACL schema (UUID PKs).

These models use ``AclBase`` (schema ``"acl"``) and are ready to use
out of the box for services that don't need to extend the tables. They
inherit ACL columns from the mixins in ``mixins.py``.

Services that need extra columns (like itq_users) should NOT import
these. Instead, they create their own concrete models by inheriting
from their own ``DeclarativeBase`` + the mixins.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import AclBase
from .mixins import (
    MembershipMixin,
    OrganizationMixin,
    PermissionMixin,
    RoleMixin,
    UserMixin,
)


class UserORM(AclBase, UserMixin):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class OrganizationORM(AclBase, OrganizationMixin):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    roles: Mapped[list["RoleORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class PermissionORM(AclBase, PermissionMixin):
    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )


class RoleORM(AclBase, RoleMixin):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.organizations.id", ondelete="CASCADE"),
        index=True,
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
    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )


class MembershipORM(AclBase, MembershipMixin):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "organization_id", "role_id",
            name="uq_memberships_user_org_role",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.users.id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.organizations.id", ondelete="CASCADE"),
        index=True,
    )
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.roles.id", ondelete="RESTRICT"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), server_default="active")

    user: Mapped[UserORM] = relationship(back_populates="memberships")
    organization: Mapped[OrganizationORM] = relationship(
        back_populates="memberships"
    )
    role: Mapped[RoleORM] = relationship(back_populates="memberships")


class MembershipInvitationORM(AclBase):
    __tablename__ = "membership_invitations"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.organizations.id", ondelete="CASCADE"),
    )
    email: Mapped[str] = mapped_column(String(255), index=True)
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.roles.id", ondelete="RESTRICT"),
    )
    token: Mapped[str] = mapped_column(String(64), unique=True)
    invited_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("acl.users.id", ondelete="SET NULL"),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuthAuditLogORM(AclBase):
    __tablename__ = "auth_audit_log"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
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
