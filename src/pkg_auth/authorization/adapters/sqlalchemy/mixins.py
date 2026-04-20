"""Abstract column mixins for the ACL ORM models.

These mixins provide the ACL-essential columns without defining ``id``,
``__tablename__``, FK columns, or relationships. Consuming services
extend them by creating a concrete model class that inherits from both
their own ``DeclarativeBase`` and the appropriate mixin.

Example (service extends UserMixin)::

    from pkg_auth.authorization.adapters.sqlalchemy.mixins import UserMixin

    class OrmUser(Base, UserMixin):
        __tablename__ = "users"
        id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
        # UserMixin columns inherited automatically
        # Add service-specific columns:
        username: Mapped[str] = mapped_column(String(255))
        bio: Mapped[str | None] = mapped_column(Text)

Services that do NOT need to extend use the default concrete models in
``models.py`` which already inherit these mixins.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column


class UserMixin:
    """ACL columns for the users table."""

    keycloak_sub: Mapped[str] = mapped_column(
        String(64), unique=True, index=True
    )
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


class OrganizationMixin:
    """ACL columns for the organizations table."""

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


class PermissionMixin:
    """ACL columns for the permissions (catalog) table.

    ``is_platform`` distinguishes permissions that operate inside a single
    organization (default) from permissions that only make sense at
    platform/system level across organizations (e.g. ``organizations:create``,
    ``organizations:approve``). Consuming services declare the flag inline
    when registering via :class:`CatalogEntry`; the central ACL UI filters
    by it via the ``scope=`` argument on the catalog repo.
    """

    key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    service_name: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_platform: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class RoleMixin:
    """ACL columns for the roles table."""

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


class MembershipMixin:
    """ACL columns for the memberships table.

    Does NOT include ``status`` — services define their own status type
    (string, enum, etc.). Does NOT include FK columns or relationships
    — those depend on the concrete model's schema and table names.
    """

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
