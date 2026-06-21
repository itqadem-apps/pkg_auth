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
from sqlalchemy.dialects.postgresql import JSONB
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

    ``visibility`` controls which role builders may see/use the permission:
    ``platform_only`` (platform org only), ``shared`` (everywhere, default),
    or ``tenant_only`` (normal orgs only — hidden from the platform org).
    Consuming services declare it inline via :class:`CatalogEntry`; the
    central ACL UI filters by it via the ``scope=`` argument on the catalog
    repo. ``description`` is a localized JSONB map (``{locale: text}``).
    """

    key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    service_name: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[dict | None] = mapped_column(JSONB)
    visibility: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="shared",
        server_default=text("'shared'"),
        index=True,
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class ServiceMixin:
    """ACL columns for the ``services`` table (the service registry).

    ``auto_provision`` and ``saas_available`` are vendor-controlled and set
    only via the ``pkg-auth-sync-services`` path. ``display_label`` is a
    localized JSONB map.
    """

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_label: Mapped[dict | None] = mapped_column(JSONB)
    auto_provision: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    saas_available: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class OrganizationServiceMixin:
    """ACL columns for the ``organization_services`` table (per-org service
    entitlements). FK columns and the ``(organization_id, service_name)``
    unique constraint live on the concrete model.
    """

    service_name: Mapped[str] = mapped_column(String(64), index=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'manual'")
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
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
