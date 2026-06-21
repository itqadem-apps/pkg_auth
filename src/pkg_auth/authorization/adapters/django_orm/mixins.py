"""Abstract Django model mixins for the ACL schema.

These are the Django analog of the SQLAlchemy mixins in
``pkg_auth.authorization.adapters.sqlalchemy.mixins`` — they declare the
ACL-essential columns without specifying ``id``, ``db_table``, FK columns,
or relationships. Consuming services that want to extend an ACL table
with their own columns subclass the mixin and provide their own concrete
``Meta`` (``abstract = False``).

Example (service extends UserMixin)::

    from pkg_auth.authorization.adapters.django_orm.mixins import UserMixin

    class User(UserMixin):
        id = models.UUIDField(primary_key=True, default=uuid.uuid4)
        username = models.CharField(max_length=255)

        class Meta:
            db_table = "users"
            app_label = "accounts"

Services that do NOT need to extend use the default concrete models in
``models.py`` (managed=False mirrors) directly.
"""
from __future__ import annotations

from django.db import models


class UserMixin(models.Model):
    """ACL columns for the users table."""

    keycloak_sub = models.CharField(max_length=64, unique=True)
    email = models.CharField(max_length=255)
    full_name = models.CharField(max_length=255, null=True, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class OrganizationMixin(models.Model):
    """ACL columns for the organizations table."""

    slug = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class PermissionMixin(models.Model):
    """ACL columns for the permissions (catalog) table.

    ``visibility`` controls which role builders may see/use the permission:
    ``platform_only`` (platform org only), ``shared`` (everywhere, default),
    or ``tenant_only`` (normal orgs only — hidden from the platform org).
    ``description`` is a localized JSONB ``{locale: text}`` map.
    """

    key = models.CharField(max_length=255, unique=True)
    service_name = models.CharField(max_length=64)
    description = models.JSONField(null=True, blank=True)
    visibility = models.CharField(max_length=32, default="shared")
    registered_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class ServiceMixin(models.Model):
    """ACL columns for the ``services`` table (the service registry).

    ``auto_provision`` and ``saas_available`` are vendor-controlled and set
    only via the ``pkg-auth-sync-services`` path. ``display_label`` is a
    localized JSONB map.
    """

    name = models.CharField(max_length=64, unique=True)
    display_label = models.JSONField(null=True, blank=True)
    auto_provision = models.BooleanField(default=False)
    saas_available = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class OrganizationServiceMixin(models.Model):
    """ACL columns for the ``organization_services`` table (per-org service
    entitlements). The FK to organizations lives on the concrete model.
    """

    service_name = models.CharField(max_length=64)
    enabled = models.BooleanField(default=True)
    source = models.CharField(max_length=16, default="manual")
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class RoleMixin(models.Model):
    """ACL columns for the roles table."""

    name = models.CharField(max_length=128)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"


class MembershipMixin(models.Model):
    """ACL columns for the memberships table.

    Does NOT include ``status`` — services define their own status type
    (string, choices field, etc.). Does NOT include FK columns or
    relationships — those depend on the concrete model's schema and
    table names.
    """

    joined_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        app_label = "pkg_auth_acl"
