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

    ``is_platform`` distinguishes permissions that operate inside a single
    organization (default) from permissions that only make sense at
    platform/system level across organizations.
    """

    key = models.CharField(max_length=255, unique=True)
    service_name = models.CharField(max_length=64)
    description = models.TextField(null=True, blank=True)
    is_platform = models.BooleanField(default=False)
    registered_at = models.DateTimeField(auto_now=True)

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
