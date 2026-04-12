"""Default concrete Django ORM mirror models for the ACL schema (UUID PKs).

These models declare ``Meta.managed = False`` because the schema is owned
by the SQLAlchemy adapter's Alembic migrations. The ``db_table`` values
include the ``acl.`` schema prefix using Django's ``'schema"."table'``
quoting trick so queries hit the right schema.

Services that need to extend the ACL tables with their own columns
should NOT import these. Instead, they create their own concrete models
inheriting from the abstract mixins in ``mixins.py`` and own the
schema (managed=True) themselves.
"""
from __future__ import annotations

import uuid

from django.db import models

from .mixins import (
    MembershipMixin,
    OrganizationMixin,
    PermissionMixin,
    RoleMixin,
    UserMixin,
)


class User(UserMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = 'acl"."users'
        app_label = "pkg_auth_acl"


class Organization(OrganizationMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = 'acl"."organizations'
        app_label = "pkg_auth_acl"


class Permission(PermissionMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = 'acl"."permissions'
        app_label = "pkg_auth_acl"


class Role(RoleMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column="organization_id",
        related_name="roles",
    )
    permissions = models.ManyToManyField(
        Permission,
        through="RolePermission",
        related_name="roles",
    )

    class Meta:
        managed = False
        db_table = 'acl"."roles'
        app_label = "pkg_auth_acl"
        unique_together = (("organization", "name"),)


class RolePermission(models.Model):
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        db_column="role_id",
        related_name="role_permissions",
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        db_column="permission_id",
        related_name="role_permissions",
    )

    class Meta:
        managed = False
        db_table = 'acl"."role_permissions'
        app_label = "pkg_auth_acl"
        unique_together = (("role", "permission"),)


class Membership(MembershipMixin):
    """Multi-role-aware: ``UNIQUE(user, organization, role)``.

    A user can hold multiple memberships in the same organization (one row
    per role); ``DjangoMembershipRepository.load_auth_context`` aggregates
    them into the union of all active roles' permissions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        db_column="user_id",
        related_name="memberships",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        db_column="organization_id",
        related_name="memberships",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        db_column="role_id",
        related_name="memberships",
    )
    status = models.CharField(max_length=32, default="active")

    class Meta:
        managed = False
        db_table = 'acl"."memberships'
        app_label = "pkg_auth_acl"
        unique_together = (("user", "organization", "role"),)


class MembershipInvitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        db_column="organization_id",
    )
    email = models.CharField(max_length=255)
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        db_column="role_id",
    )
    token = models.CharField(max_length=64, unique=True)
    invited_by_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        db_column="invited_by_user_id",
    )
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = 'acl"."membership_invitations'
        app_label = "pkg_auth_acl"


class AuthAuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        db_column="actor_user_id",
    )
    action = models.CharField(max_length=128)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=64)
    payload = models.JSONField()
    occurred_at = models.DateTimeField(auto_now_add=True)
    request_id = models.CharField(max_length=64, null=True)

    class Meta:
        managed = False
        db_table = 'acl"."auth_audit_log'
        app_label = "pkg_auth_acl"
