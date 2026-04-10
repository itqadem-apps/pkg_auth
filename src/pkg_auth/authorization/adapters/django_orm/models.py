"""Django ORM mirror models for the ACL schema.

All models declare ``Meta.managed = False`` because the schema is owned
by the SQLAlchemy adapter's Alembic migrations. The ``db_table`` values
include the ``acl.`` schema prefix using Django's
``'schema"."table'`` quoting trick so queries hit the right schema.
"""
from __future__ import annotations

from django.db import models


class User(models.Model):
    id = models.BigAutoField(primary_key=True)
    keycloak_sub = models.CharField(max_length=64, unique=True)
    email = models.CharField(max_length=255)
    full_name = models.CharField(max_length=255, null=True, blank=True)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'acl"."users'
        app_label = "pkg_auth_acl"


class Organization(models.Model):
    id = models.BigAutoField(primary_key=True)
    slug = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'acl"."organizations'
        app_label = "pkg_auth_acl"


class Permission(models.Model):
    id = models.BigAutoField(primary_key=True)
    key = models.CharField(max_length=255, unique=True)
    service_name = models.CharField(max_length=64)
    description = models.TextField(null=True, blank=True)
    registered_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'acl"."permissions'
        app_label = "pkg_auth_acl"


class Role(models.Model):
    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column="organization_id",
        related_name="roles",
    )
    name = models.CharField(max_length=128)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
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


class Membership(models.Model):
    id = models.BigAutoField(primary_key=True)
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
    joined_at = models.DateTimeField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'acl"."memberships'
        app_label = "pkg_auth_acl"
        unique_together = (("user", "organization"),)


class MembershipInvitation(models.Model):
    id = models.BigAutoField(primary_key=True)
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
    created_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'acl"."membership_invitations'
        app_label = "pkg_auth_acl"


class AuthAuditLog(models.Model):
    id = models.BigAutoField(primary_key=True)
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
    occurred_at = models.DateTimeField()
    request_id = models.CharField(max_length=64, null=True)

    class Meta:
        managed = False
        db_table = 'acl"."auth_audit_log'
        app_label = "pkg_auth_acl"
