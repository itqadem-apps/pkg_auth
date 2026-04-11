"""Initial ACL schema.

Revision ID: pkg_auth_acl_0001
Revises:
Create Date: 2026-04-10 00:00:00.000000

This migration creates the entire ``acl.*`` schema in one shot:
``users``, ``organizations``, ``permissions``, ``roles``,
``role_permissions``, ``memberships``, ``membership_invitations``,
``auth_audit_log``.

It uses an explicit, deterministic revision id (``pkg_auth_acl_0001``)
and a branch label (``pkg_auth_acl``) so consuming services can register
this directory via Alembic ``version_locations`` and run
``alembic upgrade pkg_auth_acl@head`` to apply just this branch.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = ("pkg_auth_acl",)
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS acl")

    # ----- users ---------------------------------------------------------- #
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("keycloak_sub", sa.String(64), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("keycloak_sub", name="uq_users_keycloak_sub"),
        schema="acl",
    )
    op.create_index(
        "ix_users_keycloak_sub", "users", ["keycloak_sub"], schema="acl"
    )
    op.create_index("ix_users_email", "users", ["email"], schema="acl")

    # ----- organizations -------------------------------------------------- #
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
        schema="acl",
    )
    op.create_index(
        "ix_organizations_slug", "organizations", ["slug"], schema="acl"
    )

    # ----- permissions ---------------------------------------------------- #
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("service_name", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
        schema="acl",
    )
    op.create_index("ix_permissions_key", "permissions", ["key"], schema="acl")
    op.create_index(
        "ix_permissions_service_name",
        "permissions",
        ["service_name"],
        schema="acl",
    )

    # ----- roles ---------------------------------------------------------- #
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
        schema="acl",
    )
    op.create_index(
        "ix_roles_organization_id", "roles", ["organization_id"], schema="acl"
    )

    # ----- role_permissions ---------------------------------------------- #
    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.roles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "permission_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.permissions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        schema="acl",
    )

    # ----- memberships --------------------------------------------------- #
    op.create_table(
        "memberships",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "role_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.roles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "joined_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "user_id", "organization_id", name="uq_memberships_user_org"
        ),
        schema="acl",
    )
    op.create_index(
        "ix_memberships_user_id", "memberships", ["user_id"], schema="acl"
    )
    op.create_index(
        "ix_memberships_organization_id",
        "memberships",
        ["organization_id"],
        schema="acl",
    )
    op.create_index(
        "ix_memberships_role_id", "memberships", ["role_id"], schema="acl"
    )

    # ----- membership_invitations ---------------------------------------- #
    op.create_table(
        "membership_invitations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column(
            "role_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.roles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column(
            "invited_by_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("token", name="uq_membership_invitations_token"),
        schema="acl",
    )
    op.create_index(
        "ix_membership_invitations_email",
        "membership_invitations",
        ["email"],
        schema="acl",
    )

    # ----- auth_audit_log ------------------------------------------------ #
    op.create_table(
        "auth_audit_log",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "actor_user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("acl.users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(64), nullable=True),
        schema="acl",
    )
    op.create_index(
        "ix_auth_audit_log_actor",
        "auth_audit_log",
        ["actor_user_id"],
        schema="acl",
    )
    op.create_index(
        "ix_auth_audit_log_action", "auth_audit_log", ["action"], schema="acl"
    )
    op.create_index(
        "ix_auth_audit_log_occurred_at",
        "auth_audit_log",
        ["occurred_at"],
        schema="acl",
    )


def downgrade() -> None:
    op.drop_table("auth_audit_log", schema="acl")
    op.drop_table("membership_invitations", schema="acl")
    op.drop_table("memberships", schema="acl")
    op.drop_table("role_permissions", schema="acl")
    op.drop_table("roles", schema="acl")
    op.drop_table("permissions", schema="acl")
    op.drop_table("organizations", schema="acl")
    op.drop_table("users", schema="acl")
    op.execute("DROP SCHEMA IF EXISTS acl")
