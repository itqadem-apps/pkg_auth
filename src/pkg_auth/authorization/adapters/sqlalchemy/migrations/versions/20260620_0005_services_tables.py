"""Create services and organization_services tables (service guard).

Revision ID: pkg_auth_acl_0005
Revises: pkg_auth_acl_0004
Create Date: 2026-06-20 00:00:02.000000

``services`` is the vendor-controlled service registry; ``auto_provision``
and ``saas_available`` are set only via ``pkg-auth-sync-services``.
``organization_services`` is the per-org entitlement that drives the
default-deny service guard in ``ResolveAuthContextUseCase``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0005"
down_revision: Union[str, None] = "pkg_auth_acl_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "services",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("display_label", JSONB, nullable=True),
        sa.Column(
            "auto_provision",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "saas_available",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
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
        sa.UniqueConstraint("name", name="uq_services_name"),
    )
    op.create_index("ix_services_name", "services", ["name"])

    op.create_table(
        "organization_services",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("organization_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("service_name", sa.String(64), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "source",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'manual'"),
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "organization_id", "service_name",
            name="uq_org_services_org_service",
        ),
    )
    op.create_index(
        "ix_org_services_org_id",
        "organization_services",
        ["organization_id"],
    )
    op.create_index(
        "ix_org_services_service_name",
        "organization_services",
        ["service_name"],
    )


def downgrade() -> None:
    op.drop_table("organization_services")
    op.drop_table("services")
