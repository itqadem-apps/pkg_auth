"""Add deleted_at soft-delete column to permissions.

Revision ID: pkg_auth_acl_0003
Revises: pkg_auth_acl_0002
Create Date: 2026-04-20 00:00:00.000000

Enables snapshot-based catalog sync: when a consumer service (Mode B)
publishes its full catalog over NATS and a previously-registered key
is absent from the snapshot, the subscriber stamps ``deleted_at`` on
the row instead of hard-deleting it. Soft-delete preserves referential
integrity with ``role_permissions``; the admin UI filters out rows
where ``deleted_at IS NOT NULL``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pkg_auth_acl_0003"
down_revision: Union[str, None] = "pkg_auth_acl_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column(
            "deleted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("permissions", "deleted_at")
