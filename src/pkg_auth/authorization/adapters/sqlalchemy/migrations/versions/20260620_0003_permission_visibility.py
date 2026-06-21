"""Replace permissions.is_platform with a tri-state visibility column.

Revision ID: pkg_auth_acl_0003
Revises: pkg_auth_acl_0002
Create Date: 2026-06-20 00:00:00.000000

``is_platform`` was a 2-state flag (platform-only vs everywhere). It is
replaced by a ``visibility`` enum-as-string:

    - ``platform_only`` (was ``is_platform = true``)
    - ``shared``        (was ``is_platform = false``, the default)
    - ``tenant_only``   (new — hidden from the platform org)

Backfill maps the old boolean, then the old column is dropped.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0003"
down_revision: Union[str, None] = "pkg_auth_acl_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column(
            "visibility",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'shared'"),
        ),
    )
    op.execute(
        "UPDATE permissions SET visibility = "
        "CASE WHEN is_platform THEN 'platform_only' ELSE 'shared' END"
    )
    op.create_index(
        "ix_permissions_visibility", "permissions", ["visibility"]
    )
    op.drop_column("permissions", "is_platform")


def downgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column(
            "is_platform",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.execute(
        "UPDATE permissions SET is_platform = "
        "(visibility = 'platform_only')"
    )
    op.drop_index("ix_permissions_visibility", table_name="permissions")
    op.drop_column("permissions", "visibility")
