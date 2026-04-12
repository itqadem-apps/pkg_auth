"""Add is_platform flag to acl.permissions.

Revision ID: pkg_auth_acl_0002
Revises: pkg_auth_acl_0001
Create Date: 2026-04-12 00:00:00.000000

Adds the ``is_platform`` boolean column introduced in pkg_auth v1.4 so
the central ACL UI can filter platform-only permissions out of org-scoped
role builders. Defaults to ``false`` so existing rows remain valid and
backwards-compatible 2-tuple registration calls keep working.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0002"
down_revision: Union[str, None] = "pkg_auth_acl_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column(
            "is_platform",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        schema="acl",
    )


def downgrade() -> None:
    op.drop_column("permissions", "is_platform", schema="acl")
