"""Localize permissions.description: TEXT -> JSONB locale map.

Revision ID: pkg_auth_acl_0004
Revises: pkg_auth_acl_0003
Create Date: 2026-06-20 00:00:01.000000

``description`` becomes a JSONB ``{locale: text}`` map. Existing plain-text
descriptions are backfilled under the default locale, read from the
``ACL_DEFAULT_LOCALE`` env var at migration time (fallback ``"en"``).
"""
from __future__ import annotations

import os
import re
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0004"
down_revision: Union[str, None] = "pkg_auth_acl_0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LOCALE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def _default_locale() -> str:
    loc = os.environ.get("ACL_DEFAULT_LOCALE") or "en"
    if not _LOCALE_RE.match(loc):
        raise ValueError(f"Invalid ACL_DEFAULT_LOCALE {loc!r}")
    return loc


def upgrade() -> None:
    locale = _default_locale()
    op.execute(
        f"ALTER TABLE permissions "
        f"ALTER COLUMN description TYPE JSONB USING "
        f"CASE WHEN description IS NULL OR description = '' THEN NULL "
        f"ELSE jsonb_build_object('{locale}', description) END"
    )


def downgrade() -> None:
    locale = _default_locale()
    op.execute(
        f"ALTER TABLE permissions "
        f"ALTER COLUMN description TYPE TEXT USING "
        f"COALESCE(description ->> '{locale}', "
        f"(SELECT value FROM jsonb_each_text(description) LIMIT 1))"
    )
