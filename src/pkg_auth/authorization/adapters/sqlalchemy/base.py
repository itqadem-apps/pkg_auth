"""SQLAlchemy declarative base for the bundled ACL ORM.

.. warning::
   **Mode B only.** This module is part of pkg_auth's *default
   concrete ORM* — used by consuming services (Mode B) that point
   their own sessionmaker at the shared ACL database and read the
   tables via the bundled ``*ORM`` classes.

   **Do NOT import ``AclBase`` from a Mode A service** (one that
   extends the mixins to add service-specific columns, e.g.
   ``itq_users``). Mode A services own the ACL schema — they bring
   their own ``DeclarativeBase`` and their own concrete ORM classes,
   and run their own Alembic migrations. Importing ``AclBase`` into
   a Mode A service splits the service's models across two metadata
   objects and causes ``metadata.create_all`` / migration tooling to
   misbehave.

   Mode A services must:

   - Import the abstract column mixins from
     ``pkg_auth.authorization.adapters.sqlalchemy.mixins`` (NOT from
     this module or ``models.py``)
   - Define their own concrete ``*ORM`` classes against their own
     ``DeclarativeBase``
   - Write their own Alembic migrations

   See ``docs/Django.md`` for the Mode A vs Mode B distinction.
"""
from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


def create_acl_base(schema: str | None = None) -> type[DeclarativeBase]:
    """Build a ``DeclarativeBase`` for the bundled ACL ORM.

    By default (``schema=None``), tables are emitted unqualified and
    resolve via the database ``search_path`` — which means ``public``
    on a standard Postgres setup. This matches where source-of-truth
    services like ``itq_users`` put the ACL tables.

    Pass an explicit schema name (``create_acl_base("custom")``) if
    your source-of-truth service placed the tables in a non-default
    Postgres schema.
    """
    md = MetaData(schema=schema)

    class _AclBase(DeclarativeBase):
        metadata = md

    return _AclBase


AclBase = create_acl_base()
