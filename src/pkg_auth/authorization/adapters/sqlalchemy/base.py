"""SQLAlchemy declarative base for the ACL schema.

.. warning::
   **Mode A only.** This module is part of pkg_auth's *default
   concrete schema* — used by consuming services that adopt the
   bundled Alembic migrations verbatim and want the ACL tables to live
   in the ``acl`` Postgres schema.

   **Do NOT import ``AclBase`` from a Mode B service** (one that
   extends the mixins to add service-specific columns, e.g.
   ``itq_users``). Mode B services own their own schema — typically
   ``public`` — and must bring their own ``DeclarativeBase`` with no
   hardcoded ``MetaData(schema=...)``. Importing ``AclBase`` into a
   Mode B service silently binds its models' metadata to the ``acl``
   schema, and a subsequent ``metadata.create_all()`` will create
   duplicate ``acl.users`` / ``acl.organizations`` / … tables
   alongside the service's real ``public.*`` ones.

   Mode B services must:

   - Import the abstract column mixins from
     ``pkg_auth.authorization.adapters.sqlalchemy.mixins`` (NOT from
     this module or ``models.py``)
   - Define their own concrete ``*ORM`` classes against their own
     ``DeclarativeBase``
   - Write their own Alembic migrations (not ``alembic upgrade
     pkg_auth_acl@head``)

   See ``docs/Django.md`` and the v1.4 CHANGELOG for the Mode A vs
   Mode B distinction.
"""
from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


def create_acl_base(schema: str = "acl") -> type[DeclarativeBase]:
    """Build a DeclarativeBase bound to the given schema.

    ``AclBase`` below is the default (schema ``"acl"``). Services can
    call ``create_acl_base("my_schema")`` for a custom schema, or just
    use their own ``DeclarativeBase`` with no schema prefix.
    """
    md = MetaData(schema=schema)

    class _AclBase(DeclarativeBase):
        metadata = md

    return _AclBase


AclBase = create_acl_base("acl")
