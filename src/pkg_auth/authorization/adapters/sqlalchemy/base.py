"""SQLAlchemy declarative base for the ACL schema.

Services that don't extend the default models use ``AclBase`` directly
(tables live in the ``acl`` Postgres schema). Services that extend the
mixins with their own columns use their own ``DeclarativeBase`` and
never import ``AclBase``.
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
