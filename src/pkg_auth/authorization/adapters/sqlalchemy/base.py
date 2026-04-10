"""SQLAlchemy declarative base for the ACL schema."""
from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


class AclBase(DeclarativeBase):
    """Declarative base for all ACL ORM models.

    All tables live in the ``acl`` Postgres schema. The schema itself
    is created by the initial Alembic migration.
    """

    metadata = MetaData(schema="acl")
