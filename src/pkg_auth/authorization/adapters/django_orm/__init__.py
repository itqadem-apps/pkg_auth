"""Django ORM adapter for the ACL schema (managed=False mirror models).

The schema is owned by the SQLAlchemy adapter's Alembic migrations.
This module provides Django ORM models pointing at the *same* physical
tables, with ``Meta.managed = False`` so Django's ``makemigrations`` will
not try to manage them. Repositories implement the same Protocols as
the SQLAlchemy adapter, using Django's async ORM API (``acreate``,
``aget``, etc.).

Importing this module requires Django to be installed:

    pip install pkg-auth[acl-django]

The Django app label is ``pkg_auth_acl``. Add
``"pkg_auth.authorization.adapters.django_orm"`` to your service's
``INSTALLED_APPS``.
"""
from __future__ import annotations

try:
    import django  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.authorization.adapters.django_orm requires Django. "
        "Install with: pip install pkg-auth[acl-django]"
    ) from exc

default_app_config = "pkg_auth.authorization.adapters.django_orm.apps.PkgAuthAclConfig"

# NOTE: do NOT import .mixins or .models from this __init__. Django needs
# the apps registry to be ready before any ``models.Model`` subclass can
# be defined, and __init__.py runs during app loading. Consumers should
# import the abstract mixins directly:
#
#     from pkg_auth.authorization.adapters.django_orm.mixins import UserMixin

__all__ = ["default_app_config"]
