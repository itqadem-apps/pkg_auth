"""Django AppConfig for the pkg_auth ACL ORM mirror models."""
from __future__ import annotations

from django.apps import AppConfig


class PkgAuthAclConfig(AppConfig):
    """Django app holding the ACL ORM mirror models.

    Tables are owned by Alembic migrations from the SQLAlchemy adapter,
    so all models in this app declare ``Meta.managed = False``. Adding
    this app to ``INSTALLED_APPS`` lets Django code query the ACL
    tables via the ORM without managing the schema.
    """

    name = "pkg_auth.authorization.adapters.django_orm"
    label = "pkg_auth_acl"
    verbose_name = "pkg_auth ACL"
    default_auto_field = "django.db.models.BigAutoField"
