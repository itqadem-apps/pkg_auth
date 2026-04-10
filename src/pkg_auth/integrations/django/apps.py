"""Django AppConfig for pkg_auth's framework integration."""
from __future__ import annotations

from django.apps import AppConfig


class PkgAuthDjangoConfig(AppConfig):
    name = "pkg_auth.integrations.django"
    label = "pkg_auth_django"
    verbose_name = "pkg_auth Django integration"
