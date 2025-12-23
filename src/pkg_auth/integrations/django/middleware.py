from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest

from .auth import DEFAULT_COOKIE_NAME, DjangoAuthorization, create_django_auth


@dataclass(slots=True)
class PkgAuthMiddleware:
    """
    Optional middleware that sets `request.access_context` if a valid token is present.

    Settings:
    - KEYCLOAK_BASE_URL (required)
    - KEYCLOAK_REALM (required)
    - KEYCLOAK_CLIENT_ID (required)
    - KEYCLOAK_AUDIENCE (optional)
    - PKG_AUTH_COOKIE_NAME (optional; default: "access_token")
    """

    get_response: callable
    authz: DjangoAuthorization
    cookie_name: str

    def __init__(self, get_response):
        self.get_response = get_response

        keycloak_base_url = getattr(settings, "KEYCLOAK_BASE_URL", None)
        realm = getattr(settings, "KEYCLOAK_REALM", None)
        client_id = getattr(settings, "KEYCLOAK_CLIENT_ID", None)
        audience = getattr(settings, "KEYCLOAK_AUDIENCE", None)
        cookie_name = getattr(settings, "PKG_AUTH_COOKIE_NAME", DEFAULT_COOKIE_NAME)

        missing = [
            k
            for k, v in {
                "KEYCLOAK_BASE_URL": keycloak_base_url,
                "KEYCLOAK_REALM": realm,
                "KEYCLOAK_CLIENT_ID": client_id,
            }.items()
            if not v
        ]
        if missing:
            raise ImproperlyConfigured(
                "PkgAuthMiddleware missing required settings: " + ", ".join(missing)
            )

        self.authz = create_django_auth(
            keycloak_base_url=keycloak_base_url,
            realm=realm,
            client_id=client_id,
            audience=audience,
        )
        self.cookie_name = cookie_name

    def __call__(self, request: HttpRequest):
        request.access_context = self.authz.get_optional_user(  # type: ignore[attr-defined]
            request,
            cookie_name=self.cookie_name,
        )
        return self.get_response(request)
