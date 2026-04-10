"""Token extraction helpers and identity dependency for FastAPI."""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

DEFAULT_COOKIE_NAME = "access_token"

bearer_scheme = HTTPBearer(auto_error=False)


def extract_token_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> str:
    """Extract a bearer token from the Authorization header or a cookie.

    Raises ``HTTPException(401)`` if no token is found.
    """
    if credentials is not None:
        token = (credentials.credentials or "").strip()
        if token:
            return token

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token

    cookie_token = request.cookies.get(cookie_name)
    if cookie_token:
        return cookie_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )
