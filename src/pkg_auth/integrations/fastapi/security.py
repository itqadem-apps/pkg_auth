from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Expose this so apps can plug it into dependencies if they want OpenAPI security
bearer_scheme = HTTPBearer(auto_error=False)

DEFAULT_COOKIE_NAME = "access_token"


def extract_token_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> str:
    """
    Extract an access token from either:

      1. HTTP Bearer auth header (preferred)
      2. A cookie (e.g. 'access_token')

    Raises HTTPException(401) if no token is found.
    """
    # 1) Prefer the HTTPBearer credentials if provided
    if credentials is not None:
        token = (credentials.credentials or "").strip()
        if token:
            return token

    # 2) Fallback to raw Authorization header (in case user didn't use bearer_scheme)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token

    # 3) Fallback to cookie
    cookie_token = request.cookies.get(cookie_name)
    if cookie_token:
        return cookie_token

    # 4) Nothing found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )
