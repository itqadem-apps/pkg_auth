"""Keycloak JWT decoder adapter (PyJWT + JWKS fetching)."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Mapping, Optional

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError as JWTInvalidTokenError,
)
from requests import Session

from ...domain.exceptions import InvalidTokenError, TokenExpiredError
from ...domain.ports import TokenDecoder


class JWTTokenDecoder(TokenDecoder):
    """PyJWT-based ``TokenDecoder`` implementation for Keycloak.

    Knows how to:
        - fetch JWKS from a Keycloak realm
        - cache JWKS keys with a TTL
        - verify the token signature, expiry, issuer, and audience
    """

    def __init__(
        self,
        *,
        jwks_uri: str,
        issuer: str,
        audience: str,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl_seconds

        self._session = Session()
        self._jwks_keys: Optional[List[Dict[str, Any]]] = None
        self._jwks_last_fetched: float = 0.0

    def decode(self, token: str) -> Mapping[str, Any]:
        try:
            headers = jwt.get_unverified_header(token)
            kid = headers.get("kid")

            jwks_keys = self._fetch_jwks_keys()
            key = next((k for k in jwks_keys if k.get("kid") == kid), None)

            if key is None:
                raise InvalidTokenError("No matching key found in JWKS")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

            payload: Dict[str, Any] = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=self._issuer,
            )

            aud_claim = payload.get("aud")
            if isinstance(aud_claim, str):
                aud_list = [aud_claim]
            elif isinstance(aud_claim, list):
                aud_list = list(aud_claim)
            else:
                aud_list = []

            if self._audience not in aud_list:
                raise InvalidTokenError(
                    f"Invalid audience: expected {self._audience!r}, got {aud_list!r}"
                )

            return payload

        except ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except (InvalidSignatureError, DecodeError, JWTInvalidTokenError) as exc:
            raise InvalidTokenError(f"Invalid token: {exc}") from exc

    def _fetch_jwks_keys(self) -> List[Dict[str, Any]]:
        now = time.time()
        if (
            self._jwks_keys is not None
            and (now - self._jwks_last_fetched) < self._cache_ttl
        ):
            return self._jwks_keys

        response = self._session.get(self._jwks_uri)
        response.raise_for_status()

        body = response.json()
        keys = body.get("keys", [])
        if not isinstance(keys, list):
            raise InvalidTokenError(f"JWKS endpoint returned invalid keys: {keys!r}")
        self._jwks_keys = keys
        self._jwks_last_fetched = now
        return keys
