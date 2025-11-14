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
    """
    Adapter implementing TokenDecoder port using PyJWT and Keycloak JWKS.

    Infrastructure layer:
    - Knows about JWT structure and verification.
    - Knows how to talk to Keycloak's JWKS endpoint.
    """

    def __init__(
        self,
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

    # ------------------------------------------------------------------ #
    # Port implementation
    # ------------------------------------------------------------------ #

    def decode(self, token: str) -> Mapping[str, Any]:
        """
        Decode and validate JWT token.

        Returns:
            Mapping of token claims (dict-like).

        Raises:
            TokenExpiredError
            InvalidTokenError
        """
        try:
            headers = jwt.get_unverified_header(token)
            kid = headers.get("kid")

            jwks_keys = self._fetch_jwks_keys()
            key = next((k for k in jwks_keys if k.get("kid") == kid), None)

            if not key:
                raise InvalidTokenError("No matching key found in JWKS")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

            # Decode with issuer check, but disable built-in audience check
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
                issuer=self._issuer,
            )

            # Manually verify audience (Keycloak may return string or list)
            aud_claim = payload.get("aud")
            if isinstance(aud_claim, str):
                aud_list = [aud_claim]
            else:
                aud_list = list(aud_claim or [])

            if self._audience not in aud_list:
                raise InvalidTokenError(
                    f"Invalid audience: expected {self._audience}, got {aud_list}"
                )

            return payload

        except ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except (InvalidSignatureError, DecodeError, JWTInvalidTokenError) as exc:
            raise InvalidTokenError(f"Invalid token: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _fetch_jwks_keys(self) -> List[Dict[str, Any]]:
        """
        Fetch JWKS keys with simple in-memory caching.
        """
        now = time.time()
        if self._jwks_keys is not None and (now - self._jwks_last_fetched) < self._cache_ttl:
            return self._jwks_keys

        response = self._session.get(self._jwks_uri)
        response.raise_for_status()

        body = response.json()
        self._jwks_keys = body.get("keys", [])
        self._jwks_last_fetched = now
        return self._jwks_keys
