"""Authentication domain ports (Protocols)."""
from __future__ import annotations

from typing import Any, Mapping, Protocol


class TokenDecoder(Protocol):
    """Port for decoding an access token into a claims mapping.

    Implementations live in the adapters layer (e.g.
    :class:`pkg_auth.authentication.adapters.keycloak.JWTTokenDecoder`).
    """

    def decode(self, token: str) -> Mapping[str, Any]:
        """Decode and verify the given token.

        Implementations must:
            - verify the signature
            - check the ``exp`` claim
            - validate the issuer and audience

        Raises:
            TokenExpiredError: when the ``exp`` claim is in the past.
            InvalidTokenError: for any other validation failure.
        """
        ...
