from __future__ import annotations

from typing import Protocol, Mapping, Any


class TokenDecoder(Protocol):
    """
    Port for decoding an access token into claims.

    Implementations live in the adapters layer (e.g. Keycloak JWT decoder).
    """

    def decode(self, token: str) -> Mapping[str, Any]:
        """
        Decode and verify the given token.

        Should:
          - verify signature
          - check expiry and basic claims
        Raises:
          - TokenExpiredError
          - InvalidTokenError
          - or other domain-specific auth exceptions
        """
        ...
