from enum import Enum


class ClaimSet(Enum):
    REALM_ROLE = "realm_role"
    CLIENT_ROLE = "client_role"
    PERMISSION = "permission"
    SCOPE = "scope"
    AUDIENCE = "audience"
