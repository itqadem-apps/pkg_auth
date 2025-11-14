from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Set, Iterable


class ClaimSet(Enum):
    REALM_ROLE = "realm_role"
    CLIENT_ROLE = "client_role"
    PERMISSION = "permission"
    SCOPE = "scope"
    AUDIENCE = "audience"
