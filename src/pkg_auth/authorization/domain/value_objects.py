"""Authorization value objects (typed wrappers around DB IDs and string keys)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID

# Format:
#   - one or more colon-separated segments
#   - each segment must start with a lowercase letter
#   - each segment may contain lowercase letters, digits, ``_``, ``-``
#   - at least one colon (so single bare words like ``"admin"`` are rejected)
#
# Examples (valid):   "course:edit", "media-library:upload", "billing:invoice:refund"
# Examples (invalid): "admin", "Course:edit", ":x", "x:", "1course:edit"
_PERMISSION_KEY_PATTERN = re.compile(
    r"^[a-z][a-z0-9_-]*(?::[a-z][a-z0-9_-]*)+$"
)


@dataclass(frozen=True, slots=True)
class UserId:
    """Primary key of a row in the users table (UUID)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OrgId:
    """Primary key of a row in the organizations table (UUID)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RoleId:
    """Primary key of a row in the roles table (UUID)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PermissionId:
    """Primary key of a row in the permissions table (UUID)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RoleName:
    """Human-readable role name. Unique per ``(organization_id, name)``."""

    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PermissionKey:
    """A permission key like ``"course:edit"`` or ``"billing:invoice:refund"``.

    Format (validated in ``__post_init__``):

        - one or more colon-separated segments
        - each segment must start with a lowercase letter
        - each segment may contain lowercase letters, digits, ``_``, ``-``
        - at least one colon (so single bare words like ``"admin"`` are
          rejected — they don't carry resource context)

    Raises:
        ValueError: when the value does not match the format.
    """

    value: str

    def __post_init__(self) -> None:
        if not _PERMISSION_KEY_PATTERN.match(self.value):
            raise ValueError(
                f"Invalid permission key {self.value!r}: "
                f"must be 'resource:action' (lowercase, colon-separated)"
            )

    def __str__(self) -> str:
        return self.value
