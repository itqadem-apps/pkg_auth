"""Authorization value objects (typed wrappers around DB IDs and string keys)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping
from uuid import UUID

# A service name / slug: lowercase letter first, then lowercase letters,
# digits, ``_`` or ``-``. Matches the shape of the ``service_name`` strings
# already stamped on permissions (e.g. ``"courses"``, ``"media-library"``).
_SERVICE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")

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


class PermissionVisibility(str, Enum):
    """Where a permission may be used / shown in role builders.

    - ``PLATFORM_ONLY`` — only the platform org (cross-org admin perms,
      e.g. ``organizations:create``). Hidden from normal-org role builders.
    - ``SHARED`` — usable everywhere (the historical default).
    - ``TENANT_ONLY`` — only normal organizations; **hidden from the
      platform org**. Use for perms that make no sense for the vendor's
      platform admins.

    Replaces the old ``is_platform`` boolean: ``is_platform=True`` maps to
    ``PLATFORM_ONLY`` and ``is_platform=False`` maps to ``SHARED``.
    """

    PLATFORM_ONLY = "platform_only"
    SHARED = "shared"
    TENANT_ONLY = "tenant_only"


@dataclass(frozen=True, slots=True)
class ServiceName:
    """A service identifier such as ``"courses"`` or ``"assessments"``.

    Same shape as the ``service_name`` string already carried on
    permissions; wrapping it as a value object lets the new services /
    organization_services tables share validation.
    """

    value: str

    def __post_init__(self) -> None:
        if not _SERVICE_NAME_PATTERN.match(self.value):
            raise ValueError(
                f"Invalid service name {self.value!r}: must be a lowercase "
                f"slug (letter first; letters, digits, '_' or '-')"
            )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class LocalizedText:
    """A locale → text map for user-facing strings (permission descriptions,
    service labels) that must support multiple languages.

    Stored as JSONB in the ACL database, e.g.
    ``{"en": "Edit course", "ar": "تعديل الدورة"}``. An empty map means
    "no text provided". Values must be non-empty strings.
    """

    values: Mapping[str, str]

    def __post_init__(self) -> None:
        for locale, text in self.values.items():
            if not isinstance(locale, str) or not locale:
                raise ValueError(f"Invalid locale key {locale!r}")
            if not isinstance(text, str) or not text:
                raise ValueError(
                    f"Invalid localized value for {locale!r}: must be a "
                    f"non-empty string"
                )
        # Normalize to a plain immutable dict copy so callers can't mutate.
        object.__setattr__(self, "values", dict(self.values))

    @classmethod
    def from_input(
        cls,
        value: "LocalizedText | Mapping[str, str] | str | None",
        *,
        default_locale: str,
    ) -> "LocalizedText":
        """Coerce a plain string, a dict, ``None``, or a ``LocalizedText``
        into a ``LocalizedText``. A bare string is stored under
        ``default_locale``; ``None`` becomes the empty map.
        """
        if value is None:
            return cls({})
        if isinstance(value, LocalizedText):
            return value
        if isinstance(value, str):
            return cls({default_locale: value})
        return cls(dict(value))

    def get(self, locale: str, *, fallback: str | None = None) -> str | None:
        """Return the text for ``locale`` or ``fallback`` if absent."""
        return self.values.get(locale, fallback)

    def resolve(self, locale: str, default_locale: str) -> str | None:
        """Return ``locale``'s text, falling back to ``default_locale``, then
        to any available value, then ``None``.
        """
        if locale in self.values:
            return self.values[locale]
        if default_locale in self.values:
            return self.values[default_locale]
        for text in self.values.values():
            return text
        return None

    def as_dict(self) -> dict[str, str]:
        return dict(self.values)
