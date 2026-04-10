"""Permission keys this service knows about.

Declared in code, registered into the ACL ``acl.permissions`` table on
boot via :class:`RegisterPermissionCatalogUseCase`. The users service's
admin UI then reads them from that table to populate role-editor
checkboxes.
"""
from __future__ import annotations

from pkg_auth.authorization import PermissionKey

SERVICE_NAME = "courses"

CATALOG: list[tuple[PermissionKey, str]] = [
    (PermissionKey("course:view"), "View course content"),
    (PermissionKey("course:edit"), "Edit course content"),
    (PermissionKey("course:publish"), "Publish a course"),
    (PermissionKey("course:delete"), "Delete a course"),
    (PermissionKey("course:enroll"), "Enroll in a course"),
]
