"""Process-level authorization config read from the environment.

Kept out of the (pure) domain layer so value objects stay free of I/O.
The application/adapter/CLI layers call :func:`default_locale` when they
need to coerce a bare-string description into a :class:`LocalizedText`.
"""
from __future__ import annotations

import os

DEFAULT_LOCALE_ENV = "ACL_DEFAULT_LOCALE"
FALLBACK_LOCALE = "en"


def default_locale() -> str:
    """Return the configured default/fallback locale.

    Reads ``ACL_DEFAULT_LOCALE`` from the environment, falling back to
    ``"en"`` when unset or empty.
    """
    return os.environ.get(DEFAULT_LOCALE_ENV) or FALLBACK_LOCALE
