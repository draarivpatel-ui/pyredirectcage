"""pyredirectcage: zero-dependency open redirect and return URL defense.

Typical use::

    from pyredirectcage import sanitize_redirect

    location = sanitize_redirect(request.args.get("next", "/"))
    response.headers["Location"] = location
"""

from __future__ import annotations

from .core import (
    DEFAULT_MAX_DECODE_LAYERS,
    DEFAULT_MAX_LENGTH,
    MAX_DECODE_LAYER_LIMIT,
    AllowedHost,
    AllowedOrigin,
    RedirectGuard,
    RedirectInspection,
    RedirectPolicy,
    assert_safe_redirect,
    is_safe_redirect,
    parse_redirect_location,
    safe_location_header,
    sanitize_redirect,
)
from .errors import CODE, ERROR_CODES, RedirectCageError

__version__ = "1.0.0"

__all__ = [
    "CODE",
    "DEFAULT_MAX_DECODE_LAYERS",
    "DEFAULT_MAX_LENGTH",
    "ERROR_CODES",
    "MAX_DECODE_LAYER_LIMIT",
    "AllowedHost",
    "AllowedOrigin",
    "RedirectCageError",
    "RedirectGuard",
    "RedirectInspection",
    "RedirectPolicy",
    "__version__",
    "assert_safe_redirect",
    "is_safe_redirect",
    "parse_redirect_location",
    "safe_location_header",
    "sanitize_redirect",
]
