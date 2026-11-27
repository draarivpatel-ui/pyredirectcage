"""Typed error surface for pyredirectcage.

Every expected rejection carries a stable machine-readable code. Branch on
``exc.code``, never on the human-readable reason string.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Tuple

INVALID_INPUT = "ERR_REDIRECTCAGE_INVALID_INPUT"
INVALID_OPTIONS = "ERR_REDIRECTCAGE_INVALID_OPTIONS"
LIMIT_EXCEEDED = "ERR_REDIRECTCAGE_LIMIT_EXCEEDED"
CONTROL_CHARACTER = "ERR_REDIRECTCAGE_CONTROL_CHARACTER"
UNICODE_NORMALIZATION = "ERR_REDIRECTCAGE_UNICODE_NORMALIZATION"
MALFORMED_ENCODING = "ERR_REDIRECTCAGE_MALFORMED_ENCODING"
INVALID_UTF8 = "ERR_REDIRECTCAGE_INVALID_UTF8"
ENCODED_ATTACK = "ERR_REDIRECTCAGE_ENCODED_ATTACK"
PROTOCOL_RELATIVE = "ERR_REDIRECTCAGE_PROTOCOL_RELATIVE"
BACKSLASH = "ERR_REDIRECTCAGE_BACKSLASH"
DANGEROUS_SCHEME = "ERR_REDIRECTCAGE_DANGEROUS_SCHEME"
PROTOCOL_NOT_ALLOWED = "ERR_REDIRECTCAGE_PROTOCOL_NOT_ALLOWED"
INVALID_URL = "ERR_REDIRECTCAGE_INVALID_URL"
ABSOLUTE_URL = "ERR_REDIRECTCAGE_ABSOLUTE_URL"
RELATIVE_PATH = "ERR_REDIRECTCAGE_RELATIVE_PATH"
USERINFO = "ERR_REDIRECTCAGE_USERINFO"
IP_LITERAL = "ERR_REDIRECTCAGE_IP_LITERAL"
HOST_NOT_ALLOWED = "ERR_REDIRECTCAGE_HOST_NOT_ALLOWED"
QUERY_NOT_ALLOWED = "ERR_REDIRECTCAGE_QUERY_NOT_ALLOWED"
HASH_NOT_ALLOWED = "ERR_REDIRECTCAGE_HASH_NOT_ALLOWED"
DOT_SEGMENT = "ERR_REDIRECTCAGE_DOT_SEGMENT"
BLOCKED_PATH = "ERR_REDIRECTCAGE_BLOCKED_PATH"

ERROR_CODES: Tuple[str, ...] = (
    INVALID_INPUT,
    INVALID_OPTIONS,
    LIMIT_EXCEEDED,
    CONTROL_CHARACTER,
    UNICODE_NORMALIZATION,
    MALFORMED_ENCODING,
    INVALID_UTF8,
    ENCODED_ATTACK,
    PROTOCOL_RELATIVE,
    BACKSLASH,
    DANGEROUS_SCHEME,
    PROTOCOL_NOT_ALLOWED,
    INVALID_URL,
    ABSOLUTE_URL,
    RELATIVE_PATH,
    USERINFO,
    IP_LITERAL,
    HOST_NOT_ALLOWED,
    QUERY_NOT_ALLOWED,
    HASH_NOT_ALLOWED,
    DOT_SEGMENT,
    BLOCKED_PATH,
)

CODE = MappingProxyType(
    {
        "INVALID_INPUT": INVALID_INPUT,
        "INVALID_OPTIONS": INVALID_OPTIONS,
        "LIMIT_EXCEEDED": LIMIT_EXCEEDED,
        "CONTROL_CHARACTER": CONTROL_CHARACTER,
        "UNICODE_NORMALIZATION": UNICODE_NORMALIZATION,
        "MALFORMED_ENCODING": MALFORMED_ENCODING,
        "INVALID_UTF8": INVALID_UTF8,
        "ENCODED_ATTACK": ENCODED_ATTACK,
        "PROTOCOL_RELATIVE": PROTOCOL_RELATIVE,
        "BACKSLASH": BACKSLASH,
        "DANGEROUS_SCHEME": DANGEROUS_SCHEME,
        "PROTOCOL_NOT_ALLOWED": PROTOCOL_NOT_ALLOWED,
        "INVALID_URL": INVALID_URL,
        "ABSOLUTE_URL": ABSOLUTE_URL,
        "RELATIVE_PATH": RELATIVE_PATH,
        "USERINFO": USERINFO,
        "IP_LITERAL": IP_LITERAL,
        "HOST_NOT_ALLOWED": HOST_NOT_ALLOWED,
        "QUERY_NOT_ALLOWED": QUERY_NOT_ALLOWED,
        "HASH_NOT_ALLOWED": HASH_NOT_ALLOWED,
        "DOT_SEGMENT": DOT_SEGMENT,
        "BLOCKED_PATH": BLOCKED_PATH,
    }
)


class RedirectCageError(Exception):
    """Raised for unsafe redirect targets and invalid configuration.

    Attributes:
        code: Stable machine-readable code from :data:`ERROR_CODES`.
        reason: Short human-readable explanation.
        input: The rejected redirect value when one was involved. It is not
            included in the string form because redirect URLs often carry
            query tokens that should not be written to logs.
    """

    __slots__ = ("code", "reason", "input")

    def __init__(self, code: str, reason: str, input: Any = None) -> None:
        self.code = code
        self.reason = reason
        self.input = input
        super().__init__(code, reason)

    def __str__(self) -> str:
        return "{}: {}".format(self.code, self.reason)

    def to_dict(self) -> dict:
        return {
            "name": type(self).__name__,
            "code": self.code,
            "reason": self.reason,
        }


__all__ = [
    "ABSOLUTE_URL",
    "BACKSLASH",
    "BLOCKED_PATH",
    "CODE",
    "CONTROL_CHARACTER",
    "DANGEROUS_SCHEME",
    "DOT_SEGMENT",
    "ENCODED_ATTACK",
    "ERROR_CODES",
    "HASH_NOT_ALLOWED",
    "HOST_NOT_ALLOWED",
    "INVALID_INPUT",
    "INVALID_OPTIONS",
    "INVALID_URL",
    "INVALID_UTF8",
    "IP_LITERAL",
    "LIMIT_EXCEEDED",
    "MALFORMED_ENCODING",
    "PROTOCOL_NOT_ALLOWED",
    "PROTOCOL_RELATIVE",
    "QUERY_NOT_ALLOWED",
    "RELATIVE_PATH",
    "RedirectCageError",
    "UNICODE_NORMALIZATION",
    "USERINFO",
]
