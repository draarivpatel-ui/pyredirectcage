"""Core redirect validation and canonicalization.

The parser is deliberately small and strict. It accepts only same-origin
absolute paths by default, plus explicitly allowlisted HTTP and HTTPS origins.
It never performs network access and never delegates security decisions to a
framework parser.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .errors import (
    ABSOLUTE_URL,
    BACKSLASH,
    BLOCKED_PATH,
    CONTROL_CHARACTER,
    DANGEROUS_SCHEME,
    DOT_SEGMENT,
    ENCODED_ATTACK,
    HASH_NOT_ALLOWED,
    HOST_NOT_ALLOWED,
    INVALID_INPUT,
    INVALID_OPTIONS,
    INVALID_URL,
    INVALID_UTF8,
    IP_LITERAL,
    LIMIT_EXCEEDED,
    MALFORMED_ENCODING,
    PROTOCOL_NOT_ALLOWED,
    PROTOCOL_RELATIVE,
    QUERY_NOT_ALLOWED,
    RELATIVE_PATH,
    UNICODE_NORMALIZATION,
    USERINFO,
    RedirectCageError,
)

DEFAULT_MAX_LENGTH = 2048
DEFAULT_MAX_DECODE_LAYERS = 8
MAX_DECODE_LAYER_LIMIT = 16

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_VALID_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PERCENT_TRIPLET_RE = re.compile(r"%[0-9a-fA-F]{2}")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_ASCII_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PORT_RE = re.compile(r"^\d+$")

_HARD_BLOCKED_SCHEMES = frozenset(
    (
        "javascript",
        "data",
        "vbscript",
        "file",
        "blob",
        "about",
        "filesystem",
        "chrome",
        "chrome-extension",
        "moz-extension",
        "ms-browser-extension",
        "intent",
    )
)
_SINGLE_DOT_SEGMENTS = frozenset((".", "%2e"))
_DOUBLE_DOT_SEGMENTS = frozenset(("..", "%2e%2e", ".%2e", "%2e."))
_STRUCTURAL_CHARS = ("/", "\\", "%", ":", "@", "?", "#", ".")
_DECODED_UNICODE_SPACES = frozenset(
    [
        "\u00a0",
        "\u1680",
        "\u2000",
        "\u2001",
        "\u2002",
        "\u2003",
        "\u2004",
        "\u2005",
        "\u2006",
        "\u2007",
        "\u2008",
        "\u2009",
        "\u200a",
        "\u2028",
        "\u2029",
        "\u202f",
        "\u205f",
        "\u3000",
    ]
)

_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
_SUB_DELIMS = "!$&'()*+,;="
_PATH_SAFE = _UNRESERVED + _SUB_DELIMS + ":@/"
_QUERY_SAFE = _UNRESERVED + _SUB_DELIMS + ":@/?"
_USERINFO_SAFE = _UNRESERVED + _SUB_DELIMS

_KNOWN_OPTION_KEYS = frozenset(
    (
        "allowed_origins",
        "allowed_hosts",
        "allow_subdomains",
        "allow_protocols",
        "allow_userinfo",
        "allow_ip_literals",
        "allow_query",
        "allow_hash",
        "normalize_dot_segments",
        "blocked_paths",
        "fallback",
        "max_length",
        "max_decode_layers",
        "raise_on_unsafe",
    )
)
_BOOLEAN_OPTIONS = frozenset(
    (
        "allow_subdomains",
        "allow_userinfo",
        "allow_ip_literals",
        "allow_query",
        "allow_hash",
        "normalize_dot_segments",
        "raise_on_unsafe",
    )
)

_NOT_IPV4 = object()


class _UrlError(ValueError):
    pass


@dataclass(frozen=True)
class AllowedOrigin:
    """Canonical allowlisted origin."""

    origin: str
    protocol: str
    hostname: str
    port: int


@dataclass(frozen=True)
class AllowedHost:
    """Canonical allowlisted host and optional port."""

    hostname: str
    port: Optional[int]


@dataclass(frozen=True)
class RedirectInspection:
    """Structured result returned by :func:`parse_redirect_location`.

    ``query`` and ``fragment`` do not include their delimiters. An empty string
    means the delimiter was present with an empty value. IPv6 host metadata is
    bracketed, matching URL presentation form.
    """

    input: Any
    safe: bool
    reason: Optional[str]
    code: Optional[str]
    normalized: Optional[str]
    kind: Optional[str]
    origin: Optional[str]
    path: Optional[str]
    protocol: Optional[str] = None
    host: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    query: Optional[str] = None
    fragment: Optional[str] = None

    @property
    def value(self) -> Optional[str]:
        """Alias for ``normalized`` used by the JavaScript companion API."""
        return self.normalized

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input": self.input,
            "safe": self.safe,
            "reason": self.reason,
            "code": self.code,
            "normalized": self.normalized,
            "kind": self.kind,
            "origin": self.origin,
            "path": self.path,
            "protocol": self.protocol,
            "host": self.host,
            "hostname": self.hostname,
            "port": self.port,
            "query": self.query,
            "fragment": self.fragment,
        }


@dataclass(frozen=True)
class _DecodeResult:
    value: Optional[str]
    changed: bool
    invalid_utf8: bool


@dataclass(frozen=True)
class _Prepared:
    input: str
    variants: Tuple[str, ...]
    scheme: Optional[Tuple[str, str, int]]


@dataclass(frozen=True)
class _Authority:
    userinfo: Optional[str]
    hostname: str
    explicit_port: Optional[int]
    host: str
    is_ip: bool


@dataclass(frozen=True)
class _ParsedAbsolute:
    scheme: str
    authority: _Authority
    path: str
    query_present: bool
    query: str
    fragment_present: bool
    fragment: str


def _raise_error(code: str, reason: str, input: Any = None) -> None:
    raise RedirectCageError(code, reason, input)


def _config_error(reason: str, input: Any = None) -> None:
    _raise_error(INVALID_OPTIONS, reason, input)


def _failure(input: Any, code: str, reason: str) -> RedirectInspection:
    return RedirectInspection(
        input=input,
        safe=False,
        reason=reason,
        code=code,
        normalized=None,
        kind=None,
        origin=None,
        path=None,
    )


def _success(
    input: str,
    normalized: str,
    kind: str,
    *,
    origin: Optional[str],
    protocol: Optional[str],
    host: Optional[str],
    hostname: Optional[str],
    port: Optional[int],
    path: str,
    query: Optional[str],
    fragment: Optional[str],
) -> RedirectInspection:
    for char in normalized:
        codepoint = ord(char)
        if codepoint < 0x20 or codepoint > 0x7E:
            return _failure(
                input,
                CONTROL_CHARACTER,
                "canonical redirect output is not printable ASCII",
            )
    return RedirectInspection(
        input=input,
        safe=True,
        reason=None,
        code=None,
        normalized=normalized,
        kind=kind,
        origin=origin,
        path=path,
        protocol=protocol,
        host=host,
        hostname=hostname,
        port=port,
        query=query,
        fragment=fragment,
    )


def _failure_exception(result: RedirectInspection) -> RedirectCageError:
    return RedirectCageError(result.code or INVALID_INPUT, result.reason or "unsafe redirect", result.input)


def _parse_scheme(value: str) -> Optional[Tuple[str, str, int]]:
    match = _SCHEME_RE.match(value)
    if match is None:
        return None
    raw = match.group(1)
    return raw, raw.lower(), match.end()


def _hex_value(char: str) -> int:
    codepoint = ord(char)
    if 48 <= codepoint <= 57:
        return codepoint - 48
    if 65 <= codepoint <= 70:
        return codepoint - 55
    if 97 <= codepoint <= 102:
        return codepoint - 87
    return -1


def _percent_byte_at(value: str, index: int) -> int:
    if index >= len(value) or value[index] != "%" or index + 2 >= len(value):
        return -1
    high = _hex_value(value[index + 1])
    low = _hex_value(value[index + 2])
    if high == -1 or low == -1:
        return -1
    return high * 16 + low


def _validate_percent_encoding(value: str) -> bool:
    index = value.find("%")
    while index != -1:
        if _percent_byte_at(value, index) == -1:
            return False
        index = value.find("%", index + 3)
    return True


def _utf8_bytes_for_char(char: str) -> bytes:
    codepoint = ord(char)
    if 0xD800 <= codepoint <= 0xDFFF:
        return b"\xef\xbf\xbd"
    return char.encode("utf-8")


def _decode_percent_layer(value: str) -> _DecodeResult:
    if "%" not in value:
        return _DecodeResult(value=value, changed=False, invalid_utf8=False)
    output = bytearray()
    changed = False
    index = 0
    while index < len(value):
        encoded_byte = _percent_byte_at(value, index)
        if encoded_byte != -1:
            output.append(encoded_byte)
            changed = True
            index += 3
            continue
        output.extend(_utf8_bytes_for_char(value[index]))
        index += 1
    try:
        decoded = bytes(output).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return _DecodeResult(value=None, changed=changed, invalid_utf8=True)
    return _DecodeResult(value=decoded, changed=changed, invalid_utf8=False)


def _uppercase_percent_triplets(value: str) -> str:
    return _PERCENT_TRIPLET_RE.sub(lambda match: match.group(0).upper(), value)


def _leading_slash_count(value: str) -> int:
    count = 0
    while count < len(value) and value[count] in ("/", "\\"):
        count += 1
    return count


def _is_c0_c1_or_del(char: str) -> bool:
    codepoint = ord(char)
    return codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F


def _is_format_or_surrogate(char: str) -> bool:
    codepoint = ord(char)
    return (
        unicodedata.category(char) in ("Cf", "Cs")
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xE0100 <= codepoint <= 0xE01EF
    )


def _raw_forbidden(char: str) -> bool:
    return _is_c0_c1_or_del(char) or char.isspace() or _is_format_or_surrogate(char)


def _decoded_forbidden(char: str) -> bool:
    return (
        _is_c0_c1_or_del(char)
        or _is_format_or_surrogate(char)
        or char in _DECODED_UNICODE_SPACES
    )


def _scan_unicode_hazards(value: str) -> Optional[Tuple[str, str]]:
    compat = unicodedata.normalize("NFKC", value)
    if compat == value:
        return None
    if any(_decoded_forbidden(char) for char in compat):
        return (
            UNICODE_NORMALIZATION,
            "Unicode normalization introduces whitespace, control or invisible characters",
        )
    if "\\" in compat:
        return (
            UNICODE_NORMALIZATION,
            "Unicode normalization introduces a backslash",
        )
    for char in _STRUCTURAL_CHARS:
        if compat.count(char) != value.count(char):
            return (
                UNICODE_NORMALIZATION,
                "Unicode normalization changes URL structural characters",
            )
    if _leading_slash_count(compat) >= 2:
        return (
            UNICODE_NORMALIZATION,
            "Unicode normalization creates a protocol-relative prefix",
        )
    if _parse_scheme(compat) is not None and _parse_scheme(value) is None:
        return (
            UNICODE_NORMALIZATION,
            "Unicode normalization creates a URL scheme",
        )
    return None


def _scan_variant(value: str, original: bool) -> Optional[Tuple[str, str]]:
    forbidden = _raw_forbidden if original else _decoded_forbidden
    if any(forbidden(char) for char in value):
        return (
            CONTROL_CHARACTER,
            "raw whitespace, control or invisible characters are not allowed"
            if original
            else "percent-decoding reveals control or invisible characters",
        )
    if "\\" in value:
        return (BACKSLASH, "backslashes are not allowed in redirect targets")
    if _leading_slash_count(value) >= 2:
        return (
            PROTOCOL_RELATIVE,
            "protocol-relative and authority-relative prefixes are not allowed",
        )
    return _scan_unicode_hazards(value)


def _is_single_dot_segment(segment: str) -> bool:
    return segment.lower() in _SINGLE_DOT_SEGMENTS


def _is_double_dot_segment(segment: str) -> bool:
    return segment.lower() in _DOUBLE_DOT_SEGMENTS


def _is_dotlike_segment(segment: str) -> bool:
    return _is_single_dot_segment(segment) or _is_double_dot_segment(segment)


def _mark_dot_segments(path: str) -> str:
    marked = []
    for segment in path.split("/"):
        lowered = segment.lower()
        if lowered in _SINGLE_DOT_SEGMENTS:
            marked.append(".")
        elif lowered in _DOUBLE_DOT_SEGMENTS:
            marked.append("..")
        else:
            marked.append(segment)
    return "/".join(marked)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 dot-segment removal in amortized linear time."""
    position = 0
    end = len(path)
    output_parts: List[str] = []

    def remove_last_segment() -> None:
        if output_parts:
            output_parts.pop()

    while position < end:
        if path.startswith("../", position):
            position += 3
        elif path.startswith("./", position):
            position += 2
        elif path.startswith("/./", position):
            position += 2
        elif path.startswith("/../", position):
            position += 3
            remove_last_segment()
        elif end - position == 2 and path[position] == "/" and path[position + 1] == ".":
            output_parts.append("/")
            position = end
        elif end - position == 3 and path[position] == "/" and path[position + 1 : position + 3] == "..":
            remove_last_segment()
            output_parts.append("/")
            position = end
        elif (end - position == 1 and path[position] == ".") or (
            end - position == 2 and path[position : position + 2] == ".."
        ):
            position = end
        else:
            if path[position] == "/":
                index = path.find("/", position + 1)
            else:
                index = path.find("/", position)
            if index == -1:
                output_parts.append(path[position:])
                position = end
            else:
                output_parts.append(path[position:index])
                position = index
    return "".join(output_parts)


def _normalize_path(path: str) -> str:
    normalized = _remove_dot_segments(_mark_dot_segments(path))
    return normalized if normalized else "/"


def _extract_raw_authority(value: str) -> Optional[str]:
    scheme = _parse_scheme(value)
    if scheme is None:
        return None
    scheme_length = scheme[2]
    if value[scheme_length : scheme_length + 2] != "//":
        return None
    rest_start = scheme_length + 2
    end = len(value)
    for delimiter in ("/", "?", "#"):
        index = value.find(delimiter, rest_start)
        if index != -1 and index < end:
            end = index
    return value[rest_start:end]


def _extract_raw_path(value: str) -> str:
    start = 0
    scheme = _parse_scheme(value)
    if scheme is not None:
        authority = _extract_raw_authority(value)
        if authority is None:
            return ""
        start = scheme[2] + 2 + len(authority)
        if start >= len(value) or value[start] != "/":
            return ""
    end = len(value)
    for delimiter in ("?", "#"):
        index = value.find(delimiter, start)
        if index != -1 and index < end:
            end = index
    return value[start:end]


def _has_dot_segments(value: str) -> bool:
    raw_path = _extract_raw_path(value)
    if not raw_path:
        return False
    return any(_is_dotlike_segment(segment) for segment in raw_path.split("/"))


def _split_suffix(suffix: str) -> Tuple[str, bool, str, bool, str]:
    fragment_present = False
    fragment = ""
    hash_index = suffix.find("#")
    before_fragment = suffix
    if hash_index != -1:
        fragment_present = True
        fragment = suffix[hash_index + 1 :]
        before_fragment = suffix[:hash_index]
    query_present = False
    query = ""
    query_index = before_fragment.find("?")
    path = before_fragment
    if query_index != -1:
        query_present = True
        query = before_fragment[query_index + 1 :]
        path = before_fragment[:query_index]
    return path, query_present, query, fragment_present, fragment


def _percent_canonicalize(value: str, safe_characters: str) -> str:
    output: List[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%" and _percent_byte_at(value, index) != -1:
            output.append(value[index : index + 3].upper())
            index += 3
            continue
        if char in safe_characters and ord(char) < 0x80:
            output.append(char)
        else:
            for byte in _utf8_bytes_for_char(char):
                output.append("%{:02X}".format(byte))
        index += 1
    return "".join(output)


def _canonicalize_userinfo(value: str) -> str:
    if ":" in value:
        username, password = value.split(":", 1)
        if password == "":
            if username == "":
                return ""
            return _percent_canonicalize(username, _USERINFO_SAFE) + "@"
        return (
            _percent_canonicalize(username, _USERINFO_SAFE)
            + ":"
            + _percent_canonicalize(password, _USERINFO_SAFE)
            + "@"
        )
    return _percent_canonicalize(value, _USERINFO_SAFE) + "@"


def _ipv4_number(part: str) -> Tuple[bool, Optional[int]]:
    if part == "":
        return True, None
    lowered = part.lower()
    if lowered.startswith("0x"):
        digits = part[2:]
        if digits == "":
            return True, 0
        if all(char in "0123456789abcdefABCDEF" for char in digits):
            return True, int(digits, 16)
        return False, None
    if len(part) > 1 and part.startswith("0"):
        if all(char in "01234567" for char in part):
            return True, int(part, 8)
        if part.isdigit():
            return True, None
        return False, None
    if part.isdigit():
        return True, int(part, 10)
    return False, None


def _canonicalize_ipv4(host: str) -> Any:
    candidate = host[:-1] if host.endswith(".") and len(host) > 1 else host
    parts = candidate.split(".")
    parsed = [_ipv4_number(part) for part in parts]
    if not parsed or not parsed[-1][0]:
        return _NOT_IPV4
    if len(parts) > 4:
        raise _UrlError("IPv4 host has too many parts")
    values: List[int] = []
    for numeric, value in parsed:
        if not numeric or value is None:
            raise _UrlError("IPv4 host contains an invalid numeric part")
        values.append(value)
    for value in values[:-1]:
        if value > 255:
            raise _UrlError("IPv4 host part exceeds 255")
    tail_bytes = 5 - len(parts)
    if values[-1] >= 256 ** tail_bytes:
        raise _UrlError("IPv4 host value is out of range")
    output = [str(value) for value in values[:-1]]
    remaining = values[-1]
    tail: List[str] = []
    for power in range(tail_bytes - 1, -1, -1):
        divisor = 256 ** power
        tail.append(str(remaining // divisor))
        remaining %= divisor
    return ".".join(output + tail)


def _decode_host_percent_once(host: str) -> str:
    if "%" not in host:
        return host
    output = bytearray()
    index = 0
    while index < len(host):
        encoded_byte = _percent_byte_at(host, index)
        if encoded_byte != -1:
            output.append(encoded_byte)
            index += 3
            continue
        output.extend(_utf8_bytes_for_char(host[index]))
        index += 1
    try:
        return bytes(output).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise _UrlError("host percent encoding is not valid UTF-8") from exc


def _canonicalize_domain_or_ipv4(host: str) -> Tuple[str, bool]:
    if host == "":
        raise _UrlError("host is empty")
    decoded = _decode_host_percent_once(host)
    if decoded == "":
        raise _UrlError("host is empty")
    ipv4 = _canonicalize_ipv4(decoded)
    if ipv4 is not _NOT_IPV4:
        return ipv4, True

    trailing_dot = decoded.endswith(".")
    domain = decoded[:-1] if trailing_dot else decoded
    if domain == "":
        raise _UrlError("host is empty")
    labels = domain.split(".")
    if any(label == "" for label in labels):
        raise _UrlError("host contains an empty label")
    ascii_labels: List[str] = []
    for label in labels:
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError) as exc:
            raise _UrlError("host is not a valid internationalized domain name") from exc
        if not ascii_label or len(ascii_label) > 63:
            raise _UrlError("host label length is invalid")
        if _DOMAIN_ASCII_RE.fullmatch(ascii_label) is None:
            raise _UrlError("host contains characters outside the domain alphabet")
        ascii_labels.append(ascii_label)
    canonical = ".".join(ascii_labels)
    if len(canonical) > 253:
        raise _UrlError("host name is too long")
    if trailing_dot:
        canonical += "."
    return canonical, False


def _parse_port(port_text: Optional[str], label: str) -> Optional[int]:
    if port_text is None or port_text == "":
        return None
    if _PORT_RE.fullmatch(port_text) is None:
        raise _UrlError(label + " is not decimal digits")
    port = int(port_text, 10)
    if port < 1 or port > 65535:
        raise _UrlError(label + " must be between 1 and 65535")
    return port


def _default_port(protocol: str) -> int:
    return 443 if protocol == "https" else 80


def _parse_authority(authority: str, protocol: str) -> _Authority:
    if authority == "":
        raise _UrlError("authority is empty")
    userinfo: Optional[str] = None
    hostport_text = authority
    if "@" in authority:
        userinfo_text, hostport_text = authority.rsplit("@", 1)
        if userinfo_text == "":
            raise _UrlError("userinfo must not be empty")
        userinfo = _canonicalize_userinfo(userinfo_text)
    if hostport_text == "":
        raise _UrlError("host is empty")

    explicit_port: Optional[int] = None
    if hostport_text.startswith("["):
        close = hostport_text.find("]")
        if close == -1:
            raise _UrlError("IPv6 literal is missing a closing bracket")
        ipv6_text = hostport_text[1:close]
        if "%" in ipv6_text:
            raise _UrlError("IPv6 zone identifiers are not supported")
        try:
            ipv6 = ipaddress.IPv6Address(ipv6_text)
        except ValueError as exc:
            raise _UrlError("IPv6 literal is invalid") from exc
        hostname = "[" + str(ipv6) + "]"
        rest = hostport_text[close + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise _UrlError("unexpected data after IPv6 literal")
            explicit_port = _parse_port(rest[1:], "port")
        is_ip = True
    else:
        if hostport_text.count(":") > 1:
            raise _UrlError("IPv6 literals must use brackets")
        if ":" in hostport_text:
            host_text, port_text = hostport_text.rsplit(":", 1)
            explicit_port = _parse_port(port_text, "port")
        else:
            host_text = hostport_text
        hostname, is_ip = _canonicalize_domain_or_ipv4(host_text)

    visible_port = explicit_port is not None and explicit_port != _default_port(protocol)
    host = hostname + (":" + str(explicit_port) if visible_port else "")
    return _Authority(
        userinfo=userinfo,
        hostname=hostname,
        explicit_port=explicit_port,
        host=host,
        is_ip=is_ip,
    )


def _effective_port(authority: _Authority, protocol: str) -> int:
    if authority.explicit_port is not None:
        return authority.explicit_port
    return _default_port(protocol)


def _parse_absolute_url(value: str) -> _ParsedAbsolute:
    scheme_info = _parse_scheme(value)
    if scheme_info is None:
        raise _UrlError("URL scheme is missing or invalid")
    scheme = scheme_info[1]
    scheme_length = scheme_info[2]
    if value[scheme_length : scheme_length + 2] != "//":
        raise _UrlError("absolute redirect targets require exact scheme://authority syntax")
    authority = _extract_raw_authority(value)
    if authority is None or authority == "":
        raise _UrlError("absolute redirect target must include an authority")
    suffix_start = scheme_length + 2 + len(authority)
    suffix = value[suffix_start:]
    path, query_present, query, fragment_present, fragment = _split_suffix(suffix)
    if path and not path.startswith("/"):
        raise _UrlError("absolute URL path is malformed")
    parsed_authority = _parse_authority(authority, scheme)
    return _ParsedAbsolute(
        scheme=scheme,
        authority=parsed_authority,
        path=path,
        query_present=query_present,
        query=query,
        fragment_present=fragment_present,
        fragment=fragment,
    )


def _is_ip_literal_hostname(hostname: str) -> bool:
    return (hostname.startswith("[") and hostname.endswith("]")) or _IPV4_RE.fullmatch(hostname) is not None


def _validate_hostname_shape(hostname: str, label: str) -> str:
    if hostname == "":
        _config_error(label + " must include a host", hostname)
    if hostname.startswith("[") and hostname.endswith("]"):
        return hostname
    if hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
        _config_error(label + " must not contain empty or trailing host labels", hostname)
    return hostname


def _assert_config_text(value: Any, label: str, maximum_length: Optional[int] = None) -> str:
    if not isinstance(value, str) or value == "":
        _config_error(label + " must be a non-empty string", value)
    if maximum_length is not None and len(value) > maximum_length:
        _config_error(label + " exceeds the configured length limit", value)
    if any(_raw_forbidden(char) for char in value):
        _config_error(label + " contains whitespace, control or invisible characters", value)
    if "\\" in value:
        _config_error(label + " must not contain a backslash", value)
    return value


def _as_string_list(value: Any, label: str) -> List[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, (list, tuple)):
        _config_error(label + " must be a string or a list or tuple of strings", value)
    entries = list(value)
    for entry in entries:
        if not isinstance(entry, str):
            _config_error(label + " entries must be strings", entry)
    return entries


def _parse_allowed_origin_entry(value: str) -> AllowedOrigin:
    _assert_config_text(value, "allowed_origins entry")
    if not _validate_percent_encoding(value):
        _config_error("allowed_origins entry contains malformed percent encoding", value)
    scheme = _parse_scheme(value)
    if scheme is None or scheme[1] not in ("http", "https"):
        _config_error("allowed_origins entries must use the http or https scheme", value)
    authority = _extract_raw_authority(value)
    if not authority:
        _config_error("allowed_origins entries must use exact scheme://authority syntax", value)
    if "@" in authority:
        _config_error("allowed_origins entries must not contain userinfo", value)
    suffix = value[scheme[2] + 2 + len(authority) :]
    if suffix not in ("", "/"):
        _config_error("allowed_origins entries must not contain a path", value)
    if "?" in value or "#" in value:
        _config_error("allowed_origins entries must not contain a query or fragment", value)
    try:
        parsed_authority = _parse_authority(authority, scheme[1])
    except _UrlError:
        _config_error("allowed_origins entry is not a valid absolute URL", value)
    hostname = _validate_hostname_shape(parsed_authority.hostname, "allowed_origins entry")
    port = _effective_port(parsed_authority, scheme[1])
    origin = scheme[1] + "://" + parsed_authority.host
    return AllowedOrigin(origin=origin, protocol=scheme[1], hostname=hostname, port=port)


def _parse_allowed_host_entry(value: str) -> AllowedHost:
    _assert_config_text(value, "allowed_hosts entry")
    if any(char in value for char in ("*", "@", "/", "?", "#", "%")):
        _config_error("allowed_hosts entries must be literal hosts without wildcards or URL syntax", value)
    try:
        parsed_authority = _parse_authority(value, "https")
    except _UrlError:
        _config_error("allowed_hosts entry is not a valid host", value)
    hostname = _validate_hostname_shape(parsed_authority.hostname, "allowed_hosts entry")
    return AllowedHost(hostname=hostname, port=parsed_authority.explicit_port)


def _validate_blocked_path_decoding(value: str) -> None:
    current = value
    for _layer in range(MAX_DECODE_LAYER_LIMIT):
        decoded = _decode_percent_layer(current)
        if decoded.invalid_utf8:
            _config_error("blocked_paths entry percent-decodes to invalid UTF-8", value)
        if not decoded.changed or decoded.value is None:
            break
        current = decoded.value
        if any(_decoded_forbidden(char) for char in current):
            _config_error("blocked_paths entry percent-decodes to control or invisible characters", value)
        if "\\" in current:
            _config_error("blocked_paths entry percent-decodes to a backslash", value)


def _canonicalize_blocked_path(value: str) -> str:
    _assert_config_text(value, "blocked_paths entry")
    if "?" in value or "#" in value:
        _config_error("blocked_paths entries are paths only, without query or fragment", value)
    if not _validate_percent_encoding(value):
        _config_error("blocked_paths entry contains malformed percent encoding", value)
    if not value.startswith("/") or value.startswith("//"):
        _config_error("blocked_paths entries must start with exactly one slash", value)
    _validate_blocked_path_decoding(value)
    return _uppercase_percent_triplets(_normalize_path(value))


def _parse_list_option(value: Any, label: str, parser: Any) -> Tuple[Any, ...]:
    entries = _as_string_list(value, label)
    seen = set()
    parsed_entries = []
    for entry in entries:
        parsed = parser(entry)
        key = repr(parsed)
        if key in seen:
            continue
        seen.add(key)
        parsed_entries.append(parsed)
    return tuple(parsed_entries)


def _parse_allow_protocols(value: Any) -> Tuple[str, ...]:
    entries = _as_string_list(value, "allow_protocols")
    present = set()
    for entry in entries:
        lowered = entry.lower()
        if lowered.endswith(":"):
            lowered = lowered[:-1]
        if lowered not in ("http", "https"):
            _config_error("allow_protocols supports only http and https redirect targets", entry)
        present.add(lowered)
    canonical = tuple(protocol for protocol in ("http", "https") if protocol in present)
    if not canonical:
        _config_error("allow_protocols must not be empty", value)
    return canonical


def _assert_boolean(value: Any, key: str) -> bool:
    if type(value) is not bool:
        _config_error(key + " must be a boolean", value)
    return value


def _assert_positive_integer(value: Any, key: str, maximum: Optional[int] = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        _config_error(key + " must be a positive integer within its supported range", value)
    return value


def _default_values() -> Dict[str, Any]:
    return {
        "allowed_origins": (),
        "allowed_hosts": (),
        "allow_subdomains": False,
        "allow_protocols": ("http", "https"),
        "allow_userinfo": False,
        "allow_ip_literals": False,
        "allow_query": True,
        "allow_hash": True,
        "normalize_dot_segments": True,
        "blocked_paths": (),
        "fallback": "/",
        "max_length": DEFAULT_MAX_LENGTH,
        "max_decode_layers": DEFAULT_MAX_DECODE_LAYERS,
        "raise_on_unsafe": False,
    }


def _validate_dependent_config(values: Dict[str, Any]) -> None:
    for origin in values["allowed_origins"]:
        if origin.protocol not in values["allow_protocols"]:
            _config_error("allowed_origins contains a protocol disabled by allow_protocols", origin.origin)
        if _is_ip_literal_hostname(origin.hostname) and not values["allow_ip_literals"]:
            _config_error("allowed_origins contains an IP literal but allow_ip_literals is false", origin.origin)
    for host in values["allowed_hosts"]:
        if _is_ip_literal_hostname(host.hostname) and not values["allow_ip_literals"]:
            _config_error("allowed_hosts contains an IP literal but allow_ip_literals is false", host.hostname)


def _build_values(options: Dict[str, Any], base: Optional["RedirectPolicy"] = None) -> Dict[str, Any]:
    if base is None:
        values = _default_values()
    else:
        values = {key: getattr(base, key) for key in _KNOWN_OPTION_KEYS}
    for key, value in options.items():
        if key not in _KNOWN_OPTION_KEYS:
            _config_error("unknown option key: " + key, key)
        if key == "allowed_origins":
            values[key] = _parse_list_option(value, "allowed_origins", _parse_allowed_origin_entry)
        elif key == "allowed_hosts":
            values[key] = _parse_list_option(value, "allowed_hosts", _parse_allowed_host_entry)
        elif key == "allow_protocols":
            values[key] = _parse_allow_protocols(value)
        elif key == "blocked_paths":
            values[key] = _parse_list_option(value, "blocked_paths", _canonicalize_blocked_path)
        elif key == "fallback":
            if not isinstance(value, str) or value == "":
                _config_error("fallback must be a non-empty string", value)
            values[key] = value
        elif key == "max_length":
            values[key] = _assert_positive_integer(value, "max_length")
        elif key == "max_decode_layers":
            values[key] = _assert_positive_integer(value, "max_decode_layers", MAX_DECODE_LAYER_LIMIT)
        elif key in _BOOLEAN_OPTIONS:
            values[key] = _assert_boolean(value, key)
    _validate_dependent_config(values)

    probe_config = SimpleNamespace(**values)
    probe = _evaluate_redirect_value(values["fallback"], probe_config)
    if not probe.safe:
        _config_error(
            "fallback is not safe under the configured policy ({})".format(probe.code),
            values["fallback"],
        )
    canonical_probe = _evaluate_redirect_value(probe.normalized, probe_config)
    if not canonical_probe.safe or canonical_probe.normalized != probe.normalized:
        _config_error("fallback canonicalization is not stable under the configured policy", values["fallback"])
    values["fallback"] = probe.normalized
    return values


class RedirectPolicy:
    """Immutable redirect validation policy.

    Keyword arguments match the module-level functions: ``allowed_origins``,
    ``allowed_hosts``, ``allow_subdomains``, ``allow_protocols``,
    ``allow_userinfo``, ``allow_ip_literals``, ``allow_query``, ``allow_hash``,
    ``normalize_dot_segments``, ``blocked_paths``, ``fallback``,
    ``max_length``, ``max_decode_layers``, and ``raise_on_unsafe``.
    """

    __slots__ = tuple(sorted(_KNOWN_OPTION_KEYS))

    def __init__(self, **options: Any) -> None:
        values = _build_values(dict(options), None)
        self._install(values)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("RedirectPolicy is immutable")

    def _install(self, values: Dict[str, Any]) -> None:
        for key, value in values.items():
            object.__setattr__(self, key, value)

    @classmethod
    def _from_values(cls, values: Dict[str, Any]) -> "RedirectPolicy":
        instance = cls.__new__(cls)
        instance._install(values)
        return instance

    def derive(self, **overrides: Any) -> "RedirectPolicy":
        """Return a new policy with selected settings replaced."""
        return type(self)._from_values(_build_values(dict(overrides), self))

    def __repr__(self) -> str:
        return "RedirectPolicy(fallback={!r}, max_length={!r})".format(self.fallback, self.max_length)


_DEFAULT_POLICY: Optional[RedirectPolicy] = None


def _default_policy() -> RedirectPolicy:
    global _DEFAULT_POLICY
    if _DEFAULT_POLICY is None:
        _DEFAULT_POLICY = RedirectPolicy()
    return _DEFAULT_POLICY


def _prepare_input(input: Any, config: Any) -> Any:
    if not isinstance(input, str):
        return _failure(input, INVALID_INPUT, "redirect target must be a string")
    if input == "":
        return _failure(input, INVALID_INPUT, "redirect target must not be empty")
    if len(input) > config.max_length:
        return _failure(input, LIMIT_EXCEEDED, "redirect target exceeds max_length")
    if not _validate_percent_encoding(input):
        return _failure(input, MALFORMED_ENCODING, "malformed percent encoding")

    variants = [input]
    current = input
    layers = 0
    while layers < config.max_decode_layers:
        decoded = _decode_percent_layer(current)
        if decoded.invalid_utf8:
            return _failure(input, INVALID_UTF8, "percent-decoding produces bytes that are not valid UTF-8")
        if not decoded.changed or decoded.value is None:
            break
        current = decoded.value
        layers += 1
        variants.append(current)
    if layers == config.max_decode_layers and _VALID_PERCENT_RE.search(current):
        return _failure(input, ENCODED_ATTACK, "percent-decoding depth exceeds the configured bound")

    for index, variant in enumerate(variants):
        scan = _scan_variant(variant, index == 0)
        if scan is not None:
            return _failure(input, scan[0], scan[1])

    for variant in variants:
        if not variant.startswith("/") or _leading_slash_count(variant) != 1:
            continue
        raw_path = _extract_raw_path(variant)
        normalized = _normalize_path(raw_path)
        if _leading_slash_count(normalized) >= 2:
            return _failure(input, PROTOCOL_RELATIVE, "dot-segment normalization creates a protocol-relative path")

    original_scheme = _parse_scheme(input)
    if original_scheme is None:
        for variant in variants[1:]:
            if _parse_scheme(variant) is not None:
                return _failure(input, ENCODED_ATTACK, "percent-decoding creates a URL scheme")
    return _Prepared(input=input, variants=tuple(variants), scheme=original_scheme)


def _paths_match(blocked: str, candidate: str) -> bool:
    if blocked == "/":
        return True
    if candidate == blocked:
        return True
    prefix = blocked if blocked.endswith("/") else blocked + "/"
    return candidate.startswith(prefix)


def _decoded_path_variants(pathname: str, config: Any) -> List[str]:
    variants = [pathname]
    current = pathname
    layers = 0
    while layers < config.max_decode_layers:
        decoded = _decode_percent_layer(current)
        if decoded.invalid_utf8 or decoded.value is None:
            break
        if not decoded.changed:
            break
        current = decoded.value
        layers += 1
        variants.append(_uppercase_percent_triplets(current))
    return variants


def _blocked_path_failure(input: str, pathname: str, config: Any) -> Optional[RedirectInspection]:
    if not config.blocked_paths:
        return None
    for variant in _decoded_path_variants(pathname, config):
        structural_path = variant
        end = len(structural_path)
        query_index = structural_path.find("?")
        hash_index = structural_path.find("#")
        if query_index != -1 and query_index < end:
            end = query_index
        if hash_index != -1 and hash_index < end:
            end = hash_index
        structural_path = structural_path[:end]
        if structural_path.startswith("/"):
            structural_path = _uppercase_percent_triplets(_normalize_path(structural_path))
        for blocked in config.blocked_paths:
            if _paths_match(blocked, structural_path):
                return _failure(input, BLOCKED_PATH, "redirect path is blocked by policy")
    return None


def _query_hash_failure(input: str, prepared: _Prepared, config: Any) -> Optional[RedirectInspection]:
    if not config.allow_query:
        for variant in prepared.variants:
            if "?" in variant:
                return _failure(input, QUERY_NOT_ALLOWED, "query strings are not allowed by policy")
    if not config.allow_hash:
        for variant in prepared.variants:
            if "#" in variant:
                return _failure(input, HASH_NOT_ALLOWED, "fragments are not allowed by policy")
    return None


def _dot_segment_failure(input: str, prepared: _Prepared, config: Any) -> Optional[RedirectInspection]:
    if config.normalize_dot_segments:
        return None
    for variant in prepared.variants:
        if _has_dot_segments(variant):
            return _failure(input, DOT_SEGMENT, "dot segments are not allowed when normalization is disabled")
    return None


def _host_matches(hostname: str, allowed_hostname: str, allow_subdomains: bool) -> bool:
    if hostname == allowed_hostname:
        return True
    if not allow_subdomains or _is_ip_literal_hostname(allowed_hostname):
        return False
    return len(hostname) > len(allowed_hostname) and hostname.endswith("." + allowed_hostname)


def _matches_allowed_origin(authority: _Authority, protocol: str, origin: AllowedOrigin, allow_subdomains: bool) -> bool:
    if protocol != origin.protocol:
        return False
    if _effective_port(authority, protocol) != origin.port:
        return False
    return _host_matches(authority.hostname, origin.hostname, allow_subdomains)


def _matches_allowed_host(authority: _Authority, protocol: str, host: AllowedHost, allow_subdomains: bool) -> bool:
    candidate_port = _effective_port(authority, protocol)
    if host.port is not None:
        if candidate_port != host.port:
            return False
    elif candidate_port != _default_port(protocol):
        return False
    return _host_matches(authority.hostname, host.hostname, allow_subdomains)


def _is_allowed_absolute(authority: _Authority, protocol: str, config: Any) -> bool:
    for origin in config.allowed_origins:
        if _matches_allowed_origin(authority, protocol, origin, config.allow_subdomains):
            return True
    for host in config.allowed_hosts:
        if _matches_allowed_host(authority, protocol, host, config.allow_subdomains):
            return True
    return False


def _canonical_query_and_fragment(parsed: _ParsedAbsolute) -> Tuple[Optional[str], Optional[str], str, str]:
    query = _percent_canonicalize(parsed.query, _QUERY_SAFE) if parsed.query_present else None
    fragment = _percent_canonicalize(parsed.fragment, _QUERY_SAFE) if parsed.fragment_present else None
    query_suffix = "" if query is None else "?" + query
    fragment_suffix = "" if fragment is None else "#" + fragment
    return query, fragment, query_suffix, fragment_suffix


def _evaluate_absolute(input: str, prepared: _Prepared, config: Any) -> RedirectInspection:
    assert prepared.scheme is not None
    scheme = prepared.scheme[1]
    if scheme in _HARD_BLOCKED_SCHEMES:
        return _failure(
            input,
            DANGEROUS_SCHEME,
            "this URL scheme can execute or expose local content and is never allowed",
        )
    if scheme not in config.allow_protocols:
        return _failure(input, PROTOCOL_NOT_ALLOWED, "URL scheme is not allowed by policy")
    raw_authority = _extract_raw_authority(input)
    if not raw_authority:
        return _failure(input, INVALID_URL, "absolute redirect targets require exact scheme://authority syntax")
    try:
        parsed = _parse_absolute_url(input)
    except _UrlError:
        return _failure(input, INVALID_URL, "absolute redirect target is not a valid URL")
    if "@" in raw_authority or parsed.authority.userinfo is not None:
        if not config.allow_userinfo:
            return _failure(input, USERINFO, "userinfo in redirect authority is not allowed")
    if parsed.authority.is_ip and not config.allow_ip_literals:
        return _failure(input, IP_LITERAL, "IP literal redirect hosts are not allowed")
    if not config.allowed_origins and not config.allowed_hosts:
        return _failure(input, ABSOLUTE_URL, "absolute redirect targets are not allowed without an explicit allowlist")
    if not _is_allowed_absolute(parsed.authority, parsed.scheme, config):
        return _failure(input, HOST_NOT_ALLOWED, "redirect host or origin is not allowed by policy")

    failure = _query_hash_failure(input, prepared, config)
    if failure is not None:
        return failure
    failure = _dot_segment_failure(input, prepared, config)
    if failure is not None:
        return failure

    if config.normalize_dot_segments:
        canonical_path = _percent_canonicalize(_normalize_path(parsed.path), _PATH_SAFE)
    else:
        canonical_path = _percent_canonicalize(parsed.path if parsed.path else "/", _PATH_SAFE)
    failure = _blocked_path_failure(input, canonical_path, config)
    if failure is not None:
        return failure

    query, fragment, query_suffix, fragment_suffix = _canonical_query_and_fragment(parsed)
    userinfo = parsed.authority.userinfo or ""
    visible_port = (
        parsed.authority.explicit_port
        if parsed.authority.explicit_port is not None
        and parsed.authority.explicit_port != _default_port(parsed.scheme)
        else None
    )
    normalized = (
        parsed.scheme
        + "://"
        + userinfo
        + parsed.authority.host
        + canonical_path
        + query_suffix
        + fragment_suffix
    )
    origin = parsed.scheme + "://" + parsed.authority.host
    return _success(
        input,
        normalized,
        "absolute",
        origin=origin,
        protocol=parsed.scheme,
        host=parsed.authority.host,
        hostname=parsed.authority.hostname,
        port=visible_port,
        path=canonical_path,
        query=query,
        fragment=fragment,
    )


def _evaluate_relative(input: str, prepared: _Prepared, config: Any) -> RedirectInspection:
    if not input.startswith("/"):
        return _failure(input, RELATIVE_PATH, "relative redirect targets must start with exactly one slash")
    failure = _query_hash_failure(input, prepared, config)
    if failure is not None:
        return failure
    failure = _dot_segment_failure(input, prepared, config)
    if failure is not None:
        return failure

    raw_path, query_present, raw_query, fragment_present, raw_fragment = _split_suffix(input)
    if config.normalize_dot_segments:
        canonical_path = _percent_canonicalize(_normalize_path(raw_path), _PATH_SAFE)
    else:
        canonical_path = _percent_canonicalize(raw_path, _PATH_SAFE)
    if _leading_slash_count(canonical_path) >= 2:
        return _failure(input, PROTOCOL_RELATIVE, "dot-segment normalization creates a protocol-relative path")
    failure = _blocked_path_failure(input, canonical_path, config)
    if failure is not None:
        return failure

    query = _percent_canonicalize(raw_query, _QUERY_SAFE) if query_present else None
    fragment = _percent_canonicalize(raw_fragment, _QUERY_SAFE) if fragment_present else None
    query_suffix = "" if query is None else "?" + query
    fragment_suffix = "" if fragment is None else "#" + fragment
    normalized = canonical_path + query_suffix + fragment_suffix
    return _success(
        input,
        normalized,
        "relative",
        origin=None,
        protocol=None,
        host=None,
        hostname=None,
        port=None,
        path=canonical_path,
        query=query,
        fragment=fragment,
    )


def _evaluate_redirect_value(input: Any, config: Any) -> RedirectInspection:
    prepared = _prepare_input(input, config)
    if isinstance(prepared, RedirectInspection):
        return prepared
    if prepared.scheme is not None:
        return _evaluate_absolute(input, prepared, config)
    return _evaluate_relative(input, prepared, config)


def _policy_from_options(options: Dict[str, Any]) -> RedirectPolicy:
    if not options:
        return _default_policy()
    return RedirectPolicy(**options)


def _sanitize_with_config(input: Any, config: RedirectPolicy) -> str:
    result = _evaluate_redirect_value(input, config)
    if result.safe and result.normalized is not None:
        return result.normalized
    if config.raise_on_unsafe:
        raise _failure_exception(result)
    return config.fallback


def _assert_with_config(input: Any, config: RedirectPolicy) -> str:
    result = _evaluate_redirect_value(input, config)
    if result.safe and result.normalized is not None:
        return result.normalized
    raise _failure_exception(result)


def _merge_explicit_options(
    fallback: Any,
    allowed_origins: Any,
    allowed_hosts: Any,
    allow_subdomains: Any,
    allow_protocols: Any,
    allow_userinfo: Any,
    allow_ip_literals: Any,
    allow_query: Any,
    allow_hash: Any,
    normalize_dot_segments: Any,
    blocked_paths: Any,
    max_length: Any,
    max_decode_layers: Any,
    raise_on_unsafe: Any,
    extra_options: Dict[str, Any],
) -> Dict[str, Any]:
    supplied = {
        "fallback": fallback,
        "allowed_origins": allowed_origins,
        "allowed_hosts": allowed_hosts,
        "allow_subdomains": allow_subdomains,
        "allow_protocols": allow_protocols,
        "allow_userinfo": allow_userinfo,
        "allow_ip_literals": allow_ip_literals,
        "allow_query": allow_query,
        "allow_hash": allow_hash,
        "normalize_dot_segments": normalize_dot_segments,
        "blocked_paths": blocked_paths,
        "max_length": max_length,
        "max_decode_layers": max_decode_layers,
        "raise_on_unsafe": raise_on_unsafe,
    }
    defaults = _default_values()
    options = {}
    for key, value in supplied.items():
        default = defaults[key]
        if type(value) is type(default):
            try:
                if bool(value == default):
                    continue
            except (TypeError, ValueError):
                pass
        options[key] = value
    options.update(extra_options)
    return options


def sanitize_redirect(
    target: Any,
    *,
    fallback: str = "/",
    allowed_origins: Sequence[str] = (),
    allowed_hosts: Sequence[str] = (),
    allow_subdomains: bool = False,
    allow_protocols: Sequence[str] = ("http", "https"),
    allow_userinfo: bool = False,
    allow_ip_literals: bool = False,
    allow_query: bool = True,
    allow_hash: bool = True,
    normalize_dot_segments: bool = True,
    blocked_paths: Sequence[str] = (),
    max_length: int = DEFAULT_MAX_LENGTH,
    max_decode_layers: int = DEFAULT_MAX_DECODE_LAYERS,
    raise_on_unsafe: bool = False,
    **extra_options: Any,
) -> str:
    """Return a canonical safe redirect target or the canonical fallback.

    Unsafe user input never raises by default. Set ``raise_on_unsafe=True`` to
    raise :class:`RedirectCageError` instead. Invalid policy configuration
    always raises because it is a programming error, not attacker input.
    """
    options = _merge_explicit_options(
        fallback,
        allowed_origins,
        allowed_hosts,
        allow_subdomains,
        allow_protocols,
        allow_userinfo,
        allow_ip_literals,
        allow_query,
        allow_hash,
        normalize_dot_segments,
        blocked_paths,
        max_length,
        max_decode_layers,
        raise_on_unsafe,
        extra_options,
    )
    config = _policy_from_options(options)
    return _sanitize_with_config(target, config)


def assert_safe_redirect(
    target: Any,
    *,
    fallback: str = "/",
    allowed_origins: Sequence[str] = (),
    allowed_hosts: Sequence[str] = (),
    allow_subdomains: bool = False,
    allow_protocols: Sequence[str] = ("http", "https"),
    allow_userinfo: bool = False,
    allow_ip_literals: bool = False,
    allow_query: bool = True,
    allow_hash: bool = True,
    normalize_dot_segments: bool = True,
    blocked_paths: Sequence[str] = (),
    max_length: int = DEFAULT_MAX_LENGTH,
    max_decode_layers: int = DEFAULT_MAX_DECODE_LAYERS,
    raise_on_unsafe: bool = False,
    **extra_options: Any,
) -> str:
    """Return a canonical safe redirect target or raise ``RedirectCageError``."""
    options = _merge_explicit_options(
        fallback,
        allowed_origins,
        allowed_hosts,
        allow_subdomains,
        allow_protocols,
        allow_userinfo,
        allow_ip_literals,
        allow_query,
        allow_hash,
        normalize_dot_segments,
        blocked_paths,
        max_length,
        max_decode_layers,
        raise_on_unsafe,
        extra_options,
    )
    config = _policy_from_options(options)
    return _assert_with_config(target, config)


def is_safe_redirect(
    target: Any,
    *,
    fallback: str = "/",
    allowed_origins: Sequence[str] = (),
    allowed_hosts: Sequence[str] = (),
    allow_subdomains: bool = False,
    allow_protocols: Sequence[str] = ("http", "https"),
    allow_userinfo: bool = False,
    allow_ip_literals: bool = False,
    allow_query: bool = True,
    allow_hash: bool = True,
    normalize_dot_segments: bool = True,
    blocked_paths: Sequence[str] = (),
    max_length: int = DEFAULT_MAX_LENGTH,
    max_decode_layers: int = DEFAULT_MAX_DECODE_LAYERS,
    raise_on_unsafe: bool = False,
    **extra_options: Any,
) -> bool:
    """Return only whether ``target`` is safe under the policy."""
    options = _merge_explicit_options(
        fallback,
        allowed_origins,
        allowed_hosts,
        allow_subdomains,
        allow_protocols,
        allow_userinfo,
        allow_ip_literals,
        allow_query,
        allow_hash,
        normalize_dot_segments,
        blocked_paths,
        max_length,
        max_decode_layers,
        raise_on_unsafe,
        extra_options,
    )
    config = _policy_from_options(options)
    return _evaluate_redirect_value(target, config).safe


def parse_redirect_location(
    target: Any,
    *,
    fallback: str = "/",
    allowed_origins: Sequence[str] = (),
    allowed_hosts: Sequence[str] = (),
    allow_subdomains: bool = False,
    allow_protocols: Sequence[str] = ("http", "https"),
    allow_userinfo: bool = False,
    allow_ip_literals: bool = False,
    allow_query: bool = True,
    allow_hash: bool = True,
    normalize_dot_segments: bool = True,
    blocked_paths: Sequence[str] = (),
    max_length: int = DEFAULT_MAX_LENGTH,
    max_decode_layers: int = DEFAULT_MAX_DECODE_LAYERS,
    raise_on_unsafe: bool = False,
    **extra_options: Any,
) -> RedirectInspection:
    """Inspect a redirect target without changing control flow."""
    options = _merge_explicit_options(
        fallback,
        allowed_origins,
        allowed_hosts,
        allow_subdomains,
        allow_protocols,
        allow_userinfo,
        allow_ip_literals,
        allow_query,
        allow_hash,
        normalize_dot_segments,
        blocked_paths,
        max_length,
        max_decode_layers,
        raise_on_unsafe,
        extra_options,
    )
    config = _policy_from_options(options)
    return _evaluate_redirect_value(target, config)


def safe_location_header(target: Any, *, as_bytes: bool = False, **options: Any) -> Tuple[Any, Any]:
    """Return a sanitized ``Location`` header pair for WSGI or ASGI.

    The default return value is ``("Location", value)`` for WSGI style header
    lists. With ``as_bytes=True`` it is ``(b"location", value_bytes)`` for ASGI
    style header lists.
    """
    if type(as_bytes) is not bool:
        _config_error("as_bytes must be a boolean", as_bytes)
    value = sanitize_redirect(target, **options)
    if as_bytes:
        return b"location", value.encode("ascii")
    return "Location", value


def _coerce_guard_policy(policy: Any, overrides: Dict[str, Any]) -> RedirectPolicy:
    if policy is None:
        return _policy_from_options(overrides)
    if isinstance(policy, RedirectPolicy):
        return policy.derive(**overrides) if overrides else policy
    if isinstance(policy, Mapping):
        merged = dict(policy)
        merged.update(overrides)
        return RedirectPolicy(**merged)
    _config_error("policy must be a RedirectPolicy, a mapping, or None", policy)


class RedirectGuard:
    """Reusable configured redirect guard.

    ``policy`` may be a :class:`RedirectPolicy`, a mapping of policy keyword
    arguments, or ``None``. Keyword overrides are applied immutably.
    """

    __slots__ = ("_policy",)

    def __init__(self, policy: Any = None, **overrides: Any) -> None:
        object.__setattr__(self, "_policy", _coerce_guard_policy(policy, overrides))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("RedirectGuard is immutable")

    @property
    def policy(self) -> RedirectPolicy:
        return self._policy

    def _resolve(self, overrides: Dict[str, Any]) -> RedirectPolicy:
        return self._policy.derive(**overrides) if overrides else self._policy

    def sanitize(self, target: Any, **overrides: Any) -> str:
        return _sanitize_with_config(target, self._resolve(dict(overrides)))

    def assert_safe(self, target: Any, **overrides: Any) -> str:
        return _assert_with_config(target, self._resolve(dict(overrides)))

    def is_safe(self, target: Any, **overrides: Any) -> bool:
        return _evaluate_redirect_value(target, self._resolve(dict(overrides))).safe

    def parse_location(self, target: Any, **overrides: Any) -> RedirectInspection:
        return _evaluate_redirect_value(target, self._resolve(dict(overrides)))

    def safe_location_header(self, target: Any, *, as_bytes: bool = False, **overrides: Any) -> Tuple[Any, Any]:
        if type(as_bytes) is not bool:
            _config_error("as_bytes must be a boolean", as_bytes)
        value = self.sanitize(target, **overrides)
        if as_bytes:
            return b"location", value.encode("ascii")
        return "Location", value


__all__ = [
    "AllowedHost",
    "AllowedOrigin",
    "DEFAULT_MAX_DECODE_LAYERS",
    "DEFAULT_MAX_LENGTH",
    "MAX_DECODE_LAYER_LIMIT",
    "RedirectGuard",
    "RedirectInspection",
    "RedirectPolicy",
    "assert_safe_redirect",
    "is_safe_redirect",
    "parse_redirect_location",
    "safe_location_header",
    "sanitize_redirect",
]
