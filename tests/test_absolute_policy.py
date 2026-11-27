"""Absolute URL, allowlist, host canonicalization, and path policy tests."""

import unittest

from pyredirectcage import CODE, parse_redirect_location

from _support import add_matrix_tests, assert_accepted, assert_rejected


ABSOLUTE_ACCEPT_ROWS = [
    (
        "https://trusted.example",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/",
    ),
    (
        "HTTPS://TRUSTED.EXAMPLE/x",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/x",
    ),
    (
        "https://trusted.example/a/./b",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/a/b",
    ),
    (
        "https://trusted.example?",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/?",
    ),
    (
        "https://trusted.example#",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/#",
    ),
    (
        "https://trusted.example:443/x",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/x",
    ),
    (
        "https://trusted.example:0443/x",
        {"allowed_origins": ["https://trusted.example"]},
        "https://trusted.example/x",
    ),
    (
        "https://trusted.example:8443/x",
        {"allowed_origins": ["https://trusted.example:8443"]},
        "https://trusted.example:8443/x",
    ),
    (
        "http://trusted.example:80/x",
        {"allowed_hosts": ["trusted.example"]},
        "http://trusted.example/x",
    ),
    (
        "https://trusted.example:080/x",
        {"allowed_hosts": ["trusted.example:80"]},
        "https://trusted.example:80/x",
    ),
    (
        "https://trusted.example:/x",
        {"allowed_hosts": ["trusted.example"]},
        "https://trusted.example/x",
    ),
    (
        "https://%65xample.com/x",
        {"allowed_hosts": ["example.com"]},
        "https://example.com/x",
    ),
    (
        "https://xn--xample-9ua.com/x",
        {"allowed_hosts": ["xn--xample-9ua.com"]},
        "https://xn--xample-9ua.com/x",
    ),
    (
        "https://XN--XAMPLE-9UA.COM/x",
        {"allowed_hosts": ["xn--xample-9ua.com"]},
        "https://xn--xample-9ua.com/x",
    ),
    (
        "https://127.1/x",
        {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": True},
        "https://127.0.0.1/x",
    ),
    (
        "https://2130706433/x",
        {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": True},
        "https://127.0.0.1/x",
    ),
    (
        "https://0x7f.1/x",
        {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": True},
        "https://127.0.0.1/x",
    ),
    (
        "https://0177.0.0.1/x",
        {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": True},
        "https://127.0.0.1/x",
    ),
    (
        "https://127.0.0.1./x",
        {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": True},
        "https://127.0.0.1/x",
    ),
    (
        "https://[2001:0DB8:0000::0001]/x",
        {"allowed_hosts": ["[2001:db8::1]"], "allow_ip_literals": True},
        "https://[2001:db8::1]/x",
    ),
    (
        "https://[::ffff:127.0.0.1]/x",
        {"allowed_hosts": ["[::ffff:7f00:1]"], "allow_ip_literals": True},
        "https://[::ffff:7f00:1]/x",
    ),
    (
        "https://trusted.example/é?q=é#é",
        {"allowed_hosts": ["trusted.example"]},
        "https://trusted.example/%C3%A9?q=%C3%A9#%C3%A9",
    ),
    (
        "https://user@trusted.example/x",
        {"allowed_hosts": ["trusted.example"], "allow_userinfo": True},
        "https://user@trusted.example/x",
    ),
    (
        "https://user:pass@trusted.example/x",
        {"allowed_hosts": ["trusted.example"], "allow_userinfo": True},
        "https://user:pass@trusted.example/x",
    ),
    (
        "https://a@b@c/x",
        {"allowed_hosts": ["c"], "allow_userinfo": True},
        "https://a%40b@c/x",
    ),
]


def _check_absolute_accept(case, row):
    target, options, normalized = row
    result = assert_accepted(case, target, normalized, **options)
    case.assertEqual("absolute", result.kind)
    case.assertIsNotNone(result.origin)
    case.assertFalse(result.origin.endswith("/"))
    case.assertTrue(result.path.startswith("/"))


class AbsoluteAcceptanceMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(AbsoluteAcceptanceMatrixTests, "accept", ABSOLUTE_ACCEPT_ROWS, _check_absolute_accept)


ABSOLUTE_REJECT_ROWS = [
    ("https://evil.example/x", {}, "ABSOLUTE_URL"),
    ("http://evil.example/x", {}, "ABSOLUTE_URL"),
    ("https://evil.example/x", {"allowed_hosts": ["trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("https://trusted.example.evil/x", {"allowed_hosts": ["trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("https://trusted.example@evil.example/x", {"allowed_hosts": ["trusted.example"]}, "USERINFO"),
    ("https://evil.example@trusted.example/x", {"allowed_hosts": ["trusted.example"]}, "USERINFO"),
    ("https://user@trusted.example/x", {"allowed_hosts": ["trusted.example"]}, "USERINFO"),
    ("https://127.0.0.1/x", {"allowed_hosts": ["127.0.0.1"]}, "INVALID_OPTIONS"),
    ("https://127.0.0.1/x", {"allowed_origins": ["https://127.0.0.1"]}, "INVALID_OPTIONS"),
    ("https://2130706433/x", {"allowed_hosts": ["127.0.0.1"], "allow_ip_literals": False}, "INVALID_OPTIONS"),
    ("https://trusted.example./x", {"allowed_hosts": ["trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("https://eviltrusted.example/x", {"allowed_hosts": ["trusted.example"], "allow_subdomains": True}, "HOST_NOT_ALLOWED"),
    ("https://trusted.example.evil/x", {"allowed_hosts": ["trusted.example"], "allow_subdomains": True}, "HOST_NOT_ALLOWED"),
    ("https://trusted.example:8443/x", {"allowed_hosts": ["trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("http://trusted.example/x", {"allowed_origins": ["https://trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("https://trusted.example/x", {"allowed_origins": ["http://trusted.example"]}, "HOST_NOT_ALLOWED"),
    ("http://trusted.example/x", {"allowed_hosts": ["trusted.example"], "allow_protocols": ["https"]}, "PROTOCOL_NOT_ALLOWED"),
    ("https://[::1/x", {"allowed_hosts": ["[::1]"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://::1]/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://[:::]/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://[::1]x/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://[::1]:abc/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://[fe80::1%25eth0]/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://trusted.example:0/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://trusted.example:65536/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://trusted.example:-1/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://trusted.example:12x/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://example..com/x", {"allowed_hosts": ["example.com"]}, "INVALID_URL"),
    ("https://127.999.1/x", {"allowed_hosts": ["trusted.example"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://127.09.1/x", {"allowed_hosts": ["trusted.example"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://4294967296/x", {"allowed_hosts": ["trusted.example"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://trusted.example/x?q=1", {"allowed_hosts": ["trusted.example"], "allow_query": False}, "QUERY_NOT_ALLOWED"),
    ("https://trusted.example/x%3fq=1", {"allowed_hosts": ["trusted.example"], "allow_query": False}, "QUERY_NOT_ALLOWED"),
    ("https://trusted.example/x#f", {"allowed_hosts": ["trusted.example"], "allow_hash": False}, "HASH_NOT_ALLOWED"),
    ("https://trusted.example/x%23f", {"allowed_hosts": ["trusted.example"], "allow_hash": False}, "HASH_NOT_ALLOWED"),
    ("https://trusted.example/a/./b", {"allowed_hosts": ["trusted.example"], "normalize_dot_segments": False}, "DOT_SEGMENT"),
    ("https://trusted.example/a/%2e/b", {"allowed_hosts": ["trusted.example"], "normalize_dot_segments": False}, "DOT_SEGMENT"),
    ("https://éxample.com/x", {"allowed_hosts": ["xn--xample-9ua.com"]}, "INVALID_URL"),
    ("https://fass.de/x", {"allowed_hosts": ["xn--fa-hia.de"]}, "HOST_NOT_ALLOWED"),
    ("https://faß.de/x", {"allowed_hosts": ["xn--fa-hia.de"]}, "INVALID_URL"),
    ("https://ς.gr/x", {"allowed_hosts": ["xn--3xa.gr"]}, "INVALID_URL"),
    ("https://ꭲ.com/x", {"allowed_hosts": ["xn--78d.com"]}, "INVALID_URL"),
    ("https://١٢٣/x", {"allowed_hosts": ["0.0.0.123"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://１２３/x", {"allowed_hosts": ["0.0.0.123"], "allow_ip_literals": True}, "INVALID_URL"),
    ("https://trusted.example:٤٤٣/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
    ("https://trusted.example:４４３/x", {"allowed_hosts": ["trusted.example"]}, "INVALID_URL"),
]


def _check_absolute_reject(case, row):
    target, options, code_name = row
    if code_name == "INVALID_OPTIONS":
        with case.assertRaises(Exception) as caught:
            parse_redirect_location(target, **options)
        case.assertEqual(CODE[code_name], getattr(caught.exception, "code", None))
    else:
        assert_rejected(case, target, CODE[code_name], **options)


class AbsoluteRejectionMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(AbsoluteRejectionMatrixTests, "reject", ABSOLUTE_REJECT_ROWS, _check_absolute_reject)


SUBDOMAIN_ROWS = [
    ("https://trusted.example/x", True),
    ("https://www.trusted.example/x", True),
    ("https://deep.www.trusted.example/x", True),
    ("https://eviltrusted.example/x", False),
    ("https://evil-trusted.example/x", False),
    ("https://trusted.example.evil/x", False),
    ("https://trustedexample/x", False),
    ("https://WWW.TRUSTED.EXAMPLE/x", True),
    ("https://www.trusted.example./x", False),
    ("https://www.xn--xample-9ua.com/x", False),
]


def _check_subdomain(case, row):
    target, expected = row
    result = parse_redirect_location(
        target,
        allowed_hosts=["trusted.example"],
        allow_subdomains=True,
    )
    case.assertIs(result.safe, expected, target)


class SubdomainBoundaryMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(SubdomainBoundaryMatrixTests, "subdomain", SUBDOMAIN_ROWS, _check_subdomain)


BLOCKED_ROWS = [
    ("/admin", "/admin", True),
    ("/admin", "/admin/", True),
    ("/admin", "/admin/panel", True),
    ("/admin", "/administrator", False),
    ("/admin/", "/admin", False),
    ("/admin/", "/admin/panel", True),
    ("/admin", "/Admin", False),
    ("/admin", "/a%64min", True),
    ("/admin", "/%61dmin", True),
    ("/admin", "/%2561dmin", True),
    ("/admin", "/x/../admin", True),
    ("/admin", "/x%2f..%2fadmin", True),
    ("/admin", "/admin%3fnext=/home", True),
    ("/admin", "/%2e%2e/admin", True),
    ("/logout", "/logout/../admin", False),
]


def _check_blocked(case, row):
    blocked, target, expected_blocked = row
    result = parse_redirect_location(target, blocked_paths=[blocked])
    if expected_blocked:
        case.assertEqual(CODE["BLOCKED_PATH"], result.code, target)
    else:
        case.assertNotEqual(CODE["BLOCKED_PATH"], result.code, target)
        case.assertTrue(result.safe, target)


class BlockedPathMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(BlockedPathMatrixTests, "blocked", BLOCKED_ROWS, _check_blocked)


class EncodedBlockedPathPolicyTests(unittest.TestCase):
    def test_percent_encoded_blocked_entry_matches_decoded_target(self):
        assert_rejected(self, "/admin", CODE["BLOCKED_PATH"], blocked_paths=["/a%64min"])

    def test_double_encoded_blocked_entry_matches_decoded_target(self):
        assert_rejected(self, "/admin", CODE["BLOCKED_PATH"], blocked_paths=["/%2561dmin"])

    def test_encoded_slash_in_blocked_entry_matches_decoded_descendant(self):
        assert_rejected(self, "/admin/panel", CODE["BLOCKED_PATH"], blocked_paths=["/admin%2fpanel"])

    def test_plain_blocked_entry_still_matches_encoded_target(self):
        assert_rejected(self, "/a%64min", CODE["BLOCKED_PATH"], blocked_paths=["/admin"])


class AbsoluteMetadataTests(unittest.TestCase):
    def test_absolute_inspection_metadata(self):
        result = assert_accepted(
            self,
            "https://trusted.example:8443/a/./b?q=1#f",
            "https://trusted.example:8443/a/b?q=1#f",
            allowed_hosts=["trusted.example:8443"],
        )
        self.assertEqual("https", result.protocol)
        self.assertEqual("trusted.example:8443", result.host)
        self.assertEqual("trusted.example", result.hostname)
        self.assertEqual(8443, result.port)
        self.assertEqual("https://trusted.example:8443", result.origin)
        self.assertEqual("/a/b", result.path)
        self.assertEqual("q=1", result.query)
        self.assertEqual("f", result.fragment)

    def test_default_port_metadata_is_none(self):
        result = assert_accepted(
            self,
            "https://trusted.example:443/x",
            "https://trusted.example/x",
            allowed_hosts=["trusted.example"],
        )
        self.assertIsNone(result.port)
        self.assertEqual("trusted.example", result.host)

    def test_allowed_hosts_can_match_http_and_https_default_ports(self):
        options = {"allowed_hosts": ["trusted.example"]}
        self.assertTrue(parse_redirect_location("http://trusted.example/x", **options).safe)
        self.assertTrue(parse_redirect_location("https://trusted.example/x", **options).safe)

    def test_allowed_origin_carries_scheme(self):
        options = {"allowed_origins": ["https://trusted.example"]}
        self.assertTrue(parse_redirect_location("https://trusted.example/x", **options).safe)
        self.assertFalse(parse_redirect_location("http://trusted.example/x", **options).safe)

    def test_blocked_path_applies_to_absolute_targets(self):
        result = parse_redirect_location(
            "https://trusted.example/admin/panel",
            allowed_hosts=["trusted.example"],
            blocked_paths=["/admin"],
        )
        self.assertEqual(CODE["BLOCKED_PATH"], result.code)

    def test_ipv6_inspection_uses_bracketed_hostname(self):
        result = assert_accepted(
            self,
            "https://[2001:db8::1]:8443/x",
            "https://[2001:db8::1]:8443/x",
            allowed_hosts=["[2001:db8::1]:8443"],
            allow_ip_literals=True,
        )
        self.assertEqual("[2001:db8::1]", result.hostname)
        self.assertEqual("[2001:db8::1]:8443", result.host)

    def test_absolute_canonical_output_is_idempotent(self):
        options = {"allowed_hosts": ["trusted.example"]}
        first = parse_redirect_location("https://TRUSTED.example/é/./x", **options).normalized
        second = parse_redirect_location(first, **options)
        self.assertTrue(second.safe)
        self.assertEqual(first, second.normalized)


class ParserDifferentialRegressionTests(unittest.TestCase):
    def test_percent_encoded_non_ascii_host_fails_closed(self):
        assert_rejected(
            self,
            "https://%C3%A9xample.com/x",
            CODE["INVALID_URL"],
            allowed_hosts=["xn--xample-9ua.com"],
        )

    def test_numeric_host_with_thousands_of_digits_is_invalid_without_unhandled_exception(self):
        assert_rejected(
            self,
            "https://" + "9" * 5000 + "/x",
            CODE["INVALID_URL"],
            allowed_hosts=["trusted.example"],
            allow_ip_literals=True,
            max_length=10000,
        )

    def test_port_with_thousands_of_digits_is_invalid_without_unhandled_exception(self):
        assert_rejected(
            self,
            "https://trusted.example:" + "9" * 5000 + "/x",
            CODE["INVALID_URL"],
            allowed_hosts=["trusted.example"],
            max_length=10000,
        )

    def test_zero_padded_port_keeps_browser_compatible_default_port_semantics(self):
        assert_accepted(
            self,
            "https://trusted.example:" + "0" * 100 + "443/x",
            "https://trusted.example/x",
            allowed_hosts=["trusted.example"],
        )


if __name__ == "__main__":
    unittest.main()
