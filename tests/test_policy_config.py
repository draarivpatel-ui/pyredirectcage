"""Configuration validation, policy objects, guard reuse, and error surface tests."""

import unittest

from pyredirectcage import (
    CODE,
    ERROR_CODES,
    RedirectCageError,
    RedirectGuard,
    RedirectPolicy,
    assert_safe_redirect,
    parse_redirect_location,
    safe_location_header,
    sanitize_redirect,
)

from _support import add_matrix_tests, assert_accepted, assert_rejected


def assert_config_error(case, options, fragment=None):
    with case.assertRaises(RedirectCageError) as caught:
        RedirectPolicy(**options)
    case.assertEqual(CODE["INVALID_OPTIONS"], caught.exception.code)
    if fragment is not None:
        case.assertIn(fragment, caught.exception.reason)


ORIGIN_CONFIG_ROWS = [
    "ftp://trusted.example",
    "https:trusted.example",
    "https:/trusted.example",
    "https:///trusted.example",
    "https://user@trusted.example",
    "https://trusted.example/path",
    "https://trusted.example/.",
    "https://trusted.example/./",
    "https://trusted.example/%2e",
    "https://trusted.example/%2E",
    "https://trusted.example//",
    "https://trusted.example?x=1",
    "https://trusted.example#x",
    "https://trusted.com..",
    "https://.trusted.example",
    "https://trusted.example.",
    "https://trusted example",
    "https://trusted\\example",
    "https://trusted.example/%",
]


def _check_origin_config(case, entry):
    assert_config_error(case, {"allowed_origins": [entry]})


class AllowedOriginConfigMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(AllowedOriginConfigMatrixTests, "origin", ORIGIN_CONFIG_ROWS, _check_origin_config)


HOST_CONFIG_ROWS = [
    "",
    "*example.com",
    "*.example.com",
    "user@example.com",
    "example.com/path",
    "example.com?x",
    "example.com#x",
    "example.%com",
    ".example.com",
    "example.com.",
    "example..com",
    "example com",
    "example\\com",
    "example.com:0",
    "example.com:65536",
    "example.com:abc",
    "example.com:-1",
    "2001:db8::1",
    "[2001:db8::1",
    "[2001:db8::1]x",
    "[2001:db8::1]:abc",
]


def _check_host_config(case, entry):
    options = {"allowed_hosts": [entry]}
    if "2001:db8" in entry:
        options["allow_ip_literals"] = True
    assert_config_error(case, options)


class AllowedHostConfigMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(AllowedHostConfigMatrixTests, "host", HOST_CONFIG_ROWS, _check_host_config)


BLOCKED_CONFIG_ROWS = [
    "",
    "admin",
    "//admin",
    "/admin?x=1",
    "/admin#x",
    "/admin\\x",
    "/admin%",
    "/admin%2",
    "/admin%zz",
    "/admin%ff",
    "/ad min",
    "/admin\ry",
]


def _check_blocked_config(case, entry):
    assert_config_error(case, {"blocked_paths": [entry]})


class BlockedPathConfigMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(BlockedPathConfigMatrixTests, "blocked", BLOCKED_CONFIG_ROWS, _check_blocked_config)


FALLBACK_ROWS = [
    "",
    "home",
    "//evil.example",
    "/\\evil.example",
    "/%ff",
    "/x\ry",
    "javascript:alert(1)",
    "https://evil.example/",
    "/a/../../..//evil.example",
]


def _check_fallback(case, fallback):
    assert_config_error(case, {"fallback": fallback}, "fallback")


class FallbackConfigMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(FallbackConfigMatrixTests, "fallback", FALLBACK_ROWS, _check_fallback)


class PolicyValidationTests(unittest.TestCase):
    def test_unknown_option_is_rejected(self):
        with self.assertRaises(RedirectCageError) as caught:
            sanitize_redirect("/x", unknown_option=True)
        self.assertEqual(CODE["INVALID_OPTIONS"], caught.exception.code)

    def test_boolean_option_rejects_integer_one(self):
        assert_config_error(self, {"allow_query": 1}, "boolean")

    def test_boolean_option_rejects_none(self):
        assert_config_error(self, {"allow_hash": None}, "boolean")

    def test_max_length_rejects_zero(self):
        assert_config_error(self, {"max_length": 0}, "positive")

    def test_max_length_rejects_negative(self):
        assert_config_error(self, {"max_length": -1}, "positive")

    def test_max_length_rejects_boolean(self):
        assert_config_error(self, {"max_length": True}, "positive")

    def test_max_length_rejects_float(self):
        assert_config_error(self, {"max_length": 10.0}, "positive")

    def test_max_decode_layers_rejects_zero(self):
        assert_config_error(self, {"max_decode_layers": 0}, "positive")

    def test_max_decode_layers_rejects_above_bound(self):
        assert_config_error(self, {"max_decode_layers": 17}, "positive")

    def test_max_decode_layers_accepts_bound(self):
        policy = RedirectPolicy(max_decode_layers=16)
        self.assertEqual(16, policy.max_decode_layers)

    def test_allow_protocols_rejects_empty_list(self):
        assert_config_error(self, {"allow_protocols": []}, "empty")

    def test_allow_protocols_rejects_ftp(self):
        assert_config_error(self, {"allow_protocols": ["https", "ftp"]}, "http")

    def test_allow_protocols_accepts_colon_and_case_forms(self):
        policy = RedirectPolicy(allow_protocols=["HTTPS:", "http"])
        self.assertEqual(("http", "https"), policy.allow_protocols)

    def test_allow_protocols_rejects_nonstring_entries(self):
        assert_config_error(self, {"allow_protocols": ["https", 1]})

    def test_allowed_origins_rejects_scalar_nontext(self):
        assert_config_error(self, {"allowed_origins": 3})

    def test_allowed_hosts_rejects_nonstring_entry(self):
        assert_config_error(self, {"allowed_hosts": ["trusted.example", None]})

    def test_blocked_paths_rejects_nonstring_entry(self):
        assert_config_error(self, {"blocked_paths": ["/admin", 2]})

    def test_allowed_origin_with_ip_requires_explicit_ip_opt_in(self):
        assert_config_error(self, {"allowed_origins": ["https://127.0.0.1"]}, "IP literal")

    def test_allowed_host_with_ip_requires_explicit_ip_opt_in(self):
        assert_config_error(self, {"allowed_hosts": ["127.0.0.1"]}, "IP literal")

    def test_allowed_origin_protocol_must_be_enabled(self):
        assert_config_error(
            self,
            {"allowed_origins": ["http://trusted.example"], "allow_protocols": ["https"]},
            "disabled",
        )

    def test_duplicate_canonical_origins_are_removed(self):
        policy = RedirectPolicy(
            allowed_origins=["https://trusted.example", "HTTPS://TRUSTED.EXAMPLE:443/"]
        )
        self.assertEqual(1, len(policy.allowed_origins))

    def test_duplicate_canonical_hosts_are_removed(self):
        policy = RedirectPolicy(allowed_hosts=["trusted.example", "TRUSTED.EXAMPLE"])
        self.assertEqual(1, len(policy.allowed_hosts))

    def test_fallback_is_canonicalized_at_config_time(self):
        policy = RedirectPolicy(fallback="/a/../home")
        self.assertEqual("/home", policy.fallback)

    def test_absolute_fallback_is_allowed_only_by_policy(self):
        policy = RedirectPolicy(
            fallback="https://trusted.example/home",
            allowed_origins=["https://trusted.example"],
        )
        self.assertEqual("https://trusted.example/home", policy.fallback)

    def test_policy_is_immutable(self):
        policy = RedirectPolicy()
        with self.assertRaises(AttributeError):
            policy.fallback = "/changed"

    def test_policy_slots_prevent_new_attributes(self):
        policy = RedirectPolicy()
        with self.assertRaises(AttributeError):
            policy.new_attribute = True

    def test_derive_does_not_mutate_base_policy(self):
        base = RedirectPolicy(fallback="/base")
        derived = base.derive(fallback="/derived")
        self.assertEqual("/base", base.fallback)
        self.assertEqual("/derived", derived.fallback)

    def test_policy_can_be_constructed_with_no_options(self):
        policy = RedirectPolicy()
        self.assertEqual("/", policy.fallback)
        self.assertEqual(2048, policy.max_length)
        self.assertFalse(policy.raise_on_unsafe)


class GuardTests(unittest.TestCase):
    def test_guard_reuses_policy_for_sanitize(self):
        guard = RedirectGuard(RedirectPolicy(fallback="/home"))
        self.assertEqual("/home", guard.sanitize("//evil.example"))

    def test_guard_accepts_policy_mapping(self):
        guard = RedirectGuard({"fallback": "/home"})
        self.assertEqual("/home", guard.sanitize("//evil.example"))

    def test_guard_constructor_overrides_apply_immutably(self):
        base = RedirectPolicy(fallback="/base")
        guard = RedirectGuard(base, fallback="/home")
        self.assertEqual("/base", base.fallback)
        self.assertEqual("/home", guard.sanitize("//evil.example"))

    def test_guard_method_override_does_not_mutate_policy(self):
        guard = RedirectGuard(fallback="/base")
        self.assertEqual("/home", guard.sanitize("//evil.example", fallback="/home"))
        self.assertEqual("/base", guard.sanitize("//evil.example"))

    def test_guard_assert_safe_returns_value(self):
        guard = RedirectGuard()
        self.assertEqual("/safe", guard.assert_safe("/safe"))

    def test_guard_assert_safe_raises(self):
        guard = RedirectGuard()
        with self.assertRaises(RedirectCageError):
            guard.assert_safe("//evil.example")

    def test_guard_is_safe(self):
        guard = RedirectGuard()
        self.assertIs(True, guard.is_safe("/safe"))
        self.assertIs(False, guard.is_safe("//evil.example"))

    def test_guard_parse_location(self):
        guard = RedirectGuard()
        result = guard.parse_location("/a/./b")
        self.assertTrue(result.safe)
        self.assertEqual("/a/b", result.normalized)

    def test_guard_rejects_invalid_policy_object(self):
        with self.assertRaises(RedirectCageError):
            RedirectGuard(policy=object())

    def test_guard_is_immutable(self):
        guard = RedirectGuard()
        with self.assertRaises(AttributeError):
            guard.policy = RedirectPolicy()

    def test_guard_safe_location_header_text(self):
        guard = RedirectGuard()
        self.assertEqual(("Location", "/safe"), guard.safe_location_header("/safe"))

    def test_guard_safe_location_header_bytes(self):
        guard = RedirectGuard()
        self.assertEqual((b"location", b"/safe"), guard.safe_location_header("/safe", as_bytes=True))


class HeaderAndErrorTests(unittest.TestCase):
    def test_safe_location_header_wsgi_tuple(self):
        self.assertEqual(("Location", "/x"), safe_location_header("/x"))

    def test_safe_location_header_asgi_tuple(self):
        self.assertEqual((b"location", b"/x"), safe_location_header("/x", as_bytes=True))

    def test_safe_location_header_uses_fallback(self):
        self.assertEqual(("Location", "/"), safe_location_header("//evil.example"))

    def test_safe_location_header_rejects_nonboolean_as_bytes(self):
        with self.assertRaises(RedirectCageError):
            safe_location_header("/x", as_bytes=1)

    def test_header_output_is_ascii_for_unicode_target(self):
        header, value = safe_location_header("/é", as_bytes=True)
        self.assertEqual(b"location", header)
        self.assertIsInstance(value, bytes)

    def test_error_has_machine_readable_attributes(self):
        try:
            assert_safe_redirect("//evil.example")
        except RedirectCageError as exc:
            self.assertEqual(CODE["PROTOCOL_RELATIVE"], exc.code)
            self.assertIsInstance(exc.reason, str)
            self.assertEqual("//evil.example", exc.input)
        else:
            self.fail("expected RedirectCageError")

    def test_error_string_does_not_include_attacker_input(self):
        try:
            assert_safe_redirect("//evil.example?token=secret")
        except RedirectCageError as exc:
            self.assertNotIn("secret", str(exc))
        else:
            self.fail("expected RedirectCageError")

    def test_error_to_dict_is_machine_readable(self):
        try:
            assert_safe_redirect("//evil.example")
        except RedirectCageError as exc:
            report = exc.to_dict()
            self.assertEqual("RedirectCageError", report["name"])
            self.assertEqual(exc.code, report["code"])
            self.assertEqual(exc.reason, report["reason"])
        else:
            self.fail("expected RedirectCageError")

    def test_error_codes_are_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_codes_are_stable_prefixed_strings(self):
        for code in ERROR_CODES:
            self.assertTrue(code.startswith("ERR_REDIRECTCAGE_"), code)

    def test_code_mapping_contains_documented_names(self):
        for name in (
            "INVALID_INPUT",
            "INVALID_OPTIONS",
            "LIMIT_EXCEEDED",
            "CONTROL_CHARACTER",
            "UNICODE_NORMALIZATION",
            "MALFORMED_ENCODING",
            "INVALID_UTF8",
            "ENCODED_ATTACK",
            "PROTOCOL_RELATIVE",
            "BACKSLASH",
            "DANGEROUS_SCHEME",
            "PROTOCOL_NOT_ALLOWED",
            "INVALID_URL",
            "ABSOLUTE_URL",
            "RELATIVE_PATH",
            "USERINFO",
            "IP_LITERAL",
            "HOST_NOT_ALLOWED",
            "QUERY_NOT_ALLOWED",
            "HASH_NOT_ALLOWED",
            "DOT_SEGMENT",
            "BLOCKED_PATH",
        ):
            self.assertIn(name, CODE)

    def test_code_mapping_is_immutable(self):
        with self.assertRaises(TypeError):
            CODE["NEW"] = "x"


if __name__ == "__main__":
    unittest.main()
