"""Relative redirect acceptance, canonicalization, and core API behavior."""

import unittest

from pyredirectcage import (
    CODE,
    RedirectCageError,
    assert_safe_redirect,
    is_safe_redirect,
    parse_redirect_location,
    sanitize_redirect,
)

from _support import add_matrix_tests, assert_accepted, assert_rejected, assert_sanitized


CANONICAL_ROWS = [
    ("/", "/"),
    ("/health", "/health"),
    ("/a/b", "/a/b"),
    ("/a//b", "/a//b"),
    ("/a/b/", "/a/b/"),
    ("/a/./b", "/a/b"),
    ("/a/b/../c", "/a/c"),
    ("/a/b/.", "/a/b/"),
    ("/a/b/..", "/a/"),
    ("/a/b/../", "/a/"),
    ("/../x", "/x"),
    ("/../../x", "/x"),
    ("/a/%2e/b", "/a/b"),
    ("/a/%2E/b", "/a/b"),
    ("/a/%2e%2e/b", "/b"),
    ("/a/.%2e/b", "/b"),
    ("/a/%2e./b", "/b"),
    ("/%2e", "/"),
    ("/%2e%2e", "/"),
    ("/a/..", "/"),
    ("/a/../", "/"),
    ("/a//../b", "/a/b"),
    ("/a//../../b", "/b"),
    ("/x%2fy", "/x%2Fy"),
    ("/x%2Fy", "/x%2Fy"),
    ("/%25", "/%25"),
    ("/%252", "/%252"),
    ("/x%20y", "/x%20y"),
    ("/é", "/%C3%A9"),
    ("/😀", "/%F0%9F%98%80"),
    ("/x?q=1&b=2", "/x?q=1&b=2"),
    ("/x?", "/x?"),
    ("/x#frag", "/x#frag"),
    ("/x#", "/x#"),
    ("/x?q=<>", "/x?q=%3C%3E"),
    ("/x?q=é#é", "/x?q=%C3%A9#%C3%A9"),
    ("/x<y", "/x%3Cy"),
    ("/x\"y", "/x%22y"),
    ("/x[y]", "/x%5By%5D"),
    ("/x`y", "/x%60y"),
]


def _check_canonical(case, row):
    target, normalized = row
    result = assert_accepted(case, target, normalized)
    case.assertEqual("relative", result.kind)
    case.assertIsNone(result.origin)
    case.assertTrue(result.path.startswith("/"))


class RelativeCanonicalMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(RelativeCanonicalMatrixTests, "canonical", CANONICAL_ROWS, _check_canonical)


class RelativeApiTests(unittest.TestCase):
    def test_default_fallback_for_protocol_relative(self):
        assert_sanitized(self, "//evil.example", "/")

    def test_custom_fallback_is_returned_canonically(self):
        assert_sanitized(self, "//evil.example", "/home", fallback="/a/../home")

    def test_safe_target_does_not_use_fallback(self):
        assert_sanitized(self, "/safe", "/safe", fallback="/home")

    def test_raise_on_unsafe_raises_machine_readable_error(self):
        with self.assertRaises(RedirectCageError) as caught:
            sanitize_redirect("//evil.example", raise_on_unsafe=True)
        self.assertEqual(CODE["PROTOCOL_RELATIVE"], caught.exception.code)

    def test_assert_safe_redirect_returns_normalized_value(self):
        self.assertEqual("/a/b", assert_safe_redirect("/a/./b"))

    def test_assert_safe_redirect_raises_for_unsafe_target(self):
        with self.assertRaises(RedirectCageError) as caught:
            assert_safe_redirect("javascript:alert(1)")
        self.assertEqual(CODE["DANGEROUS_SCHEME"], caught.exception.code)
        self.assertIn("ERR_REDIRECTCAGE_DANGEROUS_SCHEME", str(caught.exception))

    def test_is_safe_redirect_is_strict_boolean_for_safe_input(self):
        self.assertIs(True, is_safe_redirect("/safe"))

    def test_is_safe_redirect_is_strict_boolean_for_unsafe_input(self):
        self.assertIs(False, is_safe_redirect("https://evil.example"))

    def test_none_input_is_rejected_without_throwing(self):
        assert_rejected(self, None, CODE["INVALID_INPUT"])
        self.assertEqual("/", sanitize_redirect(None))

    def test_bytes_input_is_rejected(self):
        assert_rejected(self, b"/safe", CODE["INVALID_INPUT"])

    def test_integer_input_is_rejected(self):
        assert_rejected(self, 7, CODE["INVALID_INPUT"])

    def test_empty_input_is_rejected(self):
        assert_rejected(self, "", CODE["INVALID_INPUT"])

    def test_bare_relative_path_is_rejected(self):
        assert_rejected(self, "home", CODE["RELATIVE_PATH"])

    def test_dot_relative_path_is_rejected(self):
        assert_rejected(self, "./home", CODE["RELATIVE_PATH"])

    def test_parent_relative_path_is_rejected(self):
        assert_rejected(self, "../home", CODE["RELATIVE_PATH"])

    def test_max_length_boundary_accepts_exact_length(self):
        target = "/" + "a" * 9
        result = assert_accepted(self, target, target, max_length=10)
        self.assertEqual(10, len(result.input))

    def test_max_length_boundary_rejects_one_over(self):
        assert_rejected(self, "/" + "a" * 10, CODE["LIMIT_EXCEEDED"], max_length=10)

    def test_default_max_length_rejects_large_input(self):
        assert_rejected(self, "/" + "a" * 2048, CODE["LIMIT_EXCEEDED"])

    def test_malformed_percent_at_end_is_rejected(self):
        assert_rejected(self, "/x%", CODE["MALFORMED_ENCODING"])

    def test_malformed_percent_with_one_hex_digit_is_rejected(self):
        assert_rejected(self, "/x%2", CODE["MALFORMED_ENCODING"])

    def test_malformed_percent_with_nonhex_digits_is_rejected(self):
        assert_rejected(self, "/x%zz", CODE["MALFORMED_ENCODING"])

    def test_malformed_percent_in_query_is_rejected(self):
        assert_rejected(self, "/x?q=%", CODE["MALFORMED_ENCODING"])

    def test_nested_incomplete_percent_is_inert_and_preserved(self):
        assert_accepted(self, "/%252", "/%252")

    def test_relative_inspection_metadata(self):
        result = assert_accepted(self, "/a/./b?q=1#f", "/a/b?q=1#f")
        self.assertEqual("/a/b", result.path)
        self.assertEqual("q=1", result.query)
        self.assertEqual("f", result.fragment)
        self.assertIsNone(result.protocol)
        self.assertIsNone(result.host)
        self.assertIsNone(result.hostname)
        self.assertIsNone(result.port)

    def test_failed_inspection_has_nullable_metadata(self):
        result = parse_redirect_location("//evil.example")
        self.assertFalse(result.safe)
        self.assertIsNone(result.normalized)
        self.assertIsNone(result.kind)
        self.assertIsNone(result.origin)
        self.assertIsNone(result.path)

    def test_canonical_output_is_idempotent(self):
        once = sanitize_redirect("/é/./x?q=<>")
        twice = sanitize_redirect(once)
        self.assertEqual(twice, once)

    def test_output_is_printable_ascii_for_unicode_input(self):
        value = sanitize_redirect("/é😀?q=é#é")
        self.assertTrue(all(0x20 <= ord(char) <= 0x7E for char in value))

    def test_normalize_dot_segments_false_rejects_plain_dot(self):
        assert_rejected(self, "/a/./b", CODE["DOT_SEGMENT"], normalize_dot_segments=False)

    def test_normalize_dot_segments_false_rejects_encoded_dot(self):
        assert_rejected(self, "/a/%2e/b", CODE["DOT_SEGMENT"], normalize_dot_segments=False)

    def test_normalize_dot_segments_false_accepts_dot_free_path(self):
        assert_accepted(self, "/a/b", "/a/b", normalize_dot_segments=False)

    def test_query_can_be_disabled(self):
        assert_rejected(self, "/x?a=1", CODE["QUERY_NOT_ALLOWED"], allow_query=False)

    def test_encoded_query_can_be_disabled(self):
        assert_rejected(self, "/x%3fa=1", CODE["QUERY_NOT_ALLOWED"], allow_query=False)

    def test_fragment_can_be_disabled(self):
        assert_rejected(self, "/x#f", CODE["HASH_NOT_ALLOWED"], allow_hash=False)

    def test_encoded_fragment_can_be_disabled(self):
        assert_rejected(self, "/x%23f", CODE["HASH_NOT_ALLOWED"], allow_hash=False)

    def test_slash_lookalike_is_percent_encoded_path_text(self):
        assert_accepted(self, "/\u2044evil.example", "/%E2%81%84evil.example")

    def test_math_slash_lookalike_is_percent_encoded_path_text(self):
        assert_accepted(self, "/\u2215evil.example", "/%E2%88%95evil.example")


if __name__ == "__main__":
    unittest.main()
