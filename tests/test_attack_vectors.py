"""OWASP CWE-601 attack vector regression tests."""

import unittest

from pyredirectcage import CODE, parse_redirect_location, sanitize_redirect

from _support import add_matrix_tests, assert_rejected


ATTACK_ROWS = [
    ("//evil.example", "PROTOCOL_RELATIVE"),
    ("///evil.example", "PROTOCOL_RELATIVE"),
    ("////evil.example", "PROTOCOL_RELATIVE"),
    ("/\\/evil.example", "BACKSLASH"),
    ("\\/evil.example", "BACKSLASH"),
    ("/\\evil.example", "BACKSLASH"),
    ("//\\evil.example", "BACKSLASH"),
    ("/%5cevil.example", "BACKSLASH"),
    ("/%5Cevil.example", "BACKSLASH"),
    ("/%255cevil.example", "BACKSLASH"),
    ("/%2f%2fevil.example", "PROTOCOL_RELATIVE"),
    ("/%2F%2Fevil.example", "PROTOCOL_RELATIVE"),
    ("/%252f%252fevil.example", "PROTOCOL_RELATIVE"),
    ("/%2f/evil.example", "PROTOCOL_RELATIVE"),
    ("/a/../../..//evil.example", "PROTOCOL_RELATIVE"),
    ("/a/%2e%2e/..//evil.example", "PROTOCOL_RELATIVE"),
    ("/a/%252e%252e/..//evil.example", "PROTOCOL_RELATIVE"),
    ("/..//evil.example", "PROTOCOL_RELATIVE"),
    ("/./..//evil.example", "PROTOCOL_RELATIVE"),
    ("/x/..%2f..%2f/evil.example", "PROTOCOL_RELATIVE"),
    ("javascript:alert(1)", "DANGEROUS_SCHEME"),
    ("JaVaScRiPt:alert(1)", "DANGEROUS_SCHEME"),
    ("data:text/html,<script>alert(1)</script>", "DANGEROUS_SCHEME"),
    ("vbscript:msgbox(1)", "DANGEROUS_SCHEME"),
    ("file:///etc/passwd", "DANGEROUS_SCHEME"),
    ("blob:https://evil.example/id", "DANGEROUS_SCHEME"),
    ("about:blank", "DANGEROUS_SCHEME"),
    ("filesystem:https://evil.example/x", "DANGEROUS_SCHEME"),
    ("chrome://settings", "DANGEROUS_SCHEME"),
    ("chrome-extension://abc/page.html", "DANGEROUS_SCHEME"),
    ("moz-extension://abc/page.html", "DANGEROUS_SCHEME"),
    ("ms-browser-extension://abc/page.html", "DANGEROUS_SCHEME"),
    ("intent://evil.example/x", "DANGEROUS_SCHEME"),
    ("ftp://evil.example/file", "PROTOCOL_NOT_ALLOWED"),
    ("mailto:user@example.com", "PROTOCOL_NOT_ALLOWED"),
    ("gopher://evil.example/", "PROTOCOL_NOT_ALLOWED"),
    ("ssh://evil.example/", "PROTOCOL_NOT_ALLOWED"),
    ("https:evil.example", "INVALID_URL"),
    ("https:/evil.example", "INVALID_URL"),
    ("https:///evil.example", "INVALID_URL"),
    ("http:///evil.example", "INVALID_URL"),
    ("https://", "INVALID_URL"),
    ("https://?x=1", "INVALID_URL"),
    ("https://#x", "INVALID_URL"),
    ("%6aavascript:alert(1)", "ENCODED_ATTACK"),
    ("%6A%61vascript:alert(1)", "ENCODED_ATTACK"),
    ("javascript%3aalert(1)", "ENCODED_ATTACK"),
    ("https%3a%2f%2fevil.example", "ENCODED_ATTACK"),
    ("https:%2f%2fevil.example", "INVALID_URL"),
    ("/x\ry", "CONTROL_CHARACTER"),
    ("/x\ny", "CONTROL_CHARACTER"),
    ("/x\ty", "CONTROL_CHARACTER"),
    ("/x\0y", "CONTROL_CHARACTER"),
    ("/x\x85y", "CONTROL_CHARACTER"),
    ("/x y", "CONTROL_CHARACTER"),
    ("/x\ufeffy", "CONTROL_CHARACTER"),
    ("/x\u200by", "CONTROL_CHARACTER"),
    ("/x\u2028y", "CONTROL_CHARACTER"),
    ("/x\u202ay", "CONTROL_CHARACTER"),
    ("/x%0dy", "CONTROL_CHARACTER"),
    ("/x%0ay", "CONTROL_CHARACTER"),
    ("/x%09y", "CONTROL_CHARACTER"),
    ("/x%00y", "CONTROL_CHARACTER"),
    ("/x%1fy", "CONTROL_CHARACTER"),
    ("/x%7fy", "CONTROL_CHARACTER"),
    ("/x%c2%85y", "CONTROL_CHARACTER"),
    ("/x%250dy", "CONTROL_CHARACTER"),
    ("/x%2525250dy", "CONTROL_CHARACTER"),
    ("/%ff", "INVALID_UTF8"),
    ("/%fe", "INVALID_UTF8"),
    ("/%c0%af/evil.example", "INVALID_UTF8"),
    ("/%e0%80%af", "INVALID_UTF8"),
    ("/%ed%a0%80", "INVALID_UTF8"),
    ("/%f4%90%80%80", "INVALID_UTF8"),
    ("/%25ff", "INVALID_UTF8"),
    ("/%25c0%25af", "INVALID_UTF8"),
    ("/x%", "MALFORMED_ENCODING"),
    ("/x%2", "MALFORMED_ENCODING"),
    ("/x%zz", "MALFORMED_ENCODING"),
    ("/x%2g", "MALFORMED_ENCODING"),
    ("/\uff0fevil.example", "UNICODE_NORMALIZATION"),
    ("https\uff1a//evil.example", "UNICODE_NORMALIZATION"),
    ("https://example\uff0ecom/x", "UNICODE_NORMALIZATION"),
    ("/％2fevil.example", "UNICODE_NORMALIZATION"),
    ("/x\ufe0f", "CONTROL_CHARACTER"),
]


def _check_attack(case, row):
    target, code_name = row
    assert_rejected(case, target, CODE[code_name])


class AttackVectorMatrixTests(unittest.TestCase):
    pass


add_matrix_tests(AttackVectorMatrixTests, "attack", ATTACK_ROWS, _check_attack)


FUZZ_TOKENS = [
    "/",
    "//",
    "\\",
    "%2f",
    "%5c",
    ".",
    "..",
    "%2e",
    "%252e",
    "@",
    "?",
    "#",
    "evil.example",
    "trusted.example",
    "\u2044",
]


def _fuzz_rows():
    rows = []
    for left in FUZZ_TOKENS[:10]:
        for right in FUZZ_TOKENS[5:12]:
            rows.append("/a" + left + right + "z")
    return rows[:60]


def _check_fuzz(case, target):
    result = parse_redirect_location(target)
    if not result.safe:
        case.assertIsNone(result.normalized)
        case.assertIsNotNone(result.code)
        return
    value = result.normalized
    case.assertIsNotNone(value)
    case.assertTrue(all(0x20 <= ord(char) <= 0x7E for char in value))
    case.assertFalse(value.startswith("//"))
    case.assertNotIn("\\", value)
    again = parse_redirect_location(value)
    case.assertTrue(again.safe, "canonical output was not idempotently safe: {!r}".format(value))
    case.assertEqual(value, again.normalized)


class AdversarialCorpusTests(unittest.TestCase):
    pass


add_matrix_tests(AdversarialCorpusTests, "fuzz", _fuzz_rows(), _check_fuzz)


class NestedEncodingBoundaryTests(unittest.TestCase):
    def nested_slash(self, depth):
        return "%" + "25" * depth + "2f"

    def test_decode_bound_allows_exactly_configured_depth(self):
        target = self.nested_slash(7)
        result = parse_redirect_location(target, max_length=10000)
        self.assertEqual(CODE["RELATIVE_PATH"], result.code)

    def test_decode_bound_rejects_one_extra_layer(self):
        target = self.nested_slash(8)
        assert_rejected(self, target, CODE["ENCODED_ATTACK"], max_length=10000)

    def test_low_decode_bound_rejects_remaining_valid_triplet(self):
        assert_rejected(self, "/%252f", CODE["ENCODED_ATTACK"], max_decode_layers=1)

    def test_decode_bound_two_reaches_structural_attack(self):
        assert_rejected(self, "/%252f", CODE["PROTOCOL_RELATIVE"], max_decode_layers=2)

    def test_decode_bound_is_configurable_upward(self):
        target = self.nested_slash(9)
        result = parse_redirect_location(target, max_length=10000, max_decode_layers=10)
        self.assertEqual(CODE["RELATIVE_PATH"], result.code)

    def test_nested_encoded_scheme_is_rejected_before_use(self):
        assert_rejected(self, "%25256aavascript:alert(1)", CODE["ENCODED_ATTACK"])

    def test_sanitize_never_returns_unsafe_nested_input(self):
        self.assertEqual("/", sanitize_redirect("/%252f%252fevil.example"))

    def test_percent_encoded_emoji_is_valid_utf8_and_preserved(self):
        result = parse_redirect_location("/%f0%9f%98%80")
        self.assertTrue(result.safe)
        self.assertEqual("/%F0%9F%98%80", result.normalized)


if __name__ == "__main__":
    unittest.main()
