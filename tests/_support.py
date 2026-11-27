"""Shared deterministic assertions for the pyredirectcage suite."""

from __future__ import annotations

import unittest

from pyredirectcage import parse_redirect_location, sanitize_redirect


def assert_rejected(case: unittest.TestCase, target, code: str, **options) -> None:
    result = parse_redirect_location(target, **options)
    case.assertFalse(result.safe, "expected rejection for {!r}".format(target))
    case.assertEqual(code, result.code, "wrong code for {!r}".format(target))
    case.assertIsNone(result.normalized)
    case.assertIsInstance(result.reason, str)
    case.assertTrue(result.reason)


def assert_accepted(case: unittest.TestCase, target, normalized: str, **options):
    result = parse_redirect_location(target, **options)
    case.assertTrue(result.safe, "expected acceptance for {!r}, got {}".format(target, result.code))
    case.assertIsNone(result.code)
    case.assertIsNone(result.reason)
    case.assertEqual(normalized, result.normalized)
    case.assertEqual(normalized, result.value)
    return result


def assert_sanitized(case: unittest.TestCase, target, expected: str, **options) -> None:
    case.assertEqual(expected, sanitize_redirect(target, **options))


def add_matrix_tests(cls, prefix, rows, checker) -> None:
    for index, row in enumerate(rows):
        name = "test_{}_{:03d}".format(prefix, index)

        def test(self, row=row):
            checker(self, row)

        test.__name__ = name
        test.__qualname__ = cls.__name__ + "." + name
        setattr(cls, name, test)
