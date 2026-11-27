"""Command line and module-entry integration tests."""

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from pyredirectcage.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


def run_module(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "pyredirectcage"] + list(args),
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=10,
    )


class ModuleCliTests(unittest.TestCase):
    def test_no_command_prints_help_and_exits_two(self):
        completed = run_module()
        self.assertEqual(2, completed.returncode)
        self.assertIn("usage:", completed.stderr)

    def test_version_exits_zero(self):
        completed = run_module("--version")
        self.assertEqual(0, completed.returncode)
        self.assertIn("pyredirectcage 1.0.0", completed.stdout)

    def test_safe_relative_target_exits_zero(self):
        completed = run_module("inspect", "/safe")
        self.assertEqual(0, completed.returncode, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertIs(True, report["safe"])
        self.assertEqual("/safe", report["normalized"])

    def test_protocol_relative_target_exits_one(self):
        completed = run_module("inspect", "//evil.example")
        self.assertEqual(1, completed.returncode)
        report = json.loads(completed.stdout)
        self.assertIs(False, report["safe"])
        self.assertEqual("ERR_REDIRECTCAGE_PROTOCOL_RELATIVE", report["code"])

    def test_absolute_target_is_denied_without_allowlist(self):
        completed = run_module("inspect", "https://trusted.example/x")
        self.assertEqual(1, completed.returncode)
        report = json.loads(completed.stdout)
        self.assertEqual("ERR_REDIRECTCAGE_ABSOLUTE_URL", report["code"])

    def test_allow_host_permits_absolute_target(self):
        completed = run_module(
            "inspect",
            "https://trusted.example/x",
            "--allow-host",
            "trusted.example",
        )
        self.assertEqual(0, completed.returncode)
        report = json.loads(completed.stdout)
        self.assertEqual("https://trusted.example/x", report["normalized"])

    def test_allow_origin_permits_exact_origin(self):
        completed = run_module(
            "inspect",
            "https://trusted.example/x",
            "--allow-origin",
            "https://trusted.example",
        )
        self.assertEqual(0, completed.returncode)

    def test_allow_subdomains_flag(self):
        completed = run_module(
            "inspect",
            "https://app.trusted.example/x",
            "--allow-host",
            "trusted.example",
            "--allow-subdomains",
        )
        self.assertEqual(0, completed.returncode)

    def test_blocked_path_flag(self):
        completed = run_module("inspect", "/admin/panel", "--blocked-path", "/admin")
        self.assertEqual(1, completed.returncode)
        report = json.loads(completed.stdout)
        self.assertEqual("ERR_REDIRECTCAGE_BLOCKED_PATH", report["code"])

    def test_hidden_origin_path_is_config_error(self):
        completed = run_module(
            "inspect",
            "https://trusted.example/x",
            "--allow-origin",
            "https://trusted.example/./",
        )
        self.assertEqual(3, completed.returncode)
        self.assertIn("ERR_REDIRECTCAGE_INVALID_OPTIONS", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_disallow_query_flag(self):
        completed = run_module("inspect", "/x?a=1", "--disallow-query")
        self.assertEqual(1, completed.returncode)
        self.assertEqual("ERR_REDIRECTCAGE_QUERY_NOT_ALLOWED", json.loads(completed.stdout)["code"])

    def test_disallow_hash_flag(self):
        completed = run_module("inspect", "/x#f", "--disallow-hash")
        self.assertEqual(1, completed.returncode)
        self.assertEqual("ERR_REDIRECTCAGE_HASH_NOT_ALLOWED", json.loads(completed.stdout)["code"])

    def test_no_normalize_dot_segments_flag(self):
        completed = run_module("inspect", "/a/./b", "--no-normalize-dot-segments")
        self.assertEqual(1, completed.returncode)
        self.assertEqual("ERR_REDIRECTCAGE_DOT_SEGMENT", json.loads(completed.stdout)["code"])

    def test_malformed_ipv6_is_json_error_not_traceback(self):
        completed = run_module(
            "inspect",
            "https://[::1/x",
            "--allow-host",
            "trusted.example",
            "--allow-ip-literals",
        )
        self.assertEqual(1, completed.returncode)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertEqual("ERR_REDIRECTCAGE_INVALID_URL", json.loads(completed.stdout)["code"])

    def test_max_length_flag(self):
        completed = run_module("inspect", "/abcdef", "--max-length", "4")
        self.assertEqual(1, completed.returncode)
        self.assertEqual("ERR_REDIRECTCAGE_LIMIT_EXCEEDED", json.loads(completed.stdout)["code"])

    def test_max_decode_layers_above_bound_is_config_error(self):
        completed = run_module("inspect", "/x", "--max-decode-layers", "17")
        self.assertEqual(3, completed.returncode)
        self.assertIn("ERR_REDIRECTCAGE_INVALID_OPTIONS", completed.stderr)

    def test_invalid_numeric_option_is_argparse_error(self):
        completed = run_module("inspect", "/x", "--max-length", "abc")
        self.assertEqual(2, completed.returncode)

    def test_unknown_cli_option_is_argparse_error(self):
        completed = run_module("inspect", "/x", "--unknown")
        self.assertEqual(2, completed.returncode)

    def test_empty_query_metadata_is_preserved(self):
        completed = run_module("inspect", "/x?")
        self.assertEqual(0, completed.returncode)
        report = json.loads(completed.stdout)
        self.assertEqual("", report["query"])
        self.assertEqual("/x?", report["normalized"])

    def test_userinfo_requires_explicit_flag(self):
        base = [
            "inspect",
            "https://user@trusted.example/x",
            "--allow-host",
            "trusted.example",
        ]
        denied = run_module(*base)
        self.assertEqual(1, denied.returncode)
        allowed = run_module(*(base + ["--allow-userinfo"]))
        self.assertEqual(0, allowed.returncode)

    def test_ip_literal_requires_explicit_flag(self):
        base = [
            "inspect",
            "https://127.0.0.1/x",
            "--allow-host",
            "127.0.0.1",
        ]
        invalid_config = run_module(*base)
        self.assertEqual(3, invalid_config.returncode)
        allowed = run_module(*(base + ["--allow-ip-literals"]))
        self.assertEqual(0, allowed.returncode)

    def test_control_encoded_input_is_not_a_traceback(self):
        completed = run_module("inspect", "/x%0dy")
        self.assertEqual(1, completed.returncode)
        self.assertNotIn("Traceback", completed.stderr)


class DirectCliTests(unittest.TestCase):
    def call_main(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_build_parser_prog_name(self):
        parser = build_parser()
        self.assertEqual("pyredirectcage", parser.prog)

    def test_main_without_command_returns_two(self):
        status, _stdout, _stderr = self.call_main([])
        self.assertEqual(2, status)

    def test_main_safe_returns_zero(self):
        status, stdout, _stderr = self.call_main(["inspect", "/safe"])
        self.assertEqual(0, status)
        self.assertIs(True, json.loads(stdout)["safe"])

    def test_main_unsafe_returns_one(self):
        status, stdout, _stderr = self.call_main(["inspect", "//evil.example"])
        self.assertEqual(1, status)
        self.assertIs(False, json.loads(stdout)["safe"])

    def test_main_config_error_returns_three(self):
        status, _stdout, stderr = self.call_main(
            [
                "inspect",
                "/x",
                "--fallback",
                "//evil.example",
            ]
        )
        self.assertEqual(3, status)
        self.assertIn("ERR_REDIRECTCAGE_INVALID_OPTIONS", stderr)


if __name__ == "__main__":
    unittest.main()
