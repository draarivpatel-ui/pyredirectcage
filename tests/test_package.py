"""Package metadata, public API, typing, workflow, and repository hygiene tests."""

import ast
import inspect
import json
import re
import subprocess
import unittest
from pathlib import Path

import pyredirectcage
from pyredirectcage import ERROR_CODES, sanitize_redirect

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def project_files():
    skipped = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv"}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        yield path


class PackageMetadataTests(unittest.TestCase):
    def test_runtime_dependencies_are_empty(self):
        self.assertIn("dependencies = []", read("pyproject.toml"))

    def test_python_floor_is_39(self):
        self.assertIn('requires-python = ">=3.9"', read("pyproject.toml"))

    def test_project_name_is_pyredirectcage(self):
        self.assertIn('name = "pyredirectcage"', read("pyproject.toml"))

    def test_project_urls_point_to_public_repository(self):
        text = read("pyproject.toml")
        self.assertIn('Homepage = "https://github.com/draarivpatel-ui/pyredirectcage"', text)
        self.assertIn('Repository = "https://github.com/draarivpatel-ui/pyredirectcage"', text)
        self.assertIn('Issues = "https://github.com/draarivpatel-ui/pyredirectcage/issues"', text)

    def test_version_matches_package(self):
        self.assertIn('version = "1.0.0"', read("pyproject.toml"))
        self.assertEqual("1.0.0", pyredirectcage.__version__)

    def test_py_typed_is_present(self):
        self.assertTrue((ROOT / "src" / "pyredirectcage" / "py.typed").is_file())

    def test_src_layout_is_used(self):
        self.assertIn('package-dir = { "" = "src" }', read("pyproject.toml"))
        self.assertTrue((ROOT / "src" / "pyredirectcage" / "__init__.py").is_file())

    def test_console_script_is_declared(self):
        self.assertIn('pyredirectcage = "pyredirectcage.cli:main"', read("pyproject.toml"))

    def test_package_data_includes_py_typed(self):
        self.assertIn('pyredirectcage = ["py.typed"]', read("pyproject.toml"))


class WorkflowTests(unittest.TestCase):
    def test_ci_uses_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/ci.yml"))

    def test_ci_matrix_covers_python_39_to_313(self):
        text = read(".github/workflows/ci.yml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)

    def test_ci_runs_unittest_suite(self):
        self.assertIn("PYTHONPATH=src python3 -m unittest discover -s tests", read(".github/workflows/ci.yml"))

    def test_publish_uses_oidc_trusted_publishing_permission(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("id-token: write", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)

    def test_publish_workflow_targets_pypi_environment(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("name: pypi", text)
        self.assertIn("url: https://pypi.org/p/pyredirectcage", text)

    def test_workflows_have_read_only_contents_permission_by_default(self):
        for relative in (".github/workflows/ci.yml", ".github/workflows/publish.yml"):
            self.assertIn("contents: read", read(relative))


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist(self):
        for relative in (
            "README.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "docs/good-first-issues.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_good_first_issues_has_ten_items(self):
        count = len(re.findall(r"^\d+\. \*\*", read("docs/good-first-issues.md"), re.MULTILINE))
        self.assertEqual(10, count)

    def test_readme_documents_honest_limitations(self):
        text = read("README.md")
        self.assertIn("not an SSRF defense", text)
        self.assertIn("not a framework-specific route matcher", text)
        self.assertIn("Applications remain responsible", text)

    def test_readme_documents_canonical_output_contract(self):
        self.assertIn("returned canonical value", read("README.md"))

    def test_readme_has_no_placeholder_test_count(self):
        self.assertNotIn("TEST_COUNT", read("README.md"))

    def test_readme_count_matches_discovered_suite(self):
        match = re.search(r"contains (\d+) real deterministic tests", read("README.md"))
        self.assertIsNotNone(match)
        documented = int(match.group(1))
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        self.assertEqual(documented, suite.countTestCases())

    def test_security_policy_has_private_reporting_path(self):
        self.assertIn("private security advisory", read("SECURITY.md"))

    def test_security_policy_documents_out_of_scope_ssrf(self):
        self.assertIn("SSRF", read("SECURITY.md"))

    def test_contributing_documents_zero_dependency_rule(self):
        self.assertIn("zero runtime dependencies", read("CONTRIBUTING.md"))

    def test_license_is_mit(self):
        self.assertIn("MIT License", read("LICENSE"))


class PublicApiTests(unittest.TestCase):
    def test_required_public_names_exist(self):
        for name in (
            "CODE",
            "ERROR_CODES",
            "RedirectCageError",
            "RedirectGuard",
            "RedirectInspection",
            "RedirectPolicy",
            "assert_safe_redirect",
            "is_safe_redirect",
            "parse_redirect_location",
            "safe_location_header",
            "sanitize_redirect",
        ):
            self.assertTrue(hasattr(pyredirectcage, name), name)

    def test_all_exports_exist(self):
        for name in pyredirectcage.__all__:
            self.assertTrue(hasattr(pyredirectcage, name), name)

    def test_error_codes_are_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_codes_are_machine_readable(self):
        for code in ERROR_CODES:
            self.assertRegex(code, r"^ERR_REDIRECTCAGE_[A-Z0-9_]+$")

    def test_sanitize_signature_exposes_keyword_only_fallback(self):
        signature = inspect.signature(sanitize_redirect)
        parameter = signature.parameters["fallback"]
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, parameter.kind)
        self.assertEqual("/", parameter.default)

    def test_sanitize_signature_exposes_raise_on_unsafe(self):
        signature = inspect.signature(sanitize_redirect)
        self.assertIn("raise_on_unsafe", signature.parameters)

    def test_inspection_dataclass_is_frozen(self):
        result = pyredirectcage.parse_redirect_location("/x")
        with self.assertRaises(Exception):
            result.safe = False

    def test_public_module_does_not_export_eval_or_exec_helpers(self):
        self.assertFalse(hasattr(pyredirectcage, "eval"))
        self.assertFalse(hasattr(pyredirectcage, "exec"))


class SourceHygieneTests(unittest.TestCase):
    def test_source_has_no_third_party_imports(self):
        allowed = {
            "__future__",
            "argparse",
            "collections",
            "dataclasses",
            "ipaddress",
            "json",
            "re",
            "sys",
            "types",
            "typing",
            "unicodedata",
            "pyredirectcage",
        }
        for path in (ROOT / "src" / "pyredirectcage").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    self.assertIn(name, allowed, "{} imports {}".format(path.name, name))

    def test_source_has_no_network_or_process_modules(self):
        forbidden = ("socket", "urllib", "requests", "subprocess", "ctypes", "ssl")
        for path in (ROOT / "src" / "pyredirectcage").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [(node.module or "").split(".")[0]] if not node.level else []
                else:
                    continue
                for name in names:
                    self.assertNotIn(name, forbidden, "{} imports {}".format(path.name, name))

    def test_tracked_text_has_no_em_or_en_dashes(self):
        forbidden = (chr(0x2013), chr(0x2014))
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for char in forbidden:
                self.assertNotIn(char, text, "{} contains a Unicode dash".format(path))

    def test_tracked_text_has_no_local_private_markers(self):
        markers = (
            "/" + "Users/",
            "someone@" + "gmail.com",
            "handle-redacted286@" + "gmail.com",
            "Exampleton" + " Manor",
        )
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                self.assertNotIn(marker, text, "{} contains a private marker".format(path))

    def test_gitignore_excludes_python_cache_files(self):
        text = read(".gitignore")
        self.assertIn("__pycache__/", text)
        self.assertIn("*.py[cod]", text)

    def test_no_python_cache_is_tracked_when_git_metadata_exists(self):
        if not (ROOT / ".git").is_dir():
            self.skipTest("git metadata is not present in this checkout")
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        tracked = completed.stdout.splitlines()
        offenders = [
            name
            for name in tracked
            if "__pycache__" in name or name.endswith((".pyc", ".pyo"))
        ]
        self.assertEqual([], offenders)

    def test_source_does_not_call_network_or_process_execution_primitives(self):
        forbidden = ("socket.", "urllib.request", "subprocess.", "os.system", "requests.")
        for path in (ROOT / "src" / "pyredirectcage").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, "{} contains {}".format(path.name, marker))

    def test_distribution_metadata_contains_no_optional_runtime_dependency(self):
        text = read("pyproject.toml")
        self.assertIn("[project.optional-dependencies]", text)
        self.assertIn("dev = []", text)


if __name__ == "__main__":
    unittest.main()
