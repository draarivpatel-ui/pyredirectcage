# Contributing

Thanks for helping improve pyredirectcage. The project has zero runtime dependencies and targets Python 3.9 through 3.13.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Every change must keep the suite green using Python 3.9 syntax. No third-party test packages are required.

## Security invariants

- Keep `dependencies = []` in `pyproject.toml`.
- Same-origin relative paths are the only allowed targets by default.
- Never emit the original target when validation fails.
- Never emit attacker-controlled text in exception strings.
- Keep output printable ASCII with canonical uppercase percent triplets.
- Reject malformed percent encoding and invalid UTF-8 fail-closed.
- Keep nested percent-decoding bounded.
- Reject hidden path, query, fragment, and userinfo syntax in `allowed_origins`.
- Treat trailing-dot hostnames as distinct for allowlist matching.
- Keep host and numeric canonicalization deterministic across supported Python versions.
- Keep allowlist subdomain matching behind a strict dot boundary.
- Add regression tests for every validation rule or bug fix.
- Prefer explicit opt-in for unsafe compatibility behavior.
- Do not add em dashes or en dashes to source, docs, tests, or workflow files.

## Code guidelines

- Use only the Python standard library at runtime.
- Use type annotations on public functions.
- Preserve Python 3.9 compatibility.
- Raise `RedirectCageError` with a stable machine-readable code for every expected failure.
- Keep validation deterministic, bounded, and free of nested regular-expression backtracking.
- Do not perform network, filesystem, browser, or DNS operations in the library.

## Pull requests

1. Fork the repository and create a focused branch.
2. Describe the security impact of the change.
3. Add or update regression tests.
4. Run the full suite and paste the result.
5. Keep commits small and self-contained.

## Good first issues

See [docs/good-first-issues.md](docs/good-first-issues.md) for ten modular starter tasks.
