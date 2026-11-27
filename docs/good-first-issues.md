# Good first issues

Ten modular starter tasks for new contributors. Each is scoped to one file or one focused behavior. Every task must preserve the zero runtime dependency rule and Python 3.9 compatibility.

1. **Add host-parser boundary vectors** in `tests/test_absolute_policy.py` for additional numeric IPv4 spellings, including one valid form and one invalid form for each base.
2. **Add a Unicode normalization matrix** in `tests/test_attack_vectors.py` covering compatibility characters that must be rejected and inert non-ASCII path text that must be percent-encoded.
3. **Add blocked-path documentation examples** in `README.md` showing exact, descendant, trailing-slash, case-sensitive, and percent-decoded behavior without changing code.
4. **Add CLI regression tests** in `tests/test_cli.py` for repeated allowlist flags, blocked paths, and invalid numeric options.
5. **Write `docs/threat-model.md`** describing attacker capabilities, canonical-output requirements, framework responsibilities, and the boundary with SSRF defenses.
6. **Add a performance smoke script** under `scripts/` using only stdlib `timeit`, with clear documentation that it is not a security proof.
7. **Add package metadata tests** in `tests/test_package.py` for classifiers, scripts, package data, and the zero-dependency contract.
8. **Add userinfo canonicalization tests** in `tests/test_absolute_policy.py` for explicit opt-in behavior, empty passwords, additional at signs, and percent-triplet casing.
9. **Improve error documentation** in `README.md` with a table grouping every error code by input, encoding, scheme, host, policy, and configuration failure.
10. **Expand `SECURITY.md`** with a coordinated disclosure timeline, safe report template, and examples of sanitized reproductions.

Before starting one, open an issue or comment on the existing issue so work is not duplicated. Add tests with every code change.
