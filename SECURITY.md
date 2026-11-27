# Security Policy

## Supported versions

Version 1.x receives security fixes.

## Reporting a vulnerability

Please use GitHub's private security advisory form on the repository. Do not open a public issue for an undisclosed vulnerability.

Include the affected version, a minimal redirect target or code reproduction, the expected behavior, and the observed behavior. Do not include real session tokens, production redirect URLs containing credentials, secrets, or personal data. Reports are acknowledged within seven days. Fixes are released as patch versions with a changelog entry.

## In scope

- Open redirect bypasses that cause an unsafe absolute or protocol-relative target to be emitted
- Protocol-relative, backslash, mixed-slash, dot-segment, or percent-encoding parser differentials
- Invalid UTF-8 or overlong-encoding acceptance that changes downstream interpretation
- CRLF, control-character, invisible Unicode, or header-splitting acceptance
- Dangerous-scheme acceptance or encoded-scheme bypasses
- Userinfo, host, port, trailing-dot, IDN, IPv4, or IPv6 allowlist bypasses
- Subdomain boundary bypasses such as `eviltrusted.example`
- Hidden path, query, fragment, or userinfo syntax accepted in `allowed_origins`
- Fallback validation or canonicalization bypasses
- `blocked_paths` decoding or normalization bypasses within documented semantics
- Validation behavior that causes practical denial of service within documented length and decoding limits
- Canonical output that is not printable ASCII or is not idempotently safe

## Out of scope

- Vulnerabilities in applications using this library
- Deciding which remote origins an application should trust
- SSRF, DNS resolution, DNS rebinding, or network-fetching behavior
- Framework-specific route matching outside documented `blocked_paths` semantics
- Denial of service from inputs above the configured length limit
- Behavior enabled by explicit dangerous compatibility options such as `allow_userinfo=True` or `allow_ip_literals=True`
- Social engineering or physical access

## Design notes

pyredirectcage is defensive only. It performs no network access, filesystem access, subprocess execution, browser interaction, or DNS resolution. It validates one string and returns canonical output. Callers must emit only the returned canonical value.

Exception strings intentionally omit the attacker-controlled target because redirect URLs often contain query tokens. Structured inspection APIs can report the input when an application explicitly asks for diagnostics.
