# pyredirectcage

pyredirectcage is a zero-dependency Python library for validating and canonicalizing redirect, return, and next-page URL targets before putting them in a `Location` header. It is a CWE-601 open redirect defense for Python 3.9 through 3.13 and uses only the standard library at runtime.

Relative same-origin paths are allowed by default. Absolute HTTP and HTTPS URLs are rejected unless an exact origin or host allowlist permits them. Unsafe input is replaced with a validated fallback instead of being reflected to the client.

## Security posture

- Protocol-relative and authority-relative values such as `//evil.example` and `///evil.example` are rejected, including forms created by dot-segment normalization.
- Backslashes and mixed slash or backslash forms are rejected, including nested percent-encoded forms.
- Raw and encoded C0 controls, C1 controls, DEL, CR, LF, tab, NUL, Unicode format characters, surrogates, variation selectors, and Unicode whitespace are rejected.
- Percent encoding must be well formed. Percent-decoded bytes must be valid UTF-8. Overlong encodings such as `%c0%af` fail closed.
- Nested decoding is bounded at eight layers by default, with a hard upper bound of sixteen.
- NFKC compatibility changes that create whitespace, controls, structural URL characters, schemes, backslashes, or protocol-relative prefixes are rejected.
- `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:`, extension schemes, and other non-HTTP schemes are never valid redirect targets. Only `http` and `https` can be allowlisted, and absolute URLs require exact `scheme://authority` syntax.
- Userinfo authority spoofing such as `https://trusted.example@evil.example/` is rejected by default.
- IPv4 and IPv6 literal redirect hosts are rejected by default. Legacy IPv4 spellings such as decimal integers, octal forms, hexadecimal forms, and shorthand forms are canonicalized before policy matching.
- Allowlist matching is exact. Optional subdomain matching requires a dot boundary, so `eviltrusted.example` and `trusted.example.evil` do not match `trusted.example`.
- Trailing-dot hostnames are distinct and do not match the corresponding non-trailing-dot allowlist entry.
- `allowed_origins` entries must be pure origins. Hidden paths, queries, fragments, userinfo, and dot-path syntax are rejected at configuration time.
- `blocked_paths` can reject logout, login, or other redirect-loop paths after dot-segment normalization and bounded percent-decoding.
- Fallbacks are validated and canonicalized when the policy is built. An unsafe fallback is a configuration error.
- Input is length capped before decoding. The default cap is 2048 Unicode code points. Validation is bounded scanning and does not use nested regular expressions.
- Successful output is printable ASCII with uppercase percent triplets. Re-running the validator on canonical output is idempotent for covered inputs.
- Every failure is available as a structured code. Exception strings do not echo the attacker-controlled target.

## Non-goals and limitations

pyredirectcage does not fetch URLs, resolve DNS, follow redirect chains, or decide whether a remote host is trustworthy. It is not an SSRF defense. Use a network boundary library for that separate problem.

`blocked_paths` is a URL-path policy, not a framework-specific route matcher. Frameworks that decode or normalize paths in a different order can have additional routing behavior that a static URL library cannot observe.

The host parser is intentionally strict about empty domain labels, malformed numeric forms, IPv6 zone identifiers, port zero, empty userinfo, and non-ASCII dot separators that Python's standard IDNA codec does not accept. Those inputs fail closed even when a particular browser parser has a more permissive compatibility behavior.

The library validates one target string. Applications remain responsible for using the returned canonical value and for not concatenating it with unvalidated data.

## Installation

```bash
python3 -m pip install pyredirectcage
```

For a source checkout:

```bash
python3 -m pip install .
```

## Quick start

```python
from pyredirectcage import sanitize_redirect

def login_next(request):
    return sanitize_redirect(request.GET.get("next", "/"))
```

Use only the returned value:

```python
location = sanitize_redirect(user_supplied_next)
response.status_code = 302
response.headers["Location"] = location
```

The default fallback is `/`. A custom fallback is itself validated and normalized when the policy is created:

```python
fallback = sanitize_redirect(
    "//evil.example",
    fallback="/a/../home",
)
assert fallback == "/home"
```

For an exception-oriented API:

```python
from pyredirectcage import RedirectCageError, assert_safe_redirect

try:
    location = assert_safe_redirect(user_supplied_next)
except RedirectCageError as exc:
    if exc.code == "ERR_REDIRECTCAGE_PROTOCOL_RELATIVE":
        reject_the_login_attempt()
    else:
        reject_the_redirect_target()
```

`sanitize_redirect(..., raise_on_unsafe=True)` has the same failure behavior for unsafe input. Configuration errors always raise because they are programming errors rather than attacker-controlled data.

## Strict predicates and inspection

```python
from pyredirectcage import is_safe_redirect, parse_redirect_location

if is_safe_redirect(target):
    proceed()

inspection = parse_redirect_location(target)
print(inspection.safe)
print(inspection.code)
print(inspection.reason)
print(inspection.normalized)
print(inspection.kind)
print(inspection.origin)
print(inspection.path)
```

`parse_redirect_location` does not follow the redirect and does not perform I/O. It returns a frozen `RedirectInspection` dataclass. `normalized` is the only value that should be emitted when `safe` is true. `value` is provided as an alias for users of the JavaScript companion API.

## Absolute URL allowlists

Absolute URLs are denied without an explicit allowlist:

```python
from pyredirectcage import sanitize_redirect

location = sanitize_redirect(
    target,
    allowed_origins=["https://trusted.example"],
)
```

An origin entry is scheme, host, and optional port only. These are invalid configuration entries:

```text
https://trusted.example/path
https://trusted.example/.
https://trusted.example?next=/x
https://user@trusted.example
```

Host entries can be used when either enabled HTTP scheme is acceptable on its default port:

```python
location = sanitize_redirect(
    target,
    allowed_hosts=["trusted.example", "static.example:8443"],
)
```

Subdomains are off by default. Enable them only when every subdomain is trusted:

```python
location = sanitize_redirect(
    target,
    allowed_hosts=["trusted.example"],
    allow_subdomains=True,
)
```

The match is a strict dot-boundary match. `app.trusted.example` can match, while `eviltrusted.example` cannot.

## Redirect-loop path blocking

```python
location = sanitize_redirect(
    target,
    blocked_paths=["/logout", "/login"],
)
```

A blocked entry matches the exact path and descendants. `/admin` matches `/admin` and `/admin/panel`, not `/administrator`. A trailing slash is significant. Matching is case sensitive after canonical percent-triplet casing and bounded decoding. Dot segments are normalized before comparison.

A fallback inside a blocked path is rejected at configuration time. Choose a fallback outside the blocked subtree.

## Reusable policies and guards

```python
from pyredirectcage import RedirectGuard, RedirectPolicy

policy = RedirectPolicy(
    allowed_hosts=["trusted.example"],
    fallback="/home",
    blocked_paths=["/logout"],
)
guard = RedirectGuard(policy)

location = guard.sanitize(target)
inspection = guard.parse_location(target)
```

Policies and guards are immutable. `derive` or per-call overrides return a new policy rather than mutating the existing one:

```python
strict = guard.policy.derive(allow_query=False)
```

## WSGI and ASGI header helper

```python
from pyredirectcage import safe_location_header

wsgi_header = safe_location_header(target)
# ("Location", "/safe-or-fallback")

asgi_header = safe_location_header(target, as_bytes=True)
# (b"location", b"/safe-or-fallback")
```

The helper does not choose a redirect status. Applications normally use 302, 303, 307, or 308 according to their semantics.

## Command line inspection

```bash
python3 -m pyredirectcage inspect '/safe/path'
python3 -m pyredirectcage inspect 'https://trusted.example/x' --allow-host trusted.example
```

The command prints one JSON object. It exits with 0 when the target is safe, 1 when it is unsafe, 2 for command line misuse, and 3 for invalid policy configuration. After installation, the same command is available as `pyredirectcage inspect`.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `allowed_origins` | empty | Exact `http` or `https` origins allowed for absolute targets |
| `allowed_hosts` | empty | Exact hosts or host-port pairs allowed for absolute targets |
| `allow_subdomains` | `False` | Permit strict dot-boundary subdomains of allowlisted hosts |
| `allow_protocols` | `("http", "https")` | Enabled absolute redirect schemes |
| `allow_userinfo` | `False` | Permit userinfo in an absolute URL authority |
| `allow_ip_literals` | `False` | Permit IPv4 and IPv6 literal redirect hosts |
| `allow_query` | `True` | Permit query strings, including encoded forms |
| `allow_hash` | `True` | Permit fragments, including encoded forms |
| `normalize_dot_segments` | `True` | Canonicalize dot segments instead of rejecting them |
| `blocked_paths` | empty | Paths and descendants rejected as redirect-loop risks |
| `fallback` | `/` | Canonical safe value used when sanitizing unsafe input |
| `max_length` | `2048` | Maximum input length in Unicode code points |
| `max_decode_layers` | `8` | Nested percent-decoding bound, maximum 16 |
| `raise_on_unsafe` | `False` | Make `sanitize_redirect` raise instead of returning fallback |

## Error handling

Every unsafe target has a stable machine-readable code beginning with `ERR_REDIRECTCAGE_`. Branch on `exc.code` or `inspection.code`, not on human-readable text. The complete tuple is exported as `ERROR_CODES`, and the name-to-value mapping is exported as `CODE`.

## Test evidence and development

The offline unittest suite currently contains 504 real deterministic tests. They cover OWASP CWE-601 vectors, parser canonicalization, invalid UTF-8 and overlong encodings, nested percent encoding, Unicode normalization, host and port edge cases, IPv4 and IPv6 literals, strict allowlist boundaries, redirect-loop paths, policy validation, WSGI and ASGI helpers, CLI behavior, typing exports, and repository hygiene. All 504 tests passed in the local verification run for this commit.

Run the suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The project has no runtime dependencies and no third-party test dependencies.
