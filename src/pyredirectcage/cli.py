"""Command line interface for redirect target inspection."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional, Sequence

from .core import DEFAULT_MAX_DECODE_LAYERS, DEFAULT_MAX_LENGTH, parse_redirect_location
from .errors import RedirectCageError


def _positive_int(text: str) -> int:
    if not text or any(char < "0" or char > "9" for char in text):
        raise argparse.ArgumentTypeError("must be an integer")
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="pyredirectcage",
        description="Inspect a redirect or return URL target without following it.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="pyredirectcage {}".format(__version__),
    )
    subparsers = parser.add_subparsers(dest="command")
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="validate and canonically inspect one redirect target",
    )
    inspect_parser.add_argument("target", help="redirect target to inspect")
    inspect_parser.add_argument(
        "--allow-origin",
        action="append",
        dest="allowed_origins",
        help="allow an exact http or https origin; repeatable",
    )
    inspect_parser.add_argument(
        "--allow-host",
        action="append",
        dest="allowed_hosts",
        help="allow an exact host or host:port; repeatable",
    )
    inspect_parser.add_argument(
        "--allow-subdomains",
        action="store_true",
        help="allow strict dot-boundary subdomains of allowlisted hosts",
    )
    inspect_parser.add_argument(
        "--allow-userinfo",
        action="store_true",
        help="allow userinfo in absolute URLs",
    )
    inspect_parser.add_argument(
        "--allow-ip-literals",
        action="store_true",
        help="allow IP literal redirect hosts",
    )
    inspect_parser.add_argument(
        "--disallow-query",
        action="store_true",
        help="reject targets containing a query string",
    )
    inspect_parser.add_argument(
        "--disallow-hash",
        action="store_true",
        help="reject targets containing a fragment",
    )
    inspect_parser.add_argument(
        "--no-normalize-dot-segments",
        action="store_true",
        help="reject dot segments instead of normalizing them",
    )
    inspect_parser.add_argument(
        "--blocked-path",
        action="append",
        dest="blocked_paths",
        help="block a canonical path and its descendants; repeatable",
    )
    inspect_parser.add_argument(
        "--fallback",
        help="fallback used by sanitizing callers when input is unsafe",
    )
    inspect_parser.add_argument(
        "--max-length",
        type=_positive_int,
        default=DEFAULT_MAX_LENGTH,
        help="maximum input length in Unicode code points (default: %(default)s)",
    )
    inspect_parser.add_argument(
        "--max-decode-layers",
        type=_positive_int,
        default=DEFAULT_MAX_DECODE_LAYERS,
        help="maximum nested percent-decoding layers (default: %(default)s)",
    )
    return parser


def _policy_options(args: argparse.Namespace) -> Dict[str, Any]:
    options: Dict[str, Any] = {
        "allow_subdomains": args.allow_subdomains,
        "allow_userinfo": args.allow_userinfo,
        "allow_ip_literals": args.allow_ip_literals,
        "allow_query": not args.disallow_query,
        "allow_hash": not args.disallow_hash,
        "normalize_dot_segments": not args.no_normalize_dot_segments,
        "max_length": args.max_length,
        "max_decode_layers": args.max_decode_layers,
    }
    if args.allowed_origins is not None:
        options["allowed_origins"] = args.allowed_origins
    if args.allowed_hosts is not None:
        options["allowed_hosts"] = args.allowed_hosts
    if args.blocked_paths is not None:
        options["blocked_paths"] = args.blocked_paths
    if args.fallback is not None:
        options["fallback"] = args.fallback
    return options


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return its process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "inspect":
        parser.print_help(sys.stderr)
        return 2
    try:
        inspection = parse_redirect_location(args.target, **_policy_options(args))
    except RedirectCageError as exc:
        print("pyredirectcage: error: {}".format(exc), file=sys.stderr)
        return 3
    print(json.dumps(inspection.to_dict(), indent=2, sort_keys=True))
    return 0 if inspection.safe else 1


__all__ = ["build_parser", "main"]
