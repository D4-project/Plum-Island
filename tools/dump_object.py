#!/bin/env python
"""
Dump distinct indexed Kvrocks values as raw CSV on stdout.
"""

import argparse
from pathlib import Path
import re
import sys

import yaml

BASE_DIR = Path(__file__).resolve().parent
UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(UTILS_DIR))

HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")

DUMPABLE_FIELDS = [
    "banner",
    "domain",
    "domain_requested",
    "fqdn",
    "fqdn_requested",
    "host",
    "http_cookiename",
    "http_etag",
    "http_favicon_md5",
    "http_favicon_mmhash",
    "http_favicon_path",
    "http_favicon_sha256",
    "http_header",
    "http_headval",
    "http_server",
    "http_title",
    "ip",
    "net",
    "port",
    "tag",
    "tld",
    "x509_issuer",
    "x509_md5",
    "x509_san",
    "x509_sha1",
    "x509_sha256",
    "x509_subject",
]


def load_config():
    """
    Load tool config without requiring the caller's working directory.
    """
    with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def is_valid_http_header_name(value):
    """
    Validate a canonical lowercase HTTP header field name.
    """
    header_name = str(value or "").strip()
    return (
        bool(header_name)
        and len(header_name) <= 128
        and bool(HTTP_HEADER_NAME_RE.fullmatch(header_name))
    )


def escape_redis_glob(value):
    """
    Escape Redis glob metacharacters used by SCAN MATCH.
    """
    return "".join(f"\\{char}" if char in "\\*?[]" else char for char in str(value))


def normalize_field(raw_field):
    """
    Validate a Kvrocks index prefix.
    """
    field = str(raw_field or "").strip().lower()
    if field not in DUMPABLE_FIELDS:
        raise ValueError(
            f"Unknown dumpable field: {raw_field}. "
            "Run with --list-dumpable to see supported fields. "
            "Use http_headval:<header_name> to dump values for one collected header."
        )
    return field


def normalize_dump_target(raw_field):
    """
    Validate a dump target, including header-scoped http_headval:<header>.
    """
    field = str(raw_field or "").strip().lower()
    prefix = "http_headval:"
    if field.startswith(prefix):
        header_name = field[len(prefix) :].strip()
        if not is_valid_http_header_name(header_name):
            raise ValueError("http_headval dump expects a valid HTTP header name")
        return {
            "field": "http_headval",
            "match_prefix": f"http_headval:{header_name}:",
            "display_prefix": f"http_headval:{header_name}:",
        }

    field = normalize_field(field)
    return {
        "field": field,
        "match_prefix": f"{field}:",
        "display_prefix": f"{field}:",
    }


def parse_args(argv=None):
    """
    Parse CLI options.
    """
    parser = argparse.ArgumentParser(
        description="Dump distinct indexed Kvrocks values as count,value CSV."
    )
    parser.add_argument(
        "field",
        nargs="?",
        help=(
            "Indexed search criterion to dump, for example banner, http_title, "
            "http_header, or http_headval:x-powered-by."
        ),
    )
    parser.add_argument(
        "--list-dumpable",
        action="store_true",
        help="List dumpable indexed criteria and exit.",
    )
    return parser.parse_args(argv)


def list_dumpable():
    """
    Print supported fields.
    """
    for field in DUMPABLE_FIELDS:
        print(field)
    print("http_headval:<header_name>")


def dump_target(target):
    """
    Print `count,value` lines to stdout for one indexed target.
    """
    from kvrocks import KVrocksIndexer  # pylint: disable=import-outside-toplevel

    config = load_config()
    kvrocks_host = config.get("IN_KVROCKS_HOST", "localhost")
    kvrocks_port = config.get("IN_KVROCKS_PORT", 6666)
    indexer = KVrocksIndexer(kvrocks_host, kvrocks_port)

    results = []
    match_prefix = target["match_prefix"]
    display_prefix = target["display_prefix"]
    scan_match = f"{escape_redis_glob(match_prefix)}*"
    for key in indexer.r.scan_iter(match=scan_match, count=1000):
        if not key.startswith(match_prefix):
            continue
        value = key[len(display_prefix) :]
        if not value:
            continue
        count = indexer.r.scard(key)
        results.append((count, value))

    for count, value in sorted(results, key=lambda item: (-item[0], item[1])):
        print(f"{count},{value}")


def main(argv=None):
    """
    CLI entrypoint.
    """
    args = parse_args(argv)
    if args.list_dumpable:
        list_dumpable()
        return
    if not args.field:
        raise SystemExit("Missing dump field. Run with --list-dumpable.")

    dump_target(normalize_dump_target(args.field))


if __name__ == "__main__":
    main()
