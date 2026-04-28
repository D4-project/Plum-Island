#!/bin/env python
"""
Dump distinct indexed Kvrocks values as raw CSV on stdout.
"""

import argparse
from pathlib import Path
import sys

import yaml

BASE_DIR = Path(__file__).resolve().parent
UTILS_DIR = BASE_DIR.parent / "webapp" / "app" / "utils"
sys.path.append(str(UTILS_DIR))


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


def normalize_field(raw_field):
    """
    Validate a Kvrocks index prefix.
    """
    field = str(raw_field or "").strip()
    if field not in DUMPABLE_FIELDS:
        raise ValueError(
            f"Unknown dumpable field: {raw_field}. "
            "Run with --list-dumpable to see supported fields."
        )
    return field


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
        help="Indexed search criterion to dump, for example banner or http_title.",
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


def dump_field(field):
    """
    Print `count,value` lines to stdout for one indexed field.
    """
    from kvrocks import KVrocksIndexer  # pylint: disable=import-outside-toplevel

    config = load_config()
    kvrocks_host = config.get("IN_KVROCKS_HOST", "localhost")
    kvrocks_port = config.get("IN_KVROCKS_PORT", 6666)
    indexer = KVrocksIndexer(kvrocks_host, kvrocks_port)

    results = []
    for key in indexer.r.scan_iter(match=f"{field}:*", count=1000):
        value = key.split(":", 1)[1]
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

    dump_field(normalize_field(args.field))


if __name__ == "__main__":
    main()
